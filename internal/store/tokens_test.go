package store

import (
	"encoding/base32"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zkryakgul/keyshelf/internal/totp"
)

func TestTokenScopes(t *testing.T) {
	tok := Token{Kind: KindAgent, Scopes: []Scope{
		{Folder: "work/acme", Perms: []string{PermList, PermRead}},
		{Folder: "home", Perms: []string{PermWrite}},
	}}
	cases := []struct {
		perm, folder string
		want         bool
	}{
		{PermRead, "work/acme", true},
		{PermRead, "work/acme/staging", true},
		{PermRead, "work/acmex", false}, // prefix must stop at a separator
		{PermRead, "work", false},
		{PermRead, "", false},
		{PermWrite, "work/acme", false},
		{PermWrite, "home/router", true},
		{PermRead, "home", false},
	}
	for _, c := range cases {
		if got := tok.Allows(c.perm, c.folder); got != c.want {
			t.Errorf("Allows(%s, %q) = %v", c.perm, c.folder, got)
		}
	}
	if !(Token{Kind: KindOwner}).Allows(PermWrite, "anything") {
		t.Error("owner must be allowed everything")
	}
	all := Token{Kind: KindAgent, Scopes: []Scope{{Folder: "", Perms: []string{PermList}}}}
	if !all.Allows(PermList, "a/b") || all.Allows(PermRead, "a/b") {
		t.Error("root scope")
	}
}

func TestTokenLifecycle(t *testing.T) {
	s := unsealedStore(t)
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }

	secret, tok, err := s.CreateAgentToken("claude", []Scope{{Folder: "work", Perms: []string{PermRead}}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, "ks_") || len(secret) < 40 {
		t.Fatalf("token format")
	}
	var stored int
	s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE instr(CAST(hash AS TEXT), ?) > 0 OR instr(scopes, ?) > 0`, secret, secret).Scan(&stored)
	if stored != 0 {
		t.Fatal("token secret stored in clear")
	}
	if _, _, err := s.CreateAgentToken("claude", []Scope{{Folder: "x", Perms: []string{PermRead}}}, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	got, err := s.Authenticate(secret)
	if err != nil || got.ID != tok.ID || got.Actor() != "token:claude" || got.LastUsedAt == nil {
		t.Fatalf("authenticate: %+v %v", got, err)
	}
	for _, bad := range []string{"", "ks_", "ks_wrong", secret + "x", strings.TrimPrefix(secret, "ks_")} {
		if _, err := s.Authenticate(bad); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%q accepted", bad)
		}
	}

	now = now.Add(2 * time.Hour)
	if _, err := s.Authenticate(secret); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired token accepted")
	}

	secret2, tok2, err := s.CreateAgentToken("script", []Scope{{Folder: "", Perms: []string{PermList}}}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeToken(tok2.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(secret2); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked token accepted")
	}
	if err := s.RevokeToken(tok2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("double revoke")
	}

	for _, bad := range [][]Scope{nil, {{Folder: "a", Perms: nil}}, {{Folder: "a", Perms: []string{"admin"}}}, {{Folder: "../x", Perms: []string{PermRead}}}} {
		if _, _, err := s.CreateAgentToken("bad", bad, 0); !errors.Is(err, ErrInvalidName) {
			t.Errorf("scopes %v accepted: %v", bad, err)
		}
	}

	sess, st, err := s.CreateOwnerSession(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Authenticate(sess); err != nil || !got.IsOwner() || got.ID != st.ID {
		t.Fatalf("owner session: %v", err)
	}
	list, _ := s.ListAgentTokens()
	if len(list) != 1 || list[0].Name != "claude" {
		t.Fatalf("list tokens: %+v", list)
	}
}

func TestAuditChain(t *testing.T) {
	s := unsealedStore(t)
	for _, e := range []Event{
		{Actor: "owner", Action: "entry.put", Target: "a/b"},
		{Actor: "token:claude", Action: "value.read", Target: "a/b#password", Source: "127.0.0.1"},
		{Actor: "token:claude", Action: "value.read", Target: "a/bc#password"},
	} {
		if err := s.Audit(e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.VerifyAudit(); err != nil {
		t.Fatal(err)
	}
	ev, _ := s.ListAudit(AuditFilter{Target: "a/b"})
	if len(ev) != 2 || ev[0].Action != "value.read" {
		t.Fatalf("filter: %+v", ev)
	}
	if _, err := s.db.Exec(`UPDATE audit SET actor = 'someone' WHERE id = 2`); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAudit(); !errors.Is(err, ErrAuditTampered) {
		t.Fatalf("edit not detected: %v", err)
	}
	s.db.Exec(`UPDATE audit SET actor = 'token:claude' WHERE id = 2`)
	if err := s.VerifyAudit(); err != nil {
		t.Fatal(err)
	}
	s.db.Exec(`DELETE FROM audit WHERE id = 2`)
	if err := s.VerifyAudit(); !errors.Is(err, ErrAuditTampered) {
		t.Fatalf("deletion not detected: %v", err)
	}
}

func TestOwnerPasswordAndTOTP(t *testing.T) {
	s := unsealedStore(t)
	if err := s.CheckOwnerPassword(testPass(t)); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("no password yet: %v", err)
	}
	if err := s.SetOwnerPassword([]byte("short")); !errors.Is(err, ErrWeakPassword) {
		t.Fatal("short password accepted")
	}
	pw := testPass(t)
	if err := s.SetOwnerPassword(pw); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckOwnerPassword(pw); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckOwnerPassword(testPass(t)); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("wrong password accepted")
	}

	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	if s.TOTPEnabled() {
		t.Fatal("totp enabled by default")
	}
	if err := s.CheckTOTP("000000"); !errors.Is(err, ErrTOTPNotSetUp) {
		t.Fatal("check without setup")
	}
	uri, err := s.BeginTOTP()
	if err != nil {
		t.Fatal(err)
	}
	secret := secretFromURI(t, uri)
	if err := s.ConfirmTOTP("abcdef"); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("wrong confirm code accepted")
	}
	if err := s.ConfirmTOTP(totp.Code(secret, now)); err != nil {
		t.Fatal(err)
	}
	if !s.TOTPEnabled() {
		t.Fatal("not enabled")
	}
	// The code used for confirmation cannot be used again.
	if err := s.CheckTOTP(totp.Code(secret, now)); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("replay accepted")
	}
	now = now.Add(30 * time.Second)
	if err := s.CheckTOTP(totp.Code(secret, now)); err != nil {
		t.Fatal(err)
	}
	s.Seal()
	if err := s.CheckTOTP(totp.Code(secret, now.Add(30*time.Second))); !errors.Is(err, ErrSealed) {
		t.Fatal("totp check while sealed")
	}
}

func secretFromURI(t *testing.T, uri string) []byte {
	t.Helper()
	_, q, _ := strings.Cut(uri, "secret=")
	q, _, _ = strings.Cut(q, "&")
	b, err := totpB32.DecodeString(q)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var totpB32 = base32.StdEncoding.WithPadding(base32.NoPadding)
