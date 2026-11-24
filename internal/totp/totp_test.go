package totp

import (
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 column (8 digits).
func TestKnownAnswers(t *testing.T) {
	secret := []byte("12345678901234567890")
	cases := map[int64]string{
		59:          "94287082",
		1111111109:  "07081804",
		1111111111:  "14050471",
		1234567890:  "89005924",
		2000000000:  "69279037",
		20000000000: "65353130",
	}
	for ts, want := range cases {
		if got := codeAt(secret, uint64(ts/Period), 8); got != want {
			t.Errorf("t=%d: got %s want %s", ts, got, want)
		}
		if got := Code(secret, time.Unix(ts, 0)); got != want[2:] {
			t.Errorf("t=%d six digits: got %s want %s", ts, got, want[2:])
		}
	}
}

func TestVerify(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	code := Code(secret, now)
	step, ok := Verify(secret, code, now, 0)
	if !ok {
		t.Fatal("current code rejected")
	}
	if _, ok := Verify(secret, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	if _, ok := Verify(secret, Code(secret, now.Add(-30*time.Second)), now, 0); !ok {
		t.Fatal("previous step must be accepted (clock skew)")
	}
	if _, ok := Verify(secret, Code(secret, now.Add(-90*time.Second)), now, 0); ok {
		t.Fatal("old code accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Verify(secret, bad, now, 0); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
	u := URI(secret, "owner")
	if !strings.HasPrefix(u, "otpauth://totp/keyshelf:owner?") || !strings.Contains(u, "issuer=keyshelf") {
		t.Fatalf("uri %s", u)
	}
}
