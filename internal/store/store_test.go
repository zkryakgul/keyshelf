package store

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// testPass returns a random passphrase; tests never use fixed secrets.
func testPass(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return []byte(filepath.Base(t.Name()) + "-" + string(rune('a'+b[0]%26)) + string(b[1:]))
}

func randValue(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func openTemp(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keyshelf.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func unsealedStore(t *testing.T) *Store {
	t.Helper()
	s, _ := openTemp(t)
	if _, err := s.Init(testPass(t)); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDatabaseFileMode(t *testing.T) {
	_, path := openTemp(t)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %o, want 600", fi.Mode().Perm())
	}
}

func TestSealLifecycle(t *testing.T) {
	s, path := openTemp(t)
	if s.Initialized() || !s.Sealed() {
		t.Fatal("fresh store must be uninitialised and sealed")
	}
	if err := s.Unseal([]byte("anything-long-enough")); !errors.Is(err, ErrNotInitialized) {
		t.Fatalf("unseal before init: %v", err)
	}
	if _, err := s.Init([]byte("short")); !errors.Is(err, ErrWeakPassphrase) {
		t.Fatalf("short passphrase: %v", err)
	}
	pass := testPass(t)
	code, err := s.Init(pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Init(pass); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second init: %v", err)
	}
	if s.Sealed() {
		t.Fatal("init must leave the store unsealed")
	}
	value := randValue(t)
	if err := s.SetField("work/acme/db", "password", value, "owner"); err != nil {
		t.Fatal(err)
	}

	s.Seal()
	if _, err := s.GetField("work/acme/db", "password"); !errors.Is(err, ErrSealed) {
		t.Fatalf("read while sealed: %v", err)
	}
	if err := s.Unseal([]byte("wrong passphrase value")); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong passphrase: %v", err)
	}

	// Reopen from disk: state must survive and start sealed.
	s.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if !s2.Initialized() || !s2.Sealed() {
		t.Fatal("reopened store must be initialised and sealed")
	}
	if err := s2.Unseal(pass); err != nil {
		t.Fatal(err)
	}
	got, err := s2.GetField("work/acme/db", "password")
	if err != nil || !bytes.Equal(got, value) {
		t.Fatalf("value after reopen: %v", err)
	}

	// Recovery code resets the passphrase.
	s2.Seal()
	newPass := testPass(t)
	if err := s2.Recover("AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA", newPass); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("wrong recovery code: %v", err)
	}
	if err := s2.Recover(code, newPass); err != nil {
		t.Fatal(err)
	}
	s2.Seal()
	if err := s2.Unseal(pass); !errors.Is(err, ErrBadCredentials) {
		t.Fatal("old passphrase must stop working after recovery")
	}
	if err := s2.Unseal(newPass); err != nil {
		t.Fatal(err)
	}

	// Change passphrase.
	third := testPass(t)
	if err := s2.ChangePassphrase([]byte("not the current one!"), third); !errors.Is(err, ErrBadCredentials) {
		t.Fatalf("change with wrong old: %v", err)
	}
	if err := s2.ChangePassphrase(newPass, third); err != nil {
		t.Fatal(err)
	}
	s2.Seal()
	if err := s2.Unseal(third); err != nil {
		t.Fatal(err)
	}
	got, _ = s2.GetField("work/acme/db", "password")
	if !bytes.Equal(got, value) {
		t.Fatal("value lost after passphrase change")
	}
}

func TestNoPlaintextOnDisk(t *testing.T) {
	s, path := openTemp(t)
	if _, err := s.Init(testPass(t)); err != nil {
		t.Fatal(err)
	}
	value := []byte("needle-" + hex.EncodeToString(randValue(t)))
	if err := s.SetField("a/b", "token", value, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutEntry(EntryInput{Ref: "a/b", Notes: string(value), SecretNotes: true}, "owner"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	for _, p := range []string{path, path + "-wal"} {
		raw, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if bytes.Contains(raw, value) {
			t.Fatalf("plaintext found in %s", filepath.Base(p))
		}
	}
}

func TestCiphertextIsBoundToItsRow(t *testing.T) {
	s := unsealedStore(t)
	if err := s.SetField("f/one", "password", randValue(t), "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetField("f/two", "password", randValue(t), "owner"); err != nil {
		t.Fatal(err)
	}
	// Copy entry one's ciphertext onto entry two, as an attacker with write access to the file could.
	_, err := s.db.Exec(`UPDATE fields SET ciphertext = (SELECT f.ciphertext FROM fields f JOIN entries e ON e.id = f.entry_id WHERE e.name = 'one')
		WHERE entry_id = (SELECT id FROM entries WHERE name = 'two')`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetField("f/two", "password"); err == nil {
		t.Fatal("moved ciphertext must not decrypt")
	}
}

func TestEntriesAndFields(t *testing.T) {
	s := unsealedStore(t)
	err := s.PutEntry(EntryInput{
		Ref: "work/acme/staging/db", Kind: "login", URL: "https://db.example.test",
		Username: "admin", Notes: "primary", Tags: []string{"db", "staging"},
	}, "owner")
	if err != nil {
		t.Fatal(err)
	}
	v1, v2 := randValue(t), randValue(t)
	if err := s.SetField("work/acme/staging/db", "password", v1, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetField("work/acme/staging/db", "password", v2, "agent:claude"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetField("work/acme/staging/db", "password")
	if err != nil || !bytes.Equal(got, v2) {
		t.Fatal("latest version must win")
	}
	var versions int
	s.db.QueryRow(`SELECT COUNT(*) FROM fields WHERE name = 'password'`).Scan(&versions)
	if versions != 2 {
		t.Fatalf("old version must be kept, have %d rows", versions)
	}

	e, err := s.GetEntry("work/acme/staging/db")
	if err != nil {
		t.Fatal(err)
	}
	if e.Kind != "login" || e.Username != "admin" || e.Folder != "work/acme/staging" || e.UpdatedBy != "agent:claude" {
		t.Fatalf("unexpected entry %+v", e)
	}
	if len(e.Fields) != 1 || e.Fields[0] != "password" {
		t.Fatalf("fields %v", e.Fields)
	}

	// Metadata update keeps fields.
	if err := s.PutEntry(EntryInput{Ref: "work/acme/staging/db", Kind: "login", Username: "root"}, "owner"); err != nil {
		t.Fatal(err)
	}
	e, _ = s.GetEntry("work/acme/staging/db")
	if e.Username != "root" || len(e.Fields) != 1 {
		t.Fatalf("after update %+v", e)
	}

	if err := s.DeleteField("work/acme/staging/db", "password", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetField("work/acme/staging/db", "password"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted field: %v", err)
	}
	e, _ = s.GetEntry("work/acme/staging/db")
	if len(e.Fields) != 0 {
		t.Fatalf("deleted field still listed: %v", e.Fields)
	}

	if err := s.DeleteEntry("work/acme/staging/db", "owner"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetEntry("work/acme/staging/db"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted entry: %v", err)
	}
	// The name can be used again.
	if err := s.SetField("work/acme/staging/db", "password", v1, "owner"); err != nil {
		t.Fatal(err)
	}
}

func TestSecretNotes(t *testing.T) {
	s := unsealedStore(t)
	notes := "recovery codes: " + string(randValue(t)[:4])
	if err := s.PutEntry(EntryInput{Ref: "x/y", Notes: notes, SecretNotes: true}, "owner"); err != nil {
		t.Fatal(err)
	}
	e, _ := s.GetEntry("x/y")
	if e.Notes != "" || !e.SecretNotes {
		t.Fatal("secret notes must not appear in metadata")
	}
	got, err := s.GetField("x/y", NotesField)
	if err != nil || string(got) != notes {
		t.Fatalf("secret notes: %v", err)
	}
	if err := s.SetField("x/y", "_other", []byte("v"), "owner"); !errors.Is(err, ErrInvalidName) {
		t.Fatal("fields with a leading underscore are reserved")
	}
}

func TestFolderEntryNameClash(t *testing.T) {
	s := unsealedStore(t)
	if err := s.EnsureFolder("a/b"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutEntry(EntryInput{Ref: "a/b"}, "owner"); !errors.Is(err, ErrConflict) {
		t.Fatalf("entry over folder: %v", err)
	}
	if err := s.PutEntry(EntryInput{Ref: "a/c"}, "owner"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureFolder("a/c/d"); !errors.Is(err, ErrConflict) {
		t.Fatalf("folder over entry: %v", err)
	}
}

func TestListAndSearch(t *testing.T) {
	s := unsealedStore(t)
	for _, in := range []EntryInput{
		{Ref: "work/acme/db", URL: "https://db.example.test", Tags: []string{"postgres"}},
		{Ref: "work/acme/staging/api", Tags: []string{"api"}},
		{Ref: "home/router", URL: "http://router.example.test"},
		{Ref: "rootentry"},
	} {
		if err := s.PutEntry(in, "owner"); err != nil {
			t.Fatal(err)
		}
	}
	names := func(es []Entry) []string {
		var out []string
		for _, e := range es {
			out = append(out, e.Path())
		}
		return out
	}
	list, err := s.ListEntries("work/acme", false)
	if err != nil || len(list) != 1 || list[0].Path() != "work/acme/db" {
		t.Fatalf("non-recursive list: %v %v", names(list), err)
	}
	list, _ = s.ListEntries("work", true)
	if len(list) != 2 {
		t.Fatalf("recursive list: %v", names(list))
	}
	list, _ = s.ListEntries("", true)
	if len(list) != 4 {
		t.Fatalf("list all: %v", names(list))
	}
	// "work/ac" must not match "work/acme" as a prefix.
	if list, _ = s.ListEntries("work/ac", true); len(list) != 0 {
		t.Fatalf("prefix leak: %v", names(list))
	}
	if res, _ := s.Search("router"); len(res) != 1 {
		t.Fatalf("search by url: %v", names(res))
	}
	if res, _ := s.Search("POSTGRES"); len(res) != 1 {
		t.Fatalf("search by tag: %v", names(res))
	}
	if res, _ := s.Search("%"); len(res) != 0 {
		t.Fatalf("LIKE wildcards must be literal: %v", names(res))
	}
	folders, _ := s.ListFolders()
	want := map[string]bool{"": true, "work": true, "work/acme": true, "work/acme/staging": true, "home": true}
	if len(folders) != len(want) {
		t.Fatalf("folders %v", folders)
	}
	for _, f := range folders {
		if !want[f.Path] {
			t.Fatalf("unexpected folder %q", f.Path)
		}
	}
	if err := s.DeleteFolder("work"); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete non-empty folder: %v", err)
	}
}

func TestValidation(t *testing.T) {
	s := unsealedStore(t)
	bad := []string{"", "a//b", "../x", "a/./b", "a b", "a/" + string(make([]byte, 65)), "/abs"}
	for _, r := range bad {
		if err := s.PutEntry(EntryInput{Ref: r}, "owner"); !errors.Is(err, ErrInvalidName) {
			t.Errorf("ref %q accepted: %v", r, err)
		}
	}
	if err := s.PutEntry(EntryInput{Ref: "a/b", Kind: "weird"}, "owner"); !errors.Is(err, ErrInvalidName) {
		t.Errorf("bad kind accepted: %v", err)
	}
	if err := s.SetField("a/b", "password", make([]byte, MaxValueSize+1), "owner"); !errors.Is(err, ErrTooLarge) {
		t.Errorf("huge value accepted: %v", err)
	}
}

func TestParseRef(t *testing.T) {
	cases := []struct{ in, folder, entry, field string }{
		{"work/acme/db#token", "work/acme", "db", "token"},
		{"work/acme/db", "work/acme", "db", "password"},
		{"db", "", "db", "password"},
	}
	for _, c := range cases {
		r, err := ParseRef(c.in)
		if err != nil || r.Folder != c.folder || r.Entry != c.entry || r.Field != c.field {
			t.Errorf("%q -> %+v %v", c.in, r, err)
		}
	}
	for _, in := range []string{"a#", "#x", "a#b#c", "a/#x"} {
		if _, err := ParseRef(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestForeignKeysOn(t *testing.T) {
	s := unsealedStore(t)
	_, err := s.db.Exec(`INSERT INTO entries (folder_id, name, kind, tags, created_by, updated_by, created_at, updated_at) VALUES (9999, 'x', 'login', '[]', 'o', 'o', 0, 0)`)
	if err == nil {
		t.Fatal("foreign keys are not enforced")
	}
	var _ *sql.DB = s.db
}

func TestBackup(t *testing.T) {
	s := unsealedStore(t)
	v := randValue(t)
	if err := s.SetField("a/b", "password", v, "owner"); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "backup.db")
	if err := s.Backup(dest); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dest); fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %o", fi.Mode().Perm())
	}
	if err := s.Backup(dest); !errors.Is(err, ErrConflict) {
		t.Fatal("backup must not overwrite")
	}
	raw, _ := os.ReadFile(dest)
	if bytes.Contains(raw, v) {
		t.Fatal("plaintext in backup")
	}
	b, err := Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !b.Initialized() || !b.Sealed() {
		t.Fatal("backup must be initialised and sealed")
	}
}
