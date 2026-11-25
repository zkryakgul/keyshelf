package vault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Known-answer test: draft-irtf-cfrg-xchacha-01, appendix A.3.1.
func TestSealKnownAnswer(t *testing.T) {
	plaintext := mustHex(t, "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e")
	aad := mustHex(t, "50515253c0c1c2c3c4c5c6c7")
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex(t, "404142434445464748494a4b4c4d4e4f5051525354555657")
	want := mustHex(t, "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52ec0875924c1c7987947deafd8780acf49")

	blob, err := sealWithNonce(key, nonce, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob[:NonceSize], nonce) || !bytes.Equal(blob[NonceSize:], want) {
		t.Fatalf("blob does not match the known answer")
	}
	got, err := Open(key, blob, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatal("round trip mismatch")
	}
}

// Known-answer test: Argon2id reference vector (P-H-C CLI), password "password", salt "somesalt".
func TestArgon2idKnownAnswer(t *testing.T) {
	got := deriveKey([]byte("password"), []byte("somesalt"), 1, 64, 1, 24)
	want := mustHex(t, "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb")
	if !bytes.Equal(got, want) {
		t.Fatalf("argon2id mismatch: %x", got)
	}
}

func newKey(t *testing.T) []byte {
	t.Helper()
	k, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNonceUniqueness(t *testing.T) {
	key := newKey(t)
	seen := make(map[string]bool)
	for range 10000 {
		blob, err := Seal(key, []byte("x"), nil)
		if err != nil {
			t.Fatal(err)
		}
		n := string(blob[:NonceSize])
		if seen[n] {
			t.Fatal("nonce repeated")
		}
		seen[n] = true
	}
}

func TestOpenFailures(t *testing.T) {
	key := newKey(t)
	aad := FieldAAD(7, "password", 1)
	blob, err := Seal(key, []byte("value"), aad)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]func() error{
		"wrong key": func() error { _, err := Open(newKey(t), blob, aad); return err },
		"wrong field": func() error {
			_, err := Open(key, blob, FieldAAD(7, "token", 1))
			return err
		},
		"wrong entry": func() error {
			_, err := Open(key, blob, FieldAAD(8, "password", 1))
			return err
		},
		"wrong version": func() error {
			_, err := Open(key, blob, FieldAAD(7, "password", 2))
			return err
		},
		"tampered": func() error {
			bad := bytes.Clone(blob)
			bad[len(bad)-1] ^= 1
			_, err := Open(key, bad, aad)
			return err
		},
		"truncated": func() error { _, err := Open(key, blob[:NonceSize+3], aad); return err },
		"short key": func() error { _, err := Open(key[:16], blob, aad); return err },
	}
	for name, f := range cases {
		if err := f(); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: want ErrDecrypt, got %v", name, err)
		}
	}
}

func TestFieldAADIsUnambiguous(t *testing.T) {
	// Length-prefixing must keep ("ab", "c") and ("a", "bc")-style splits apart.
	if bytes.Equal(FieldAAD(1, "ab", 1), FieldAAD(1, "a", 1)) {
		t.Fatal("aad collision")
	}
	if bytes.Equal(FieldAAD(12, "x", 3), FieldAAD(1, "2x", 3)) {
		t.Fatal("aad collision")
	}
}

func TestKDFParamsValidation(t *testing.T) {
	p, err := NewKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("defaults must be valid: %v", err)
	}
	weak := []KDFParams{
		{Time: 3, MemoryKiB: 32 * 1024, Threads: 4, Salt: p.Salt},
		{Time: 0, MemoryKiB: 64 * 1024, Threads: 4, Salt: p.Salt},
		{Time: 3, MemoryKiB: 64 * 1024, Threads: 0, Salt: p.Salt},
		{Time: 3, MemoryKiB: 64 * 1024, Threads: 4, Salt: p.Salt[:8]},
		{Time: 3, MemoryKiB: 1 << 30, Threads: 4, Salt: p.Salt},
		{Time: 1000, MemoryKiB: 64 * 1024, Threads: 4, Salt: p.Salt},
		{Time: 3, MemoryKiB: 64 * 1024, Threads: 255, Salt: p.Salt},
	}
	for i, w := range weak {
		if w.Validate() == nil {
			t.Errorf("case %d: weak params accepted", i)
		}
		if _, err := DeriveKEK([]byte("pass"), w); err == nil {
			t.Errorf("case %d: DeriveKEK accepted weak params", i)
		}
	}
}

func TestWrapUnwrapDEK(t *testing.T) {
	p, err := NewKDFParams()
	if err != nil {
		t.Fatal(err)
	}
	dek := newKey(t)
	kek, err := DeriveKEK([]byte("correct horse"), p)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := WrapKey(kek, dek, "passphrase")
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapKey(kek, wrapped, "passphrase")
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("unwrap failed: %v", err)
	}
	if _, err := UnwrapKey(kek, wrapped, "recovery"); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrap purpose must be bound")
	}
	wrongKEK, err := DeriveKEK([]byte("wrong horse"), p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapKey(wrongKEK, wrapped, "passphrase"); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrong passphrase must fail")
	}
}

func TestRecoveryCode(t *testing.T) {
	code, err := NewRecoveryCode()
	if err != nil {
		t.Fatal(err)
	}
	// 160 bits as base32 = 32 chars, in 8 groups of 4.
	if len(strings.ReplaceAll(code, "-", "")) != 32 || strings.Count(code, "-") != 7 {
		t.Fatalf("unexpected format %q", code)
	}
	norm, err := NormalizeRecoveryCode(" " + strings.ToLower(strings.ReplaceAll(code, "-", " ")) + "\n")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := NormalizeRecoveryCode(code)
	if !bytes.Equal(norm, want) {
		t.Fatal("normalisation must ignore case, spaces and dashes")
	}
	if _, err := NormalizeRecoveryCode("too-short"); err == nil {
		t.Fatal("short code accepted")
	}
	other, _ := NewRecoveryCode()
	if other == code {
		t.Fatal("codes repeat")
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3}
	Wipe(b)
	if !bytes.Equal(b, []byte{0, 0, 0}) {
		t.Fatal("not wiped")
	}
}

func TestPasswordHash(t *testing.T) {
	pw := newKey(t)
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyPassword(pw, h); !ok || err != nil {
		t.Fatalf("right password rejected: %v", err)
	}
	if ok, _ := VerifyPassword(newKey(t), h); ok {
		t.Fatal("wrong password accepted")
	}
	weak := h
	weak.KDF.MemoryKiB = 1024
	if _, err := VerifyPassword(pw, weak); err == nil {
		t.Fatal("weak stored parameters must be refused")
	}
	if bytes.Equal(MetaAAD("a"), FieldAAD(0, "a", 0)) {
		t.Fatal("meta and field AAD must differ")
	}
}
