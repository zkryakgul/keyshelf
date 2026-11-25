// Package vault holds keyshelf's cryptographic primitives: key generation, Argon2id key derivation,
// XChaCha20-Poly1305 sealing of values and wrapping of the data encryption key. It only composes
// golang.org/x/crypto and crypto/rand; it implements no primitive of its own.
package vault

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = chacha20poly1305.KeySize    // 32 bytes
	NonceSize = chacha20poly1305.NonceSizeX // 24 bytes
	SaltSize  = 16

	minTimeCost  = 1
	minMemoryKiB = 64 * 1024
	minThreads   = 1
)

// ErrDecrypt is returned for every failure to open a sealed value: wrong key, wrong associated data,
// tampering or truncation. Callers must not be able to tell these cases apart.
var ErrDecrypt = errors.New("vault: decryption failed")

// NewKey returns a fresh random 256-bit key.
func NewKey() ([]byte, error) {
	k := make([]byte, KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("vault: random key: %w", err)
	}
	return k, nil
}

// Seal encrypts plaintext under key with a random nonce. The result is nonce || ciphertext || tag.
func Seal(key, plaintext, aad []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: random nonce: %w", err)
	}
	return sealWithNonce(key, nonce, plaintext, aad) // #nosec G407 -- the nonce is fresh from crypto/rand just above
}

func sealWithNonce(key, nonce, plaintext, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("vault: %w", err)
	}
	out := make([]byte, NonceSize, NonceSize+len(plaintext)+aead.Overhead())
	copy(out, nonce)
	return aead.Seal(out, nonce, plaintext, aad), nil
}

// Open reverses Seal. Any failure yields ErrDecrypt.
func Open(key, blob, aad []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ErrDecrypt
	}
	if len(blob) < NonceSize+aead.Overhead() {
		return nil, ErrDecrypt
	}
	pt, err := aead.Open(nil, blob[:NonceSize], blob[NonceSize:], aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// FieldAAD binds a sealed value to its entry, field and version, so a ciphertext cannot be moved to
// another place in the database and still open. Fields are length-prefixed to stay unambiguous.
func FieldAAD(entryID int64, field string, version int64) []byte {
	return encodeAAD("field", fmt.Sprint(entryID), field, fmt.Sprint(version))
}

func encodeAAD(parts ...string) []byte {
	var b []byte
	b = append(b, "keyshelf-v1"...)
	for _, p := range parts {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p))) // #nosec G115 -- AAD parts are short strings
		b = append(b, p...)
	}
	return b
}

// KDFParams are the Argon2id parameters stored next to each wrapped key.
type KDFParams struct {
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      []byte `json:"salt"`
}

// NewKDFParams returns the default parameters (t=3, 64 MiB, 4 lanes) with a fresh random salt.
func NewKDFParams() (KDFParams, error) {
	salt := make([]byte, SaltSize)
	if _, err := rand.Read(salt); err != nil {
		return KDFParams{}, fmt.Errorf("vault: random salt: %w", err)
	}
	return KDFParams{Time: 3, MemoryKiB: minMemoryKiB, Threads: 4, Salt: salt}, nil
}

// Validate rejects parameters below the floor, so a tampered database cannot downgrade the KDF.
func (p KDFParams) Validate() error {
	switch {
	case p.Time < minTimeCost:
		return errors.New("vault: argon2 time cost too low")
	case p.MemoryKiB < minMemoryKiB:
		return errors.New("vault: argon2 memory too low")
	case p.Threads < minThreads:
		return errors.New("vault: argon2 threads too low")
	case len(p.Salt) < SaltSize:
		return errors.New("vault: salt too short")
	}
	return nil
}

// DeriveKEK derives a key encryption key from a passphrase or recovery code.
func DeriveKEK(secret []byte, p KDFParams) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return deriveKey(secret, p.Salt, p.Time, p.MemoryKiB, p.Threads, KeySize), nil
}

func deriveKey(secret, salt []byte, time, memoryKiB uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(secret, salt, time, memoryKiB, threads, keyLen)
}

// WrapKey seals dek under kek. purpose ("passphrase", "recovery") is bound as associated data so a
// wrap made for one unlock method cannot be presented as another.
func WrapKey(kek, dek []byte, purpose string) ([]byte, error) {
	return Seal(kek, dek, encodeAAD("wrap", purpose))
}

// UnwrapKey reverses WrapKey.
func UnwrapKey(kek, wrapped []byte, purpose string) ([]byte, error) {
	dek, err := Open(kek, wrapped, encodeAAD("wrap", purpose))
	if err != nil {
		return nil, err
	}
	if len(dek) != KeySize {
		Wipe(dek)
		return nil, ErrDecrypt
	}
	return dek, nil
}

var recoveryEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

const recoveryBytes = 20 // 160 bits, 32 base32 characters

// NewRecoveryCode returns a random recovery code such as "ABCD-EFGH-...", 8 groups of 4 characters.
func NewRecoveryCode() (string, error) {
	raw := make([]byte, recoveryBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("vault: random recovery code: %w", err)
	}
	s := recoveryEncoding.EncodeToString(raw)
	var groups []string
	for i := 0; i < len(s); i += 4 {
		groups = append(groups, s[i:i+4])
	}
	return strings.Join(groups, "-"), nil
}

// NormalizeRecoveryCode turns what a person typed into the canonical bytes fed to DeriveKEK.
// Case, spaces and dashes are ignored.
func NormalizeRecoveryCode(typed string) ([]byte, error) {
	s := strings.ToUpper(typed)
	s = strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, s)
	raw, err := recoveryEncoding.DecodeString(s)
	if err != nil || len(raw) != recoveryBytes {
		return nil, errors.New("vault: malformed recovery code")
	}
	return []byte(s), nil
}

// Wipe overwrites b with zeros. It is best effort: Go may have copied the bytes elsewhere.
func Wipe(b []byte) {
	clear(b)
}

// PasswordHash is an Argon2id hash of a login password with its parameters.
type PasswordHash struct {
	KDF  KDFParams `json:"kdf"`
	Hash []byte    `json:"hash"`
}

// HashPassword hashes a login password with fresh default parameters.
func HashPassword(password []byte) (PasswordHash, error) {
	p, err := NewKDFParams()
	if err != nil {
		return PasswordHash{}, err
	}
	h, err := DeriveKEK(password, p)
	if err != nil {
		return PasswordHash{}, err
	}
	return PasswordHash{KDF: p, Hash: h}, nil
}

// VerifyPassword reports whether password matches h, in constant time. It returns an error only for
// unusable parameters (weak or tampered), never for a wrong password.
func VerifyPassword(password []byte, h PasswordHash) (bool, error) {
	got, err := DeriveKEK(password, h.KDF)
	if err != nil {
		return false, err
	}
	defer Wipe(got)
	return subtle.ConstantTimeCompare(got, h.Hash) == 1, nil
}

// MetaAAD binds a value sealed outside the fields table (such as the TOTP secret) to its name.
func MetaAAD(name string) []byte {
	return encodeAAD("meta", name)
}
