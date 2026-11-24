package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/zkryakgul/keyshelf/internal/totp"
	"github.com/zkryakgul/keyshelf/internal/vault"
)

// MinPasswordLen is the minimum owner login password length.
const MinPasswordLen = 12

var (
	ErrWeakPassword  = fmt.Errorf("store: password must be at least %d bytes", MinPasswordLen)
	ErrTOTPNotSetUp  = errors.New("store: TOTP is not set up")
	ErrTOTPRequired  = errors.New("store: TOTP code required")
	errNoTOTPPending = errors.New("store: no TOTP setup in progress")
)

type totpRecord struct {
	Sealed   []byte `json:"sealed"` // secret sealed with the DEK
	Enabled  bool   `json:"enabled"`
	LastStep int64  `json:"last_step"`
}

func (s *Store) getMeta(key string, v any) (bool, error) {
	var raw []byte
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, v)
}

func (s *Store) setMeta(key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, raw)
	return err
}

// SetOwnerPassword sets or replaces the owner's login password.
func (s *Store) SetOwnerPassword(password []byte) error {
	if len(password) < MinPasswordLen {
		return ErrWeakPassword
	}
	h, err := vault.HashPassword(password)
	if err != nil {
		return err
	}
	return s.setMeta("owner_password", h)
}

// HasOwnerPassword reports whether a login password is set.
func (s *Store) HasOwnerPassword() bool {
	var h vault.PasswordHash
	ok, err := s.getMeta("owner_password", &h)
	return ok && err == nil
}

// CheckOwnerPassword returns nil if password is right, ErrBadCredentials otherwise.
func (s *Store) CheckOwnerPassword(password []byte) error {
	var h vault.PasswordHash
	ok, err := s.getMeta("owner_password", &h)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotInitialized
	}
	match, err := vault.VerifyPassword(password, h)
	if err != nil {
		return err
	}
	if !match {
		return ErrBadCredentials
	}
	return nil
}

// TOTPEnabled reports whether TOTP is set up and confirmed.
func (s *Store) TOTPEnabled() bool {
	var r totpRecord
	ok, err := s.getMeta("totp", &r)
	return ok && err == nil && r.Enabled
}

// BeginTOTP creates a new pending TOTP secret and returns its otpauth:// URI. It replaces any earlier
// pending one; an enabled TOTP stays in force until ConfirmTOTP succeeds with the new secret.
func (s *Store) BeginTOTP() (string, error) {
	var uri string
	err := s.unsealed(func(dek []byte) error {
		secret, err := totp.NewSecret()
		if err != nil {
			return err
		}
		defer vault.Wipe(secret)
		sealed, err := vault.Seal(dek, secret, vault.MetaAAD("totp_pending"))
		if err != nil {
			return err
		}
		uri = totp.URI(secret, "owner")
		return s.setMeta("totp_pending", totpRecord{Sealed: sealed})
	})
	return uri, err
}

// ConfirmTOTP enables the pending secret if code matches it.
func (s *Store) ConfirmTOTP(code string) error {
	return s.unsealed(func(dek []byte) error {
		var p totpRecord
		ok, err := s.getMeta("totp_pending", &p)
		if err != nil {
			return err
		}
		if !ok {
			return errNoTOTPPending
		}
		secret, err := vault.Open(dek, p.Sealed, vault.MetaAAD("totp_pending"))
		if err != nil {
			return err
		}
		defer vault.Wipe(secret)
		step, match := totp.Verify(secret, code, s.now(), 0)
		if !match {
			return ErrBadCredentials
		}
		sealed, err := vault.Seal(dek, secret, vault.MetaAAD("totp"))
		if err != nil {
			return err
		}
		if err := s.setMeta("totp", totpRecord{Sealed: sealed, Enabled: true, LastStep: step}); err != nil {
			return err
		}
		_, err = s.db.Exec(`DELETE FROM meta WHERE key = 'totp_pending'`)
		return err
	})
}

// CheckTOTP verifies a code against the enabled secret; each code is accepted once.
func (s *Store) CheckTOTP(code string) error {
	return s.unsealed(func(dek []byte) error {
		var r totpRecord
		ok, err := s.getMeta("totp", &r)
		if err != nil {
			return err
		}
		if !ok || !r.Enabled {
			return ErrTOTPNotSetUp
		}
		secret, err := vault.Open(dek, r.Sealed, vault.MetaAAD("totp"))
		if err != nil {
			return err
		}
		defer vault.Wipe(secret)
		step, match := totp.Verify(secret, code, s.now(), r.LastStep)
		if !match {
			return ErrBadCredentials
		}
		r.LastStep = step
		return s.setMeta("totp", r)
	})
}
