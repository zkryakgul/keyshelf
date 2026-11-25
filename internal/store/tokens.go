package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

const (
	KindAgent = "agent"
	KindOwner = "owner"

	PermList  = "list"
	PermRead  = "read"
	PermWrite = "write"

	tokenPrefix = "ks_"
)

var (
	ErrUnauthorized = errors.New("store: invalid, expired or revoked token")
	allPerms        = []string{PermList, PermRead, PermWrite}
)

// Scope grants permissions on a folder and everything below it. Folder "" is the whole shelf.
type Scope struct {
	Folder string   `json:"folder"`
	Perms  []string `json:"perms"`
}

// Token is a stored token; the secret itself is never kept.
type Token struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"`
	Scopes     []Scope    `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// IsOwner reports whether the token is an owner session.
func (t Token) IsOwner() bool { return t.Kind == KindOwner }

// Actor is the name written to the audit log and to created_by/updated_by.
func (t Token) Actor() string {
	if t.IsOwner() {
		return "owner"
	}
	return "token:" + t.Name
}

// Allows reports whether the token holds perm on folder. Owner sessions hold every permission.
func (t Token) Allows(perm, folder string) bool {
	if t.IsOwner() {
		return true
	}
	for _, sc := range t.Scopes {
		inside := sc.Folder == "" || folder == sc.Folder || strings.HasPrefix(folder, sc.Folder+"/")
		if inside && slices.Contains(sc.Perms, perm) {
			return true
		}
	}
	return false
}

func validateScopes(scopes []Scope) error {
	if len(scopes) == 0 {
		return fmt.Errorf("%w: a token needs at least one scope", ErrInvalidName)
	}
	for _, sc := range scopes {
		if err := ValidateFolder(sc.Folder); err != nil {
			return err
		}
		if len(sc.Perms) == 0 {
			return fmt.Errorf("%w: scope %q has no permissions", ErrInvalidName, sc.Folder)
		}
		for _, p := range sc.Perms {
			if !slices.Contains(allPerms, p) {
				return fmt.Errorf("%w: permission %q", ErrInvalidName, p)
			}
		}
	}
	return nil
}

func hashToken(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}

func newTokenSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// CreateAgentToken creates a scoped token. The secret is returned once and only its hash is stored.
func (s *Store) CreateAgentToken(name string, scopes []Scope, ttl time.Duration) (string, Token, error) {
	if !segmentRe.MatchString(name) {
		return "", Token{}, fmt.Errorf("%w: token name %q", ErrInvalidName, name)
	}
	if err := validateScopes(scopes); err != nil {
		return "", Token{}, err
	}
	secret, tok, err := s.insertToken(name, KindAgent, scopes, ttl)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return "", Token{}, fmt.Errorf("%w: a token named %q exists", ErrConflict, name)
	}
	return secret, tok, err
}

// CreateOwnerSession creates an owner session token valid for ttl, and removes expired sessions.
func (s *Store) CreateOwnerSession(ttl time.Duration) (string, Token, error) {
	if _, err := s.db.Exec(`DELETE FROM tokens WHERE kind = 'owner' AND (expires_at <= ? OR revoked_at IS NOT NULL)`, s.now().Unix()); err != nil {
		return "", Token{}, err
	}
	return s.insertToken("session", KindOwner, []Scope{}, ttl)
}

func (s *Store) insertToken(name, kind string, scopes []Scope, ttl time.Duration) (string, Token, error) {
	secret, err := newTokenSecret()
	if err != nil {
		return "", Token{}, err
	}
	raw, err := json.Marshal(scopes)
	if err != nil {
		return "", Token{}, err
	}
	now := s.now()
	tok := Token{Name: name, Kind: kind, Scopes: scopes, CreatedAt: now.UTC().Truncate(time.Second)}
	var expires *int64
	if ttl > 0 {
		e := now.Add(ttl).UTC().Truncate(time.Second)
		tok.ExpiresAt = &e
		v := e.Unix()
		expires = &v
	}
	err = s.db.QueryRow(`INSERT INTO tokens (name, kind, hash, scopes, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
		name, kind, hashToken(secret), string(raw), now.Unix(), expires).Scan(&tok.ID)
	if err != nil {
		return "", Token{}, err
	}
	return secret, tok, nil
}

const tokenColumns = `id, name, kind, scopes, created_at, expires_at, last_used_at` // #nosec G101 -- a list of column names, not a credential

func scanToken(row scanner) (Token, error) {
	var t Token
	var scopes string
	var created int64
	var expires, used sql.NullInt64
	if err := row.Scan(&t.ID, &t.Name, &t.Kind, &scopes, &created, &expires, &used); err != nil {
		return t, err
	}
	if err := json.Unmarshal([]byte(scopes), &t.Scopes); err != nil {
		return t, err
	}
	t.CreatedAt = time.Unix(created, 0).UTC()
	if expires.Valid {
		e := time.Unix(expires.Int64, 0).UTC()
		t.ExpiresAt = &e
	}
	if used.Valid {
		u := time.Unix(used.Int64, 0).UTC()
		t.LastUsedAt = &u
	}
	return t, nil
}

// Authenticate looks up a live token by its secret and records its use.
func (s *Store) Authenticate(secret string) (Token, error) {
	if !strings.HasPrefix(secret, tokenPrefix) || len(secret) > 128 {
		return Token{}, ErrUnauthorized
	}
	now := s.now().Unix()
	tok, err := scanToken(s.db.QueryRow(`SELECT `+tokenColumns+` FROM tokens
		WHERE hash = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)`, hashToken(secret), now))
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrUnauthorized
	}
	if err != nil {
		return Token{}, err
	}
	if _, err := s.db.Exec(`UPDATE tokens SET last_used_at = ? WHERE id = ?`, now, tok.ID); err != nil {
		return Token{}, err
	}
	used := time.Unix(now, 0).UTC()
	tok.LastUsedAt = &used
	return tok, nil
}

// ListAgentTokens lists live agent tokens.
func (s *Store) ListAgentTokens() ([]Token, error) {
	rows, err := s.db.Query(`SELECT ` + tokenColumns + ` FROM tokens WHERE kind = 'agent' AND revoked_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeOwnerSessions revokes every owner session except keepID (0 keeps none).
func (s *Store) RevokeOwnerSessions(keepID int64) error {
	_, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE kind = 'owner' AND revoked_at IS NULL AND id <> ?`, s.now().Unix(), keepID)
	return err
}

// RevokeToken revokes a token at once.
func (s *Store) RevokeToken(id int64) error {
	res, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, s.now().Unix(), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}
