// Package store keeps keyshelf's data in one SQLite file: folders, entries, encrypted fields with their
// versions, and the wrapped data encryption key. It also owns the seal state: while sealed the store
// holds no key and refuses every data operation.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/zkryakgul/keyshelf/internal/vault"
)

var (
	ErrSealed             = errors.New("store: sealed")
	ErrNotInitialized     = errors.New("store: not initialised")
	ErrAlreadyInitialized = errors.New("store: already initialised")
	ErrBadCredentials     = errors.New("store: wrong passphrase or recovery code")
	ErrWeakPassphrase     = fmt.Errorf("store: passphrase must be at least %d bytes", MinPassphraseLen)
	ErrNotFound           = errors.New("store: not found")
	ErrConflict           = errors.New("store: conflict")
	ErrInvalidName        = errors.New("store: invalid name")
	ErrTooLarge           = errors.New("store: value too large")
)

const (
	MinPassphraseLen = 12
	MaxValueSize     = 64 << 10
	DefaultField     = "password"
	// NotesField holds an entry's notes when they are marked secret. Names with a leading underscore
	// are reserved for keyshelf and cannot be set as ordinary fields.
	NotesField = "_notes"

	purposePassphrase = "passphrase"
	purposeRecovery   = "recovery"
)

var (
	segmentRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	fieldRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	kinds     = []string{"login", "api-key", "url", "note"}
)

// Store is safe for concurrent use.
type Store struct {
	db  *sql.DB
	mu  sync.RWMutex // guards dek; held for reading during every data operation
	dek []byte
	now func() time.Time
}

// Open opens (or creates) the database at path with mode 0600. The store starts sealed.
func Open(path string) (*Store, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- the database path is chosen by the owner
	if err != nil {
		return nil, err
	}
	f.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, err
	}
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // one writer, no SQLITE_BUSY between our own connections
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	for _, side := range []string{"-wal", "-shm"} {
		if err := os.Chmod(path+side, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			db.Close()
			return nil, err
		}
	}
	return s, nil
}

// Close seals the store and closes the database.
func (s *Store) Close() error {
	s.Seal()
	return s.db.Close()
}

// ---- seal state ----

type keyRecord struct {
	KDF     vault.KDFParams `json:"kdf"`
	Wrapped []byte          `json:"wrapped"`
}

// Initialized reports whether Init has run.
func (s *Store) Initialized() bool {
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM meta WHERE key = 'key_passphrase'`).Scan(&n)
	return n == 1
}

// Sealed reports whether the store holds no key.
func (s *Store) Sealed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dek == nil
}

// Init creates the data key, wraps it under the passphrase and a new recovery code, and leaves the store
// unsealed. The recovery code is returned once and never stored.
func (s *Store) Init(passphrase []byte) (string, error) {
	if len(passphrase) < MinPassphraseLen {
		return "", ErrWeakPassphrase
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Initialized() {
		return "", ErrAlreadyInitialized
	}
	dek, err := vault.NewKey()
	if err != nil {
		return "", err
	}
	passRec, err := wrapFor(dek, passphrase, purposePassphrase)
	if err != nil {
		return "", err
	}
	code, err := vault.NewRecoveryCode()
	if err != nil {
		return "", err
	}
	norm, err := vault.NormalizeRecoveryCode(code)
	if err != nil {
		return "", err
	}
	recRec, err := wrapFor(dek, norm, purposeRecovery)
	if err != nil {
		return "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err := putKey(tx, "key_passphrase", passRec); err != nil {
		return "", err
	}
	if err := putKey(tx, "key_recovery", recRec); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	s.dek = dek
	return code, nil
}

// Unseal loads the data key using the passphrase.
func (s *Store) Unseal(passphrase []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dek, err := s.unwrap("key_passphrase", passphrase, purposePassphrase)
	if err != nil {
		return err
	}
	s.setDEK(dek)
	return nil
}

// Recover unseals with the recovery code and replaces the passphrase. The recovery code stays valid.
func (s *Store) Recover(code string, newPassphrase []byte) error {
	if len(newPassphrase) < MinPassphraseLen {
		return ErrWeakPassphrase
	}
	norm, err := vault.NormalizeRecoveryCode(code)
	if err != nil {
		return ErrBadCredentials
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dek, err := s.unwrap("key_recovery", norm, purposeRecovery)
	if err != nil {
		return err
	}
	if err := s.rewrapPassphrase(dek, newPassphrase); err != nil {
		vault.Wipe(dek)
		return err
	}
	s.setDEK(dek)
	return nil
}

// ChangePassphrase re-wraps the data key under a new passphrase. The seal state does not change.
func (s *Store) ChangePassphrase(oldPassphrase, newPassphrase []byte) error {
	if len(newPassphrase) < MinPassphraseLen {
		return ErrWeakPassphrase
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	dek, err := s.unwrap("key_passphrase", oldPassphrase, purposePassphrase)
	if err != nil {
		return err
	}
	defer vault.Wipe(dek)
	return s.rewrapPassphrase(dek, newPassphrase)
}

// Seal drops the data key from memory.
func (s *Store) Seal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setDEK(nil)
}

func (s *Store) setDEK(dek []byte) {
	if s.dek != nil {
		vault.Wipe(s.dek)
	}
	s.dek = dek
}

func (s *Store) unwrap(metaKey string, secret []byte, purpose string) ([]byte, error) {
	var raw []byte
	err := s.db.QueryRow(`SELECT value FROM meta WHERE key = ?`, metaKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotInitialized
	}
	if err != nil {
		return nil, err
	}
	var rec keyRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("store: key record: %w", err)
	}
	kek, err := vault.DeriveKEK(secret, rec.KDF)
	if err != nil {
		return nil, err // weak or tampered parameters: refuse, do not report as a wrong passphrase
	}
	defer vault.Wipe(kek)
	dek, err := vault.UnwrapKey(kek, rec.Wrapped, purpose)
	if err != nil {
		return nil, ErrBadCredentials
	}
	return dek, nil
}

func (s *Store) rewrapPassphrase(dek, passphrase []byte) error {
	rec, err := wrapFor(dek, passphrase, purposePassphrase)
	if err != nil {
		return err
	}
	return putKey(s.db, "key_passphrase", rec)
}

func wrapFor(dek, secret []byte, purpose string) (keyRecord, error) {
	p, err := vault.NewKDFParams()
	if err != nil {
		return keyRecord{}, err
	}
	kek, err := vault.DeriveKEK(secret, p)
	if err != nil {
		return keyRecord{}, err
	}
	defer vault.Wipe(kek)
	w, err := vault.WrapKey(kek, dek, purpose)
	if err != nil {
		return keyRecord{}, err
	}
	return keyRecord{KDF: p, Wrapped: w}, nil
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func putKey(db execer, key string, rec keyRecord) error {
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, raw)
	return err
}

// unsealed runs fn with the data key while holding the read lock, so Seal cannot run in between.
func (s *Store) unsealed(fn func(dek []byte) error) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.dek == nil {
		return ErrSealed
	}
	return fn(s.dek)
}

// ---- names and references ----

// Ref addresses one field: Folder/Entry#Field.
type Ref struct {
	Folder, Entry, Field string
}

// ParseRef parses "folder/path/entry#field". The field defaults to "password".
func ParseRef(s string) (Ref, error) {
	path, field, hasField := strings.Cut(s, "#")
	if hasField {
		if strings.Contains(field, "#") || !fieldRe.MatchString(field) {
			return Ref{}, fmt.Errorf("%w: field %q", ErrInvalidName, field)
		}
	} else {
		field = DefaultField
	}
	folder, entry, err := SplitPath(path)
	if err != nil {
		return Ref{}, err
	}
	return Ref{Folder: folder, Entry: entry, Field: field}, nil
}

// SplitPath splits "folder/path/entry" into its folder and entry name, validating both.
func SplitPath(path string) (folder, entry string, err error) {
	if path == "" {
		return "", "", fmt.Errorf("%w: empty path", ErrInvalidName)
	}
	if err := ValidateFolder(path); err != nil {
		return "", "", err
	}
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "", path, nil
	}
	return path[:i], path[i+1:], nil
}

// ValidateFolder checks a folder path; "" is the root.
func ValidateFolder(path string) error {
	if path == "" {
		return nil // root
	}
	for _, seg := range strings.Split(path, "/") {
		if !segmentRe.MatchString(seg) || seg == "." || seg == ".." {
			return fmt.Errorf("%w: %q", ErrInvalidName, path)
		}
	}
	return nil
}

func validateField(name string) error {
	if !fieldRe.MatchString(name) {
		return fmt.Errorf("%w: field %q", ErrInvalidName, name)
	}
	return nil
}

func joinPath(folder, name string) string {
	if folder == "" {
		return name
	}
	return folder + "/" + name
}

// ---- folders ----

type Folder struct {
	ID   int64  `json:"id"`
	Path string `json:"path"`
}

// EnsureFolder creates path and its ancestors if needed.
func (s *Store) EnsureFolder(path string) error {
	if err := ValidateFolder(path); err != nil {
		return err
	}
	return s.unsealed(func([]byte) error {
		return s.inTx(func(tx *sql.Tx) error {
			_, err := s.ensureFolderTx(tx, path)
			return err
		})
	})
}

func (s *Store) ensureFolderTx(tx *sql.Tx, path string) (int64, error) {
	var id int64
	err := tx.QueryRow(`SELECT id FROM folders WHERE path = '' `).Scan(&id)
	if err != nil {
		return 0, err
	}
	if path == "" {
		return id, nil
	}
	cur := ""
	for _, seg := range strings.Split(path, "/") {
		parentID := id
		cur = joinPath(cur, seg)
		var n int
		if err := tx.QueryRow(`SELECT COUNT(*) FROM entries WHERE folder_id = ? AND name = ? AND deleted_at IS NULL`, parentID, seg).Scan(&n); err != nil {
			return 0, err
		}
		if n > 0 {
			return 0, fmt.Errorf("%w: an entry named %q already exists", ErrConflict, cur)
		}
		err := tx.QueryRow(`SELECT id FROM folders WHERE path = ? AND deleted_at IS NULL`, cur).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			err = tx.QueryRow(`INSERT INTO folders (path, created_at) VALUES (?, ?) RETURNING id`, cur, s.now().Unix()).Scan(&id)
		}
		if err != nil {
			return 0, err
		}
	}
	return id, nil
}

// ListFolders returns every live folder, the root ("") included, sorted by path.
func (s *Store) ListFolders() ([]Folder, error) {
	var out []Folder
	err := s.unsealed(func([]byte) error {
		rows, err := s.db.Query(`SELECT id, path FROM folders WHERE deleted_at IS NULL ORDER BY path`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f Folder
			if err := rows.Scan(&f.ID, &f.Path); err != nil {
				return err
			}
			out = append(out, f)
		}
		return rows.Err()
	})
	return out, err
}

// DeleteFolder removes an empty folder.
func (s *Store) DeleteFolder(path string) error {
	if path == "" {
		return fmt.Errorf("%w: cannot delete the root folder", ErrConflict)
	}
	if err := ValidateFolder(path); err != nil {
		return err
	}
	return s.unsealed(func([]byte) error {
		return s.inTx(func(tx *sql.Tx) error {
			var id int64
			err := tx.QueryRow(`SELECT id FROM folders WHERE path = ? AND deleted_at IS NULL`, path).Scan(&id)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			var n int
			err = tx.QueryRow(`SELECT (SELECT COUNT(*) FROM entries WHERE folder_id = ?1 AND deleted_at IS NULL)
				+ (SELECT COUNT(*) FROM folders WHERE deleted_at IS NULL AND substr(path, 1, ?2) = ?3)`,
				id, len(path)+1, path+"/").Scan(&n)
			if err != nil {
				return err
			}
			if n > 0 {
				return fmt.Errorf("%w: folder %q is not empty", ErrConflict, path)
			}
			_, err = tx.Exec(`UPDATE folders SET deleted_at = ? WHERE id = ?`, s.now().Unix(), id)
			return err
		})
	})
}

// ---- entries ----

// Entry is an entry's metadata. Values are never part of it; Fields lists the names of the live fields.
type Entry struct {
	ID          int64      `json:"id"`
	Folder      string     `json:"folder"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	URL         string     `json:"url"`
	Username    string     `json:"username"`
	Notes       string     `json:"notes"`
	SecretNotes bool       `json:"secret_notes"`
	Tags        []string   `json:"tags"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	Fields      []string   `json:"fields"`
	CreatedBy   string     `json:"created_by"`
	UpdatedBy   string     `json:"updated_by"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Path returns "folder/name".
func (e Entry) Path() string { return joinPath(e.Folder, e.Name) }

// EntryInput is the full metadata of an entry; PutEntry replaces what is stored.
type EntryInput struct {
	Ref         string     `json:"ref"` // folder/path/entry
	Kind        string     `json:"kind"`
	URL         string     `json:"url"`
	Username    string     `json:"username"`
	Notes       string     `json:"notes"`
	SecretNotes bool       `json:"secret_notes"`
	Tags        []string   `json:"tags"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// PutEntry creates the entry (and its folders) or replaces its metadata. Fields are kept.
func (s *Store) PutEntry(in EntryInput, actor string) error {
	folder, name, err := SplitPath(in.Ref)
	if err != nil {
		return err
	}
	if in.Kind == "" {
		in.Kind = "login"
	}
	if !slices.Contains(kinds, in.Kind) {
		return fmt.Errorf("%w: kind %q", ErrInvalidName, in.Kind)
	}
	if len(in.Notes) > MaxValueSize || len(in.URL) > 4096 || len(in.Username) > 1024 {
		return ErrTooLarge
	}
	if in.Tags == nil {
		in.Tags = []string{}
	}
	tags, err := json.Marshal(in.Tags)
	if err != nil {
		return err
	}
	var expires *int64
	if in.ExpiresAt != nil {
		v := in.ExpiresAt.Unix()
		expires = &v
	}
	return s.unsealed(func(dek []byte) error {
		return s.inTx(func(tx *sql.Tx) error {
			id, wasSecret, err := s.findOrCreateEntry(tx, folder, name, actor)
			if err != nil {
				return err
			}
			plainNotes := in.Notes
			if in.SecretNotes {
				plainNotes = ""
				if err := s.setFieldTx(tx, dek, id, NotesField, []byte(in.Notes), actor); err != nil {
					return err
				}
			} else if wasSecret {
				if err := s.setFieldTx(tx, dek, id, NotesField, nil, actor); err != nil {
					return err
				}
			}
			_, err = tx.Exec(`UPDATE entries SET kind = ?, url = ?, username = ?, notes = ?, secret_notes = ?, tags = ?,
				expires_at = ?, updated_by = ?, updated_at = ? WHERE id = ?`,
				in.Kind, in.URL, in.Username, plainNotes, in.SecretNotes, string(tags), expires, actor, s.now().Unix(), id)
			return err
		})
	})
}

func (s *Store) findOrCreateEntry(tx *sql.Tx, folder, name, actor string) (id int64, secretNotes bool, err error) {
	folderID, err := s.ensureFolderTx(tx, folder)
	if err != nil {
		return 0, false, err
	}
	err = tx.QueryRow(`SELECT id, secret_notes FROM entries WHERE folder_id = ? AND name = ? AND deleted_at IS NULL`,
		folderID, name).Scan(&id, &secretNotes)
	if err == nil {
		return id, secretNotes, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, false, err
	}
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM folders WHERE path = ? AND deleted_at IS NULL`, joinPath(folder, name)).Scan(&n); err != nil {
		return 0, false, err
	}
	if n > 0 {
		return 0, false, fmt.Errorf("%w: a folder named %q already exists", ErrConflict, joinPath(folder, name))
	}
	now := s.now().Unix()
	err = tx.QueryRow(`INSERT INTO entries (folder_id, name, kind, tags, created_by, updated_by, created_at, updated_at)
		VALUES (?, ?, 'login', '[]', ?, ?, ?, ?) RETURNING id`, folderID, name, actor, actor, now, now).Scan(&id)
	return id, false, err
}

const entryColumns = `e.id, f.path, e.name, e.kind, e.url, e.username, e.notes, e.secret_notes, e.tags, e.expires_at,
	e.created_by, e.updated_by, e.created_at, e.updated_at`

type scanner interface{ Scan(dest ...any) error }

func scanEntry(row scanner) (Entry, error) {
	var e Entry
	var tags string
	var expires sql.NullInt64
	var created, updated int64
	err := row.Scan(&e.ID, &e.Folder, &e.Name, &e.Kind, &e.URL, &e.Username, &e.Notes, &e.SecretNotes, &tags, &expires,
		&e.CreatedBy, &e.UpdatedBy, &created, &updated)
	if err != nil {
		return e, err
	}
	if err := json.Unmarshal([]byte(tags), &e.Tags); err != nil {
		return e, err
	}
	if expires.Valid {
		t := time.Unix(expires.Int64, 0).UTC()
		e.ExpiresAt = &t
	}
	e.CreatedAt, e.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return e, nil
}

func (s *Store) liveFields(entryID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT f.name FROM fields f WHERE f.entry_id = ? AND f.ciphertext IS NOT NULL
		AND substr(f.name, 1, 1) <> '_'
		AND f.version = (SELECT MAX(version) FROM fields g WHERE g.entry_id = f.entry_id AND g.name = f.name)
		ORDER BY f.name`, entryID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetEntry returns the metadata of the entry at path ("folder/name").
func (s *Store) GetEntry(path string) (Entry, error) {
	folder, name, err := SplitPath(path)
	if err != nil {
		return Entry{}, err
	}
	var e Entry
	err = s.unsealed(func([]byte) error {
		e, err = scanEntry(s.db.QueryRow(`SELECT `+entryColumns+` FROM entries e JOIN folders f ON f.id = e.folder_id
			WHERE f.path = ? AND f.deleted_at IS NULL AND e.name = ? AND e.deleted_at IS NULL`, folder, name))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		e.Fields, err = s.liveFields(e.ID)
		return err
	})
	return e, err
}

// ListEntries lists the entries in folder; with recursive, also those in its subfolders.
func (s *Store) ListEntries(folder string, recursive bool) ([]Entry, error) {
	if err := ValidateFolder(folder); err != nil {
		return nil, err
	}
	where := `f.path = ?1`
	if recursive {
		where = `(?1 = '' OR f.path = ?1 OR substr(f.path, 1, ?2) = ?3)`
	}
	return s.queryEntries(where, folder, len(folder)+1, folder+"/")
}

// Search finds entries whose path, URL, username or tags contain q, ignoring case.
func (s *Store) Search(q string) ([]Entry, error) {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return []Entry{}, nil
	}
	return s.queryEntries(`(instr(lower(f.path || '/' || e.name), ?1) > 0 OR instr(lower(e.url), ?1) > 0
		OR instr(lower(e.username), ?1) > 0 OR instr(lower(e.tags), ?1) > 0)`, q)
}

func (s *Store) queryEntries(where string, args ...any) ([]Entry, error) {
	out := []Entry{}
	err := s.unsealed(func([]byte) error {
		// where is one of the constant fragments in ListEntries and Search; every value is a bound argument.
		query := `SELECT ` + entryColumns + ` FROM entries e JOIN folders f ON f.id = e.folder_id
			WHERE e.deleted_at IS NULL AND f.deleted_at IS NULL AND ` + where + ` ORDER BY f.path, e.name` // #nosec G202
		rows, err := s.db.Query(query, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			e, err := scanEntry(rows)
			if err != nil {
				rows.Close()
				return err
			}
			out = append(out, e)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i := range out {
			if out[i].Fields, err = s.liveFields(out[i].ID); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}

// DeleteEntry removes the entry. Its rows are kept (soft delete) so v0.2 can restore it.
func (s *Store) DeleteEntry(path, actor string) error {
	return s.withEntry(path, func(tx *sql.Tx, _ []byte, id int64) error {
		_, err := tx.Exec(`UPDATE entries SET deleted_at = ?, updated_by = ? WHERE id = ?`, s.now().Unix(), actor, id)
		return err
	})
}

func (s *Store) withEntry(path string, fn func(tx *sql.Tx, dek []byte, id int64) error) error {
	folder, name, err := SplitPath(path)
	if err != nil {
		return err
	}
	return s.unsealed(func(dek []byte) error {
		return s.inTx(func(tx *sql.Tx) error {
			var id int64
			err := tx.QueryRow(`SELECT e.id FROM entries e JOIN folders f ON f.id = e.folder_id
				WHERE f.path = ? AND f.deleted_at IS NULL AND e.name = ? AND e.deleted_at IS NULL`, folder, name).Scan(&id)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			if err != nil {
				return err
			}
			return fn(tx, dek, id)
		})
	})
}

// ---- fields ----

// SetField stores a new version of a secret field, creating the entry (kind "login") if needed.
func (s *Store) SetField(path, field string, value []byte, actor string) error {
	if err := validateField(field); err != nil {
		return err
	}
	if len(value) > MaxValueSize {
		return ErrTooLarge
	}
	folder, name, err := SplitPath(path)
	if err != nil {
		return err
	}
	return s.unsealed(func(dek []byte) error {
		return s.inTx(func(tx *sql.Tx) error {
			id, _, err := s.findOrCreateEntry(tx, folder, name, actor)
			if err != nil {
				return err
			}
			if value == nil {
				value = []byte{}
			}
			if err := s.setFieldTx(tx, dek, id, field, value, actor); err != nil {
				return err
			}
			return s.touch(tx, id, actor)
		})
	})
}

// DeleteField removes a field; earlier versions are kept.
func (s *Store) DeleteField(path, field, actor string) error {
	if err := validateField(field); err != nil {
		return err
	}
	return s.withEntry(path, func(tx *sql.Tx, dek []byte, id int64) error {
		var ct []byte
		err := tx.QueryRow(`SELECT ciphertext FROM fields WHERE entry_id = ? AND name = ? ORDER BY version DESC LIMIT 1`, id, field).Scan(&ct)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && ct == nil) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := s.setFieldTx(tx, dek, id, field, nil, actor); err != nil {
			return err
		}
		return s.touch(tx, id, actor)
	})
}

// GetField returns the current value of a field. The caller must not log it.
func (s *Store) GetField(path, field string) ([]byte, error) {
	if field != NotesField {
		if err := validateField(field); err != nil {
			return nil, err
		}
	}
	var out []byte
	err := s.withEntry(path, func(tx *sql.Tx, dek []byte, id int64) error {
		var version int64
		var ct []byte
		err := tx.QueryRow(`SELECT version, ciphertext FROM fields WHERE entry_id = ? AND name = ? ORDER BY version DESC LIMIT 1`,
			id, field).Scan(&version, &ct)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && ct == nil) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out, err = vault.Open(dek, ct, vault.FieldAAD(id, field, version))
		if err != nil {
			return fmt.Errorf("store: field %s#%s cannot be decrypted: %w", path, field, err)
		}
		return nil
	})
	return out, err
}

// setFieldTx writes the next version of a field; value nil writes a tombstone.
func (s *Store) setFieldTx(tx *sql.Tx, dek []byte, entryID int64, field string, value []byte, actor string) error {
	var version int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(version), 0) + 1 FROM fields WHERE entry_id = ? AND name = ?`, entryID, field).Scan(&version); err != nil {
		return err
	}
	var ct []byte
	if value != nil {
		var err error
		ct, err = vault.Seal(dek, value, vault.FieldAAD(entryID, field, version))
		if err != nil {
			return err
		}
	}
	_, err := tx.Exec(`INSERT INTO fields (entry_id, name, version, ciphertext, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		entryID, field, version, ct, actor, s.now().Unix())
	return err
}

func (s *Store) touch(tx *sql.Tx, entryID int64, actor string) error {
	_, err := tx.Exec(`UPDATE entries SET updated_by = ?, updated_at = ? WHERE id = ?`, actor, s.now().Unix(), entryID)
	return err
}

func (s *Store) inTx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Backup writes a consistent copy of the database (still encrypted) to dest, which must not exist.
// It works while the server runs and while sealed.
func (s *Store) Backup(dest string) error {
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("%w: %s already exists", ErrConflict, dest)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- the backup path is chosen by the owner
	if err != nil {
		return err
	}
	f.Close()
	os.Remove(dest) // VACUUM INTO wants to create it; we only reserved the name with the right mode
	if _, err := s.db.Exec(`VACUUM INTO ?`, dest); err != nil {
		return err
	}
	return os.Chmod(dest, 0o600)
}
