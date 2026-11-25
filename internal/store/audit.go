package store

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Event is one audit log row. It never contains a secret value.
type Event struct {
	ID     int64     `json:"id"`
	At     time.Time `json:"at"`
	Actor  string    `json:"actor"`  // "owner", "token:<name>" or "anonymous"
	Action string    `json:"action"` // e.g. value.read, entry.put, unseal.fail
	Target string    `json:"target"` // entry path, path#field, token name...
	Source string    `json:"source"` // remote address or "cli"
}

// ErrAuditTampered is returned by VerifyAudit when the hash chain is broken.
var ErrAuditTampered = errors.New("store: audit log hash chain broken")

func eventHash(prev []byte, e Event) []byte {
	h := sha256.New()
	h.Write(prev)
	for _, part := range []string{fmt.Sprint(e.ID), fmt.Sprint(e.At.Unix()), e.Actor, e.Action, e.Target, e.Source} {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(part)))) // #nosec G115 -- audit fields are short strings
		h.Write([]byte(part))
	}
	return h.Sum(nil)
}

// Audit appends an event. It works while sealed (unseal attempts are logged too).
func (s *Store) Audit(e Event) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	prev := make([]byte, sha256.Size)
	var lastID int64
	err = tx.QueryRow(`SELECT id, hash FROM audit ORDER BY id DESC LIMIT 1`).Scan(&lastID, &prev)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	e.ID = lastID + 1
	e.At = s.now().UTC().Truncate(time.Second)
	_, err = tx.Exec(`INSERT INTO audit (id, at, actor, action, target, source, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.At.Unix(), e.Actor, e.Action, e.Target, e.Source, prev, eventHash(prev, e))
	if err != nil {
		return err
	}
	return tx.Commit()
}

// AuditFilter selects events; zero values match everything. Target matches exactly or as a prefix
// followed by '#' (so "a/b" also returns "a/b#password").
type AuditFilter struct {
	Target string
	Limit  int
}

// ListAudit returns events, newest first.
func (s *Store) ListAudit(f AuditFilter) ([]Event, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	rows, err := s.db.Query(`SELECT id, at, actor, action, target, source FROM audit
		WHERE ?1 = '' OR target = ?1 OR substr(target, 1, ?2) = ?3
		ORDER BY id DESC LIMIT ?4`, f.Target, len(f.Target)+1, f.Target+"#", f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		var at int64
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Source); err != nil {
			return nil, err
		}
		e.At = time.Unix(at, 0).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyAudit walks the whole chain. It detects edited, removed or reordered rows; it cannot stop
// someone with write access to the file from rebuilding the chain from scratch.
func (s *Store) VerifyAudit() error {
	rows, err := s.db.Query(`SELECT id, at, actor, action, target, source, prev_hash, hash FROM audit ORDER BY id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	prev := make([]byte, sha256.Size)
	var wantID int64 = 1
	for rows.Next() {
		var e Event
		var at int64
		var p, h []byte
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.Target, &e.Source, &p, &h); err != nil {
			return err
		}
		e.At = time.Unix(at, 0).UTC()
		if e.ID != wantID || !bytes.Equal(p, prev) || !bytes.Equal(h, eventHash(prev, e)) {
			return fmt.Errorf("%w at row %d", ErrAuditTampered, e.ID)
		}
		prev, wantID = h, wantID+1
	}
	return rows.Err()
}
