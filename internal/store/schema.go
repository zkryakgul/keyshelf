package store

import (
	"database/sql"
	"errors"
	"fmt"
)

// migrations are applied in order; each runs once, recorded in meta.schema_version. Never edit a
// released migration: append a new one.
var migrations = []string{
	// 1: folders, entries, versioned encrypted fields.
	`CREATE TABLE folders (
		id         INTEGER PRIMARY KEY,
		path       TEXT    NOT NULL,
		created_at INTEGER NOT NULL,
		deleted_at INTEGER
	);
	CREATE UNIQUE INDEX folders_live_path ON folders(path) WHERE deleted_at IS NULL;
	INSERT INTO folders (path, created_at) VALUES ('', 0);

	CREATE TABLE entries (
		id           INTEGER PRIMARY KEY,
		owner_id     INTEGER NOT NULL DEFAULT 1,
		folder_id    INTEGER NOT NULL REFERENCES folders(id),
		name         TEXT    NOT NULL,
		kind         TEXT    NOT NULL,
		url          TEXT    NOT NULL DEFAULT '',
		username     TEXT    NOT NULL DEFAULT '',
		notes        TEXT    NOT NULL DEFAULT '',
		secret_notes INTEGER NOT NULL DEFAULT 0,
		tags         TEXT    NOT NULL DEFAULT '[]',
		expires_at   INTEGER,
		created_by   TEXT    NOT NULL,
		updated_by   TEXT    NOT NULL,
		created_at   INTEGER NOT NULL,
		updated_at   INTEGER NOT NULL,
		deleted_at   INTEGER
	);
	CREATE UNIQUE INDEX entries_live_name ON entries(folder_id, name) WHERE deleted_at IS NULL;

	CREATE TABLE fields (
		id         INTEGER PRIMARY KEY,
		entry_id   INTEGER NOT NULL REFERENCES entries(id),
		name       TEXT    NOT NULL,
		version    INTEGER NOT NULL,
		ciphertext BLOB,              -- NULL marks a deleted field
		created_by TEXT    NOT NULL,
		created_at INTEGER NOT NULL,
		UNIQUE (entry_id, name, version)
	);`,

	// 2: tokens (agent tokens and owner sessions) and the hash-chained audit log.
	`CREATE TABLE tokens (
		id           INTEGER PRIMARY KEY,
		name         TEXT    NOT NULL,
		kind         TEXT    NOT NULL,          -- 'agent' or 'owner'
		hash         BLOB    NOT NULL UNIQUE,   -- SHA-256 of the token
		scopes       TEXT    NOT NULL DEFAULT '[]',
		created_at   INTEGER NOT NULL,
		expires_at   INTEGER,
		last_used_at INTEGER,
		revoked_at   INTEGER
	);
	CREATE UNIQUE INDEX tokens_live_agent_name ON tokens(name) WHERE revoked_at IS NULL AND kind = 'agent';

	CREATE TABLE audit (
		id        INTEGER PRIMARY KEY,
		at        INTEGER NOT NULL,
		actor     TEXT    NOT NULL,
		action    TEXT    NOT NULL,
		target    TEXT    NOT NULL DEFAULT '',
		source    TEXT    NOT NULL DEFAULT '',
		prev_hash BLOB    NOT NULL,
		hash      BLOB    NOT NULL
	);`,
}

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)`); err != nil {
		return err
	}
	var current int
	err := s.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'`).Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if current > len(migrations) {
		return fmt.Errorf("database schema %d is newer than this binary (%d)", current, len(migrations))
	}
	for i := current; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.Exec(`INSERT INTO meta (key, value) VALUES ('schema_version', ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`, i+1); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}
