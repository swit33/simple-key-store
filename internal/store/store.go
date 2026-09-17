package store

import (
	"errors"
	"os"
	"path/filepath"

	// "errors"
	"context"
	"database/sql"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

var ErrNotFound = errors.New("not found")

const dbFile = "cache.db"

func Open(path string) (*Store, error) {
	err := os.MkdirAll(path, 0700)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", filepath.Join(path, dbFile))
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	_, err = db.Exec(`PRAGMA journal_mode=WAL`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`PRAGMA busy_timeout=5000`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`PRAGMA synchronous=NORMAL`)
	if err != nil {
		return nil, err
	}
	_, err = db.Exec(`PRAGMA temp_store=MEMORY`)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS local_secrets (
		path TEXT PRIMARY KEY,
		ciphertext BLOB NOT NULL,
		nonce BLOB NOT NULL,
		deleted INTEGER NOT NULL
	)`)
	if err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

func (store *Store) Close() error {
	return store.db.Close()
}

func (store *Store) Set(ctx context.Context, path string, ciphertext, nonce []byte) error {
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO local_secrets(path, ciphertext, nonce, deleted)
		VALUES (?, ?, ?, 0)
		ON CONFLICT(path) DO UPDATE SET 
			ciphertext = excluded.ciphertext,
			nonce = excluded.nonce,
			deleted = 0,	
		`, path, ciphertext, nonce)
	if err != nil {
		return err
	}
	return nil
}

func (store *Store) Get(ctx context.Context, path string) (ciphertext, nonce []byte, err error) {
	row := store.db.QueryRowContext(ctx, `
		SELECT ciphertext, nonce FROM local_secrets WHERE path = ? AND deleted = 0
		`, path)
	err = row.Scan(&ciphertext, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	return ciphertext, nonce, nil
}
