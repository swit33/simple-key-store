package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// Store is the client-side encrypted cache (secrets-spec.md §5). It owns a
// single-writer SQLite database holding local_secrets and local_meta.
type Store struct {
	db *sql.DB
}

var (
	// ErrNotFound means no live record exists for the requested path.
	ErrNotFound = errors.New("not found")
	// ErrInvalidPath means the path violates the §2 alphabet (D2): a lowercase
	// segment list, no leading/trailing slash, no empty, "." or ".." segments,
	// at most 512 bytes. Callers map it to exit code 1, never to ErrNotFound.
	ErrInvalidPath = errors.New("invalid path")
	// errEmptyBlob means a caller passed a nil or zero-length ciphertext/nonce.
	errEmptyBlob = errors.New("empty blob")
)

// dbFile is the cache database file name inside the store directory.
const dbFile = "cache.db"

// maxPathLen is the byte limit of §2 ("[a-z0-9._/-]{1,512}").
const maxPathLen = 512

// Record is one row of local_secrets. Rev, Version and BaseVersion are the
// sync metadata of §5; M1 writes them with their defaults (0, "", "") and
// marks every local write dirty until a push clears it.
type Record struct {
	Path        string
	Ciphertext  []byte
	Nonce       []byte
	Rev         int64
	Version     string
	BaseVersion string
	Dirty       bool
	Deleted     bool
	Conflict    bool
}

// ValidatePath reports whether path is a legal §2 key path. The rules are
// exact: segments of [a-z0-9._-] separated by single '/', no empty, "." or
// ".." segment, no leading or trailing slash, 1..512 bytes.
//
// It walks the string byte by byte and allocates nothing on success, so it is
// cheap enough to call on every Set/Get/Delete before touching SQL.
func ValidatePath(path string) error {
	if len(path) == 0 || len(path) > maxPathLen {
		return fmt.Errorf("%w: %d bytes, want 1..%d", ErrInvalidPath, len(path), maxPathLen)
	}
	segStart := 0
	for i := 0; i < len(path); i++ {
		switch c := path[i]; {
		case c == '/':
			if !validSegment(path[segStart:i]) {
				return fmt.Errorf("%w: %q", ErrInvalidPath, path)
			}
			segStart = i + 1
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
			// Legal byte of the §2 alphabet.
		default:
			return fmt.Errorf("%w: %q", ErrInvalidPath, path)
		}
	}
	if !validSegment(path[segStart:]) {
		return fmt.Errorf("%w: %q", ErrInvalidPath, path)
	}
	return nil
}

// validSegment reports whether seg is a non-empty segment that is not "." or
// "..". Bytes are already known to be legal.
func validSegment(seg string) bool {
	return seg != "" && seg != "." && seg != ".."
}

// Open creates (or reopens) the store directory, pre-creates the database file
// with tight permissions and returns a Store. The directory is 0700 and
// cache.db 0600, both set explicitly rather than left to umask (D15).
//
// The DSN carries the §2 PRAGMAs as modernc per-connection options, so every
// pooled connection gets them — including the ones opened later, which a
// single db.Exec after sql.Open would miss.
func Open(path string) (_ *Store, err error) {
	if err = prepareDir(path); err != nil {
		return nil, err
	}
	dbPath := filepath.Join(path, dbFile)
	if err = prepareFile(dbPath); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", dsn(dbPath))
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()

	// M1 writes through one connection (D15); the tests raise the limit
	// temporarily to prove the PRAGMAs come from the DSN, not from this pool.
	db.SetMaxOpenConns(1)

	for _, stmt := range []string{ddlSecrets, ddlMeta, ddlSchemaVersion} {
		if _, err = db.Exec(stmt); err != nil {
			return nil, err
		}
	}

	return &Store{db: db}, nil
}

const (
	ddlSecrets = `CREATE TABLE IF NOT EXISTS local_secrets (
		path TEXT PRIMARY KEY,
		ciphertext BLOB NOT NULL,
		nonce BLOB NOT NULL,
		rev INTEGER NOT NULL DEFAULT 0,
		version TEXT NOT NULL DEFAULT '',
		base_version TEXT NOT NULL DEFAULT '',
		dirty INTEGER NOT NULL DEFAULT 1,
		deleted INTEGER NOT NULL DEFAULT 0,
		conflict INTEGER NOT NULL DEFAULT 0
	)`

	ddlMeta = `CREATE TABLE IF NOT EXISTS local_meta (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL
	)`

	ddlSchemaVersion = `INSERT INTO local_meta(key, value) VALUES ('schema_version', '1')
		ON CONFLICT(key) DO NOTHING`
)

// prepareDir creates the store directory and tightens an existing one to 0700.
func prepareDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}
	return nil
}

// prepareFile pre-creates cache.db as 0600 before sql.Open, and tightens a
// pre-existing loose file. O_CREATE does not change the mode of an existing
// file, so the chmod is not redundant.
func prepareFile(name string) error {
	f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("chmod %s: %w", name, err)
	}
	return f.Close()
}

// dsn builds the modernc DSN with the §2 PRAGMA set applied on every
// connection. temp_store in particular is not inherited by new connections,
// and a disk-backed temp store would spill decrypted pages (§1, D15).
func dsn(dbPath string) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "temp_store(MEMORY)")
	return (&url.URL{Scheme: "file", OmitHost: true, Path: dbPath, RawQuery: q.Encode()}).String()
}

// Close closes the underlying database.
func (store *Store) Close() error {
	return store.db.Close()
}

// Set stores ciphertext and nonce for path, replacing any previous value and
// clearing the tombstone. Empty paths and empty blobs are rejected before any
// SQL runs.
func (store *Store) Set(ctx context.Context, path string, ciphertext, nonce []byte) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	if len(ciphertext) == 0 || len(nonce) == 0 {
		return fmt.Errorf("set %q: %w", path, errEmptyBlob)
	}
	_, err := store.db.ExecContext(ctx, `
		INSERT INTO local_secrets(path, ciphertext, nonce)
		VALUES (?, ?, ?)
		ON CONFLICT(path) DO UPDATE SET
			ciphertext = excluded.ciphertext,
			nonce = excluded.nonce,
			deleted = 0,
			dirty = 1
		`, path, ciphertext, nonce)
	return err
}

// Get returns the live ciphertext and nonce of path, or ErrNotFound when the
// path is absent or tombstoned. An invalid path is a validation error, never
// ErrNotFound.
func (store *Store) Get(ctx context.Context, path string) (ciphertext, nonce []byte, err error) {
	if err := ValidatePath(path); err != nil {
		return nil, nil, err
	}
	err = store.db.QueryRowContext(ctx, `
		SELECT ciphertext, nonce FROM local_secrets WHERE path = ? AND deleted = 0
		`, path).Scan(&ciphertext, &nonce)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil, ErrNotFound
		}
		return nil, nil, err
	}
	return ciphertext, nonce, nil
}

// Delete tombstones path (§2: never a physical delete, the deletion has to
// reach other machines). Missing and already-deleted paths are ErrNotFound.
func (store *Store) Delete(ctx context.Context, path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	res, err := store.db.ExecContext(ctx, `
		UPDATE local_secrets SET deleted = 1, dirty = 1 WHERE path = ? AND deleted = 0
		`, path)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("delete %q: %w", path, ErrNotFound)
	}
	return nil
}

// List returns every live record, ordered by path. Tombstoned rows are
// excluded; Rev/Version/BaseVersion carry whatever sync metadata the row has.
func (store *Store) List(ctx context.Context) ([]Record, error) {
	rows, err := store.db.QueryContext(ctx, `
		SELECT path, ciphertext, nonce, rev, version, base_version, dirty, deleted, conflict
		FROM local_secrets WHERE deleted = 0 ORDER BY path
		`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var recs []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(
			&r.Path, &r.Ciphertext, &r.Nonce, &r.Rev, &r.Version,
			&r.BaseVersion, &r.Dirty, &r.Deleted, &r.Conflict,
		); err != nil {
			return nil, err
		}
		recs = append(recs, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return recs, nil
}
