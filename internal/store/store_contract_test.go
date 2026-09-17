package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// This file pins the M1 store contract: path validation (secrets-spec.md §2,
// DECISIONS.md D2), delete/list beyond set/get (§5), the M1 sync-metadata
// defaults (§5), the SQLite recipe of D15 (permissions, PRAGMA per connection,
// one writer) and the §5 schema. Ciphertext and nonces here are synthetic bytes
// — crypto and plaintext are out of scope for this package.

// openStore opens a store in a fresh subdirectory of t.TempDir and closes it on
// cleanup.
func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "data", "secrets"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func countRows(t *testing.T, s *Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRowContext(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count query %q: %v", query, err)
	}
	return n
}

func TestValidatePath(t *testing.T) {
	valid := []string{
		"a",
		"deepseek-api",
		"prod/pullmd/token",
		"a.b/c_d/e-1",
		"0/1/2",
		strings.Repeat("a", 512),         // exactly the byte limit, single segment
		strings.Repeat("a/", 255) + "aa", // exactly 512 bytes across many segments, no trailing slash
	}
	for _, p := range valid {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) = %v, want nil", p, err)
		}
	}

	invalid := []string{
		"",
		"/leading",
		"trailing/",
		"a//b",
		".",
		"..",
		"../escape",
		"a/../b",
		"Upper",
		"a_b/C",
		"a b",
		"a%b",
		"a\nb",
		"ключ",
		strings.Repeat("a", 513),
		strings.Repeat("a/", 256) + "a", // 513 bytes
	}
	for _, p := range invalid {
		if err := ValidatePath(p); err == nil {
			t.Errorf("ValidatePath(%q) = nil, want error", p)
		}
	}
}

func TestSetRejectsInvalidPathBeforeSQL(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	for _, p := range []string{"", "/leading", "Upper", "a//b", "../escape", "a/..", "trailing/"} {
		err := s.Set(ctx, p, []byte{0x01}, []byte{0x02})
		if err == nil {
			t.Errorf("Set(%q) = nil, want validation error", p)
			continue
		}
		if errors.Is(err, ErrNotFound) {
			t.Errorf("Set(%q) = ErrNotFound, want validation error", p)
		}
	}

	if n := countRows(t, s, `SELECT count(*) FROM local_secrets`); n != 0 {
		t.Fatalf("local_secrets rows = %d, want 0: invalid paths must be rejected before SQL", n)
	}
}

func TestSetRejectsEmptyBlobs(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	cases := []struct {
		name       string
		ciphertext []byte
		nonce      []byte
	}{
		{"nil ciphertext", nil, []byte{0x02}},
		{"empty ciphertext", []byte{}, []byte{0x02}},
		{"nil nonce", []byte{0x01}, nil},
		{"empty nonce", []byte{0x01}, []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.Set(ctx, "prod/api", tc.ciphertext, tc.nonce); err == nil {
				t.Fatal("Set = nil, want error")
			}
		})
	}

	if n := countRows(t, s, `SELECT count(*) FROM local_secrets`); n != 0 {
		t.Fatalf("local_secrets rows = %d, want 0: rejected blobs must not reach SQL", n)
	}
}

func TestSetUpsertAndDeleteTombstone(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	ct1, nc1 := []byte{0x11, 0x22, 0x33}, []byte{0xa1, 0xa2, 0xa3}
	ct2, nc2 := []byte{0x44, 0x55, 0x66}, []byte{0xb1, 0xb2, 0xb3}

	if err := s.Set(ctx, "prod/api", ct1, nc1); err != nil {
		t.Fatalf("Set: %v", err)
	}
	// Upsert replaces the blobs, still exactly one row for the path.
	if err := s.Set(ctx, "prod/api", ct2, nc2); err != nil {
		t.Fatalf("Set (upsert): %v", err)
	}
	gotCT, gotNC, err := s.Get(ctx, "prod/api")
	if err != nil {
		t.Fatalf("Get after upsert: %v", err)
	}
	if !slices.Equal(gotCT, ct2) || !slices.Equal(gotNC, nc2) {
		t.Fatalf("Get after upsert = %x/%x, want %x/%x", gotCT, gotNC, ct2, nc2)
	}
	if n := countRows(t, s, `SELECT count(*) FROM local_secrets WHERE path = ?`, "prod/api"); n != 1 {
		t.Fatalf("rows for prod/api = %d, want 1", n)
	}

	if err := s.Delete(ctx, "prod/api"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := s.Get(ctx, "prod/api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	// Delete is a tombstone, not a physical delete: the row survives for sync.
	var deleted int
	if err := s.db.QueryRowContext(ctx, `SELECT deleted FROM local_secrets WHERE path = ?`, "prod/api").Scan(&deleted); err != nil {
		t.Fatalf("tombstone row missing: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted = %d, want 1", deleted)
	}

	// Missing and already-deleted paths are both ErrNotFound.
	if err := s.Delete(ctx, "prod/api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(tombstoned) = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, "prod/absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(absent) = %v, want ErrNotFound", err)
	}
	if err := s.Delete(ctx, "/bad"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("Delete(invalid path) = %v, want validation error", err)
	}

	// Set resets the tombstone.
	if err := s.Set(ctx, "prod/api", ct1, nc1); err != nil {
		t.Fatalf("Set after Delete: %v", err)
	}
	gotCT, gotNC, err = s.Get(ctx, "prod/api")
	if err != nil {
		t.Fatalf("Get after re-Set: %v", err)
	}
	if !slices.Equal(gotCT, ct1) || !slices.Equal(gotNC, nc1) {
		t.Fatalf("Get after re-Set = %x/%x, want %x/%x", gotCT, gotNC, ct1, nc1)
	}
}

func TestGetValidatesPathAndHidesTombstones(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	for _, p := range []string{"", "/abs", "Upper", "a//b", "..", "a/..", "trailing/"} {
		_, _, err := s.Get(ctx, p)
		if err == nil {
			t.Errorf("Get(%q) = nil, want error", p)
			continue
		}
		if errors.Is(err, ErrNotFound) {
			t.Errorf("Get(%q) = ErrNotFound, want validation error", p)
		}
	}

	if err := s.Set(ctx, "prod/api", []byte{0x01}, []byte{0x02}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := s.Delete(ctx, "prod/api"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, err := s.Get(ctx, "prod/api"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(tombstoned) = %v, want ErrNotFound", err)
	}
	if _, _, err := s.Get(ctx, "prod/absent"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(absent) = %v, want ErrNotFound", err)
	}
}

func TestSetKeepsM1SyncMetadataDefaults(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	if err := s.Set(ctx, "prod/api", []byte{0x01, 0x02}, []byte{0x03, 0x04}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	recs, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("List len = %d, want 1", len(recs))
	}
	r := recs[0]
	if r.Path != "prod/api" {
		t.Errorf("Path = %q, want %q", r.Path, "prod/api")
	}
	if r.Rev != 0 {
		t.Errorf("Rev = %d, want 0", r.Rev)
	}
	if r.Version != "" {
		t.Errorf("Version = %q, want empty", r.Version)
	}
	if r.BaseVersion != "" {
		t.Errorf("BaseVersion = %q, want empty", r.BaseVersion)
	}
	if !r.Dirty {
		t.Error("Dirty = false, want true")
	}
	if r.Deleted {
		t.Error("Deleted = true, want false")
	}
	if r.Conflict {
		t.Error("Conflict = true, want false")
	}

	// An upsert must not corrupt the M1 defaults either.
	if err := s.Set(ctx, "prod/api", []byte{0x05}, []byte{0x06}); err != nil {
		t.Fatalf("Set (upsert): %v", err)
	}
	recs, err = s.List(ctx)
	if err != nil {
		t.Fatalf("List after upsert: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("List len after upsert = %d, want 1", len(recs))
	}
	r = recs[0]
	if r.Rev != 0 || r.Version != "" || r.BaseVersion != "" || !r.Dirty || r.Deleted || r.Conflict {
		t.Fatalf("record after upsert = %+v, want M1 defaults (rev 0, empty versions, dirty, live, no conflict)", r)
	}
}

func TestListReturnsLiveRowsSortedWithCopiedBlobs(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	recs, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List on empty store: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("List on empty store len = %d, want 0", len(recs))
	}

	seeded := []struct {
		path  string
		ct    []byte
		nonce []byte
	}{
		{"prod/z", []byte{0x01}, []byte{0x11}},
		{"prod/a", []byte{0x02}, []byte{0x12}},
		{"alpha", []byte{0x03}, []byte{0x13}},
	}
	wantBlobs := make(map[string][2][]byte, len(seeded))
	for _, e := range seeded {
		if err := s.Set(ctx, e.path, e.ct, e.nonce); err != nil {
			t.Fatalf("Set(%q): %v", e.path, err)
		}
		wantBlobs[e.path] = [2][]byte{e.ct, e.nonce}
	}
	// A tombstoned path must not appear in List.
	if err := s.Set(ctx, "prod/m", []byte{0x04}, []byte{0x14}); err != nil {
		t.Fatalf("Set(prod/m): %v", err)
	}
	if err := s.Delete(ctx, "prod/m"); err != nil {
		t.Fatalf("Delete(prod/m): %v", err)
	}

	recs, err = s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	wantPaths := []string{"alpha", "prod/a", "prod/z"}
	gotPaths := make([]string, len(recs))
	for i, r := range recs {
		gotPaths[i] = r.Path
	}
	if !slices.Equal(gotPaths, wantPaths) {
		t.Fatalf("List paths = %v, want %v (live rows only, sorted)", gotPaths, wantPaths)
	}
	for i, r := range recs {
		want := wantBlobs[r.Path]
		if !slices.Equal(r.Ciphertext, want[0]) || !slices.Equal(r.Nonce, want[1]) {
			t.Errorf("List[%d] (%s) blobs = %x/%x, want %x/%x", i, r.Path, r.Ciphertext, r.Nonce, want[0], want[1])
		}
	}

	// Returned blobs are copies: mutating them must not reach the database.
	for i := range recs {
		for j := range recs[i].Ciphertext {
			recs[i].Ciphertext[j] = 0xff
		}
		for j := range recs[i].Nonce {
			recs[i].Nonce[j] = 0xff
		}
	}
	recs2, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List after mutation: %v", err)
	}
	for i, r := range recs2 {
		want := wantBlobs[r.Path]
		if !slices.Equal(r.Ciphertext, want[0]) || !slices.Equal(r.Nonce, want[1]) {
			t.Fatalf("List[%d] (%s) blobs after mutating previous result = %x/%x, want %x/%x (aliasing)", i, r.Path, r.Ciphertext, r.Nonce, want[0], want[1])
		}
	}

	// Get copies too.
	ct, nonce, err := s.Get(ctx, "prod/a")
	if err != nil {
		t.Fatalf("Get(prod/a): %v", err)
	}
	for j := range ct {
		ct[j] = 0xff
	}
	for j := range nonce {
		nonce[j] = 0xff
	}
	ct2, nonce2, err := s.Get(ctx, "prod/a")
	if err != nil {
		t.Fatalf("Get(prod/a) second time: %v", err)
	}
	wantA := wantBlobs["prod/a"]
	if !slices.Equal(ct2, wantA[0]) || !slices.Equal(nonce2, wantA[1]) {
		t.Fatalf("Get after mutating previous result = %x/%x, want %x/%x (aliasing)", ct2, nonce2, wantA[0], wantA[1])
	}
}

func TestSchemaColumnsAndSchemaVersion(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	cols := tableColumns(t, s, "local_secrets")
	want := []string{"path", "ciphertext", "nonce", "rev", "version", "base_version", "dirty", "deleted", "conflict"}
	for _, name := range want {
		if _, ok := cols[name]; !ok {
			t.Errorf("local_secrets.%s: column missing", name)
		}
	}
	if c, ok := cols["path"]; ok && !c.pk {
		t.Error("local_secrets.path: want primary key")
	}
	for _, name := range []string{"ciphertext", "nonce"} {
		if c, ok := cols[name]; ok && !c.notNull {
			t.Errorf("local_secrets.%s: want NOT NULL", name)
		}
	}

	var version string
	if err := s.db.QueryRowContext(ctx, `SELECT value FROM local_meta WHERE key = 'schema_version'`).Scan(&version); err != nil {
		t.Fatalf("local_meta schema_version: %v", err)
	}
	if version != "1" {
		t.Fatalf("schema_version = %q, want %q", version, "1")
	}
}

func TestOpenPermissions(t *testing.T) {
	ctx := context.Background()
	base := t.TempDir()

	// Fresh directory tree: all levels 0700, DB 0600.
	dir := filepath.Join(base, "fresh", "secrets")
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	assertPerm(t, dir, 0o700)
	dbPath := filepath.Join(dir, dbFile)
	assertPerm(t, dbPath, 0o600)

	if err := s.Set(ctx, "prod/api", []byte{0x01}, []byte{0x02}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	for _, name := range []string{dbFile + "-wal", dbFile + "-shm"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			continue // SQLite may remove -wal/-shm on checkpoint/close.
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s mode = %o, want 600", name, perm)
		}
	}
	assertPerm(t, dbPath, 0o600)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Pre-existing loose directory and DB file are tightened, not accepted as-is.
	loose := filepath.Join(base, "loose")
	if err := os.MkdirAll(loose, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(loose, 0o755); err != nil {
		t.Fatalf("Chmod dir: %v", err)
	}
	looseDB := filepath.Join(loose, dbFile)
	if err := os.WriteFile(looseDB, nil, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.Chmod(looseDB, 0o644); err != nil {
		t.Fatalf("Chmod db: %v", err)
	}

	s2, err := Open(loose)
	if err != nil {
		t.Fatalf("Open(loose): %v", err)
	}
	defer func() { _ = s2.Close() }()
	assertPerm(t, loose, 0o700)
	assertPerm(t, looseDB, 0o600)
	if err := s2.Set(ctx, "prod/api", []byte{0x03}, []byte{0x04}); err != nil {
		t.Fatalf("Set on tightened store: %v", err)
	}
	assertPerm(t, loose, 0o700)
	assertPerm(t, looseDB, 0o600)
}

func TestPragmasArePerConnection(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	// Pin the first pooled connection with an open transaction, then take a
	// second one: PRAGMAs must be applied per connection (D15), not once via
	// db.Exec after Open.
	s.db.SetMaxOpenConns(2)
	pinned, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatalf("Conn: %v", err)
	}
	defer func() { _ = pinned.Close() }()
	if _, err := pinned.ExecContext(ctx, "BEGIN"); err != nil {
		t.Fatalf("BEGIN: %v", err)
	}
	defer func() { _, _ = pinned.ExecContext(ctx, "ROLLBACK") }()

	fresh, err := s.db.Conn(ctx)
	if err != nil {
		t.Fatalf("second Conn: %v", err)
	}
	defer func() { _ = fresh.Close() }()

	want := []struct{ pragma, value string }{
		{"journal_mode", "wal"},
		{"busy_timeout", "5000"},
		{"synchronous", "1"}, // NORMAL
		{"temp_store", "2"},  // MEMORY
	}
	for _, w := range want {
		assertPragma(t, fresh, w.pragma, w.value)
		assertPragma(t, pinned, w.pragma, w.value)
	}
}

func TestConcurrentCallsDoNotRaceOrRunBusy(t *testing.T) {
	s := openStore(t)
	ctx := context.Background()

	const (
		workers   = 8
		perWorker = 20
	)
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range perWorker {
				path := fmt.Sprintf("prod/w%d/k%d", w, i)
				if err := s.Set(ctx, path, []byte{byte(w), byte(i)}, []byte{0x0a, 0x0b, 0x0c}); err != nil {
					errs <- fmt.Errorf("Set %s: %w", path, err)
					return
				}
				if _, _, err := s.Get(ctx, path); err != nil {
					errs <- fmt.Errorf("Get %s: %w", path, err)
					return
				}
				if _, err := s.List(ctx); err != nil {
					errs <- fmt.Errorf("List: %w", err)
					return
				}
				if i%5 == 0 {
					if err := s.Delete(ctx, path); err != nil {
						errs <- fmt.Errorf("Delete %s: %w", path, err)
						return
					}
				}
			}
			if _, _, err := s.Get(ctx, "prod/absent"); !errors.Is(err, ErrNotFound) {
				errs <- fmt.Errorf("Get(absent) = %v, want ErrNotFound", err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	live, deleted := 0, 0
	for w := range workers {
		for i := range perWorker {
			// i%5 == 0 → deleted in the worker loop.
			state := countRows(t, s, `SELECT coalesce(sum(deleted), 0) FROM local_secrets WHERE path = ?`, fmt.Sprintf("prod/w%d/k%d", w, i))
			if state == 1 {
				deleted++
			} else {
				live++
			}
		}
	}
	if deleted != workers*(perWorker/5) {
		t.Errorf("tombstoned rows = %d, want %d", deleted, workers*(perWorker/5))
	}
	recs, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(recs) != live {
		t.Fatalf("List len = %d, want %d live rows", len(recs), live)
	}
	for i := 1; i < len(recs); i++ {
		if recs[i-1].Path >= recs[i].Path {
			t.Fatalf("List not sorted: %q >= %q", recs[i-1].Path, recs[i].Path)
		}
	}
}

type column struct {
	typ     string
	notNull bool
	pk      bool
}

func tableColumns(t *testing.T, s *Store, table string) map[string]column {
	t.Helper()
	rows, err := s.db.QueryContext(context.Background(), `PRAGMA table_info(`+table+`)`)
	if err != nil {
		t.Fatalf("PRAGMA table_info(%s): %v", table, err)
	}
	defer func() { _ = rows.Close() }()

	cols := make(map[string]column)
	for rows.Next() {
		var (
			cid     int
			name    string
			typ     string
			notNull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &typ, &notNull, &dflt, &pk); err != nil {
			t.Fatalf("table_info scan: %v", err)
		}
		cols[name] = column{typ: typ, notNull: notNull != 0, pk: pk != 0}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("table_info rows: %v", err)
	}
	return cols
}

func assertPragma(t *testing.T, conn *sql.Conn, pragma, want string) {
	t.Helper()
	var got string
	if err := conn.QueryRowContext(context.Background(), `PRAGMA `+pragma).Scan(&got); err != nil {
		t.Fatalf("PRAGMA %s: %v", pragma, err)
	}
	if got != want {
		t.Errorf("PRAGMA %s = %q, want %q", pragma, got, want)
	}
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat(%s): %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != want {
		t.Errorf("%s mode = %o, want %o", filepath.Base(path), perm, want)
	}
}
