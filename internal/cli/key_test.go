// Machine-key lifecycle, permissions and "ciphertext only" proofs for M1-T4:
// secrets-spec.md §1 (the cache holds ciphertext and nothing else; stderr never
// carries a value), §5 (paths, permissions, first-write key generation), §11
// ("нет plaintext в кэше", "восстановление ключа", "права 600/700") and
// DECISIONS.md D11 (a missing or malformed key is a hard error on reads and is
// never repaired or regenerated behind the caller's back) and D15 (dirs 0700,
// cache.db and machine.key forced to 0600).
package cli_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func fileMode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func assertPerm(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	if got := fileMode(t, path); got != want {
		t.Errorf("%s has mode %03o, want %03o", path, got, want)
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Size()
}

// assertMarkerAbsent walks dir and fails if marker appears in any file, byte
// for byte. It covers the WAL and SHM siblings too: §1 forbids plaintext
// anywhere in the cache, not only in cache.db (the gate's
// scripts/no-plaintext-test.sh greps the same way, guide §3.3).
func assertMarkerAbsent(t *testing.T, dir string, marker string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(marker)) {
			t.Errorf("%s contains the plaintext marker %q (only ciphertext may be stored, §1)", path, marker)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
}

func TestFirstLocalSetCreatesLockedLayout(t *testing.T) {
	e := newEnv(t)
	e.seed("fixture/permissions", marker(t, "PERM"))

	// §5/D15: directory 0700, key and database 0600, set explicitly rather than
	// left to umask.
	assertPerm(t, e.dataDir(), 0o700)
	assertPerm(t, e.machineKey(), 0o600)
	assertPerm(t, e.cacheDB(), 0o600)
	if size := fileSize(t, e.machineKey()); size != 32 {
		t.Errorf("machine.key is %d bytes, want the 32-byte AES-256 key of §1", size)
	}
}

func TestCacheHoldsOnlyCiphertext(t *testing.T) {
	e := newEnv(t)
	const path = "fixture/plaintext/check"
	m := marker(t, "PLAINTEXT")
	e.seed(path, m)

	// §11: no plaintext anywhere the client writes — the whole sandbox, which
	// covers cache.db, its -wal/-shm siblings and any stray log or config file.
	assertMarkerAbsent(t, e.root, m)

	ciphertext, nonce, deleted := cacheRow(t, e.cacheDB(), path)
	if deleted != 0 {
		t.Errorf("local_secrets.deleted = %d, want 0 for a live value", deleted)
	}
	if len(ciphertext) == 0 {
		t.Error("stored ciphertext is empty; AES-GCM output is never empty, even for an empty value (§1)")
	}
	if len(nonce) != 12 {
		t.Errorf("stored nonce is %d bytes, want 12 (§1)", len(nonce))
	}
	if bytes.Contains(ciphertext, []byte(m)) || bytes.Contains(nonce, []byte(m)) {
		t.Error("the stored blob contains the plaintext marker (§1)")
	}
}

func TestEmptyValueIsStoredAsCiphertext(t *testing.T) {
	e := newEnv(t)
	const path = "fixture/plaintext/empty"
	e.seed(path, "")

	// The crypto layer allows an empty value; the store must reject an empty
	// blob, so a successful round-trip proves the ciphertext is non-empty.
	ciphertext, _, deleted := cacheRow(t, e.cacheDB(), path)
	if deleted != 0 || len(ciphertext) == 0 {
		t.Errorf("empty value stored with deleted=%d and %d ciphertext bytes, want a live non-empty blob",
			deleted, len(ciphertext))
	}
	if got := e.mustRun("", "get", path); got.stdout != "" {
		t.Errorf("get of an empty value = %q, want empty (the path exists, the value is empty)", snippet(got.stdout))
	}
}

func TestMissingMachineKeyIsHardError(t *testing.T) {
	e := newEnv(t)
	const path = "fixture/key/missing"
	m := marker(t, "KEYMISS")
	e.seed(path, m)

	if err := os.Remove(e.machineKey()); err != nil {
		t.Fatalf("remove machine.key: %v", err)
	}

	// D11: with a cache present and no key, reads fail hard — non-zero, empty
	// stdout, a diagnostic naming the recovery path, no value on stderr.
	assertFailure(t, e.run("", "get", path), m)
	assertFailure(t, e.run("", "export"), m)
	assertFailure(t, e.run("", "export", "--format", "json"), m)

	// And the key is never regenerated behind the caller's back: doing so would
	// make the existing cache silently unreadable.
	if _, err := os.Stat(e.machineKey()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("machine.key exists after a failed read (stat err = %v); D11 forbids regenerating it on a read", err)
	}
	if got := e.run("", "get", path); got.code == 0 || got.stdout != "" {
		t.Errorf("get = %d stdout %q, want a non-zero exit and empty stdout", got.code, snippet(got.stdout))
	}
}

func TestMalformedMachineKeyIsHardError(t *testing.T) {
	e := newEnv(t)
	const path = "fixture/key/malformed"
	m := marker(t, "KEYBAD")
	e.seed(path, m)

	bad := bytes.Repeat([]byte{0xAB}, 16) // wrong length: §1 requires 32 bytes
	if err := os.WriteFile(e.machineKey(), bad, 0o600); err != nil {
		t.Fatalf("overwrite machine.key: %v", err)
	}

	assertFailure(t, e.run("", "get", path), m)
	assertFailure(t, e.run("", "export"), m)

	// D11: a key of the wrong length is reported, never rewritten or "repaired".
	got, err := os.ReadFile(e.machineKey())
	if err != nil {
		t.Fatalf("read machine.key: %v", err)
	}
	if !bytes.Equal(got, bad) {
		t.Errorf("machine.key was modified after being rejected: %d bytes, want the original %d",
			len(got), len(bad))
	}
}
