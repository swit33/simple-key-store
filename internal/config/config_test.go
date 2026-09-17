// Package config tests define the machine.key / XDG-path contract for M1-T1:
// secrets-spec.md §1, §5, §11 (paths, 0700/0600, no-plaintext neighbours),
// DECISIONS.md D11 (lifecycle: never auto-create on read; the CLI owns the
// policy of when ensure/reset is allowed) and D15 (dirs 0700, key file forced
// to 0600). Tests are written before the implementation and are the API.
// A relative XDG_DATA_HOME/XDG_CONFIG_HOME/HOME is rejected outright rather
// than resolved against the process working directory.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const keyLen = 32

func writeFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}

func filePerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return fi.Mode().Perm()
}

func isConstant(b []byte) bool {
	for _, c := range b {
		if c != b[0] {
			return false
		}
	}
	return true
}

func TestResolvePathsUsesXDG(t *testing.T) {
	root := t.TempDir()
	dataHome := filepath.Join(root, "data")
	configHome := filepath.Join(root, "config")
	t.Setenv("XDG_DATA_HOME", dataHome)
	t.Setenv("XDG_CONFIG_HOME", configHome)
	t.Setenv("HOME", filepath.Join(root, "home"))

	got, err := ResolvePaths()
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}

	dataDir := filepath.Join(dataHome, "secrets")
	configDir := filepath.Join(configHome, "secrets")
	want := Paths{
		DataDir:    dataDir,
		ConfigDir:  configDir,
		CacheDB:    filepath.Join(dataDir, "cache.db"),
		MachineKey: filepath.Join(dataDir, "machine.key"),
		ConfigFile: filepath.Join(configDir, "config.toml"),
	}
	if got != want {
		t.Errorf("ResolvePaths() = %+v, want %+v", got, want)
	}
}

func TestResolvePathsFallsBackToHOME(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	got, err := ResolvePaths()
	if err != nil {
		t.Fatalf("ResolvePaths: %v", err)
	}

	dataDir := filepath.Join(home, ".local", "share", "secrets")
	configDir := filepath.Join(home, ".config", "secrets")
	want := Paths{
		DataDir:    dataDir,
		ConfigDir:  configDir,
		CacheDB:    filepath.Join(dataDir, "cache.db"),
		MachineKey: filepath.Join(dataDir, "machine.key"),
		ConfigFile: filepath.Join(configDir, "config.toml"),
	}
	if got != want {
		t.Errorf("ResolvePaths() = %+v, want %+v", got, want)
	}
}

func TestResolvePathsErrorsWithoutUsableHome(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	_, err := ResolvePaths()
	if err == nil {
		t.Fatal("ResolvePaths() with no HOME/XDG = nil error, want error")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "home") {
		t.Errorf("error %q does not explain the missing home", err)
	}
}

func TestResolvePathsErrorsWhenOnlyDataHomeIsUsable(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("XDG_DATA_HOME", filepath.Join(t.TempDir(), "data"))
	t.Setenv("XDG_CONFIG_HOME", "")

	if _, err := ResolvePaths(); err == nil {
		t.Fatal("ResolvePaths() without a config home = nil error, want error")
	}
}

// TestResolvePathsRejectsRelativeLocations pins the no-relative-output rule:
// a relative location must fail loudly (and name the variable it came from)
// instead of silently anchoring client data to whatever CWD the CLI ran in.
func TestResolvePathsRejectsRelativeLocations(t *testing.T) {
	root := t.TempDir()
	absData := filepath.Join(root, "data")
	absConfig := filepath.Join(root, "config")
	absHome := filepath.Join(root, "home")

	tests := []struct {
		name    string
		data    string
		config  string
		home    string
		wantVar string
	}{
		{name: "relative XDG_DATA_HOME", data: "rel/data", config: absConfig, home: absHome, wantVar: "XDG_DATA_HOME"},
		{name: "relative XDG_CONFIG_HOME", data: absData, config: "rel/config", home: absHome, wantVar: "XDG_CONFIG_HOME"},
		{name: "relative HOME fallback", data: "", config: "", home: "relhome", wantVar: "HOME"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_DATA_HOME", tc.data)
			t.Setenv("XDG_CONFIG_HOME", tc.config)
			t.Setenv("HOME", tc.home)

			got, err := ResolvePaths()
			if err == nil {
				t.Fatalf("ResolvePaths() = %+v, nil error; a relative location must be rejected, not anchored to the working directory", got)
			}
			if got != (Paths{}) {
				t.Errorf("ResolvePaths() = %+v with error %v, want no paths alongside an error", got, err)
			}
			if msg := strings.ToLower(err.Error()); !strings.Contains(msg, strings.ToLower(tc.wantVar)) {
				t.Errorf("error %q does not name the offending %s variable", err, tc.wantVar)
			}
		})
	}
}

func TestEnsureDataDirCreatesMissingDirAt0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "a", "b", "secrets")

	if err := EnsureDataDir(dir); err != nil {
		t.Fatalf("EnsureDataDir: %v", err)
	}

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat %s: %v", dir, err)
	}
	if !fi.IsDir() {
		t.Fatalf("%s is not a directory (mode %v)", dir, fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %o, want 700", perm)
	}
}

func TestEnsureDataDirTightensExistingDirTo0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	writeLooseDir(t, dir)

	if err := EnsureDataDir(dir); err != nil {
		t.Fatalf("EnsureDataDir: %v", err)
	}
	if perm := filePerm(t, dir); perm != 0o700 {
		t.Errorf("dir perm = %o, want 700 (D15 forces the mode, not just umask)", perm)
	}
}

func writeLooseDir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	// Chmod is not masked by umask, so the precondition is exact.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod %s: %v", dir, err)
	}
}

func TestEnsureMachineKeyCreates32RandomBytesAt0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.key")

	key, err := EnsureMachineKey(path)
	if err != nil {
		t.Fatalf("EnsureMachineKey: %v", err)
	}

	if len(key) != keyLen {
		t.Fatalf("len(key) = %d, want %d", len(key), keyLen)
	}
	if isConstant(key) {
		t.Fatalf("key is a constant byte %#x, want crypto/rand output", key[0])
	}
	if !bytes.Equal(readFile(t, path), key) {
		t.Error("file content differs from the returned key")
	}
	if perm := filePerm(t, path); perm != 0o600 {
		t.Errorf("key perm = %o, want 600", perm)
	}
}

func TestEnsureMachineKeyGeneratesDistinctKeys(t *testing.T) {
	first, err := EnsureMachineKey(filepath.Join(t.TempDir(), "machine.key"))
	if err != nil {
		t.Fatalf("EnsureMachineKey: %v", err)
	}
	second, err := EnsureMachineKey(filepath.Join(t.TempDir(), "machine.key"))
	if err != nil {
		t.Fatalf("EnsureMachineKey: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Fatalf("two fresh keys are identical (%x), want crypto/rand output", first)
	}
}

func TestEnsureMachineKeyIsStableOnRepeat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.key")

	first, err := EnsureMachineKey(path)
	if err != nil {
		t.Fatalf("EnsureMachineKey: %v", err)
	}
	second, err := EnsureMachineKey(path)
	if err != nil {
		t.Fatalf("second EnsureMachineKey: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Error("second EnsureMachineKey returned a different key, want the existing one unchanged")
	}
	if !bytes.Equal(readFile(t, path), first) {
		t.Error("file content changed on repeat EnsureMachineKey")
	}
	if perm := filePerm(t, path); perm != 0o600 {
		t.Errorf("key perm = %o, want 600", perm)
	}
}

func TestEnsureMachineKeyTightensExistingFileTo0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.key")
	key, err := EnsureMachineKey(path)
	if err != nil {
		t.Fatalf("EnsureMachineKey: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	again, err := EnsureMachineKey(path)
	if err != nil {
		t.Fatalf("EnsureMachineKey: %v", err)
	}

	if !bytes.Equal(again, key) {
		t.Error("EnsureMachineKey rewrote an existing valid key")
	}
	if perm := filePerm(t, path); perm != 0o600 {
		t.Errorf("key perm = %o, want 600 (D15 forces the mode on an existing key)", perm)
	}
}

// TestEnsureMachineKeyTightensContainingDirTo0700 covers both entry points into
// writeMachineKey: a fresh key and an already-valid key whose directory was
// widened after the fact. MkdirAll alone leaves an existing directory alone, so
// the mode must be forced explicitly (D15).
func TestEnsureMachineKeyTightensContainingDirTo0700(t *testing.T) {
	tests := []struct {
		name string
		seed bool
	}{
		{name: "generates_key_in_loose_dir"},
		{name: "existing_key_in_loose_dir", seed: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "secrets")
			writeLooseDir(t, dir)
			path := filepath.Join(dir, "machine.key")
			if tc.seed {
				writeFile(t, path, bytes.Repeat([]byte{0x11}, keyLen), 0o600)
			}

			if _, err := EnsureMachineKey(path); err != nil {
				t.Fatalf("EnsureMachineKey: %v", err)
			}
			if perm := filePerm(t, dir); perm != 0o700 {
				t.Errorf("dir perm = %o, want 700 (D15 forces the directory holding the key, not only the file)", perm)
			}
		})
	}
}

func TestEnsureMachineKeyRejectsMalformedLength(t *testing.T) {
	for _, n := range []int{0, keyLen - 1, keyLen + 1} {
		t.Run(fmt.Sprintf("%d_bytes", n), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "machine.key")
			malformed := bytes.Repeat([]byte{7}, n)
			writeFile(t, path, malformed, 0o600)

			if _, err := EnsureMachineKey(path); err == nil {
				t.Fatalf("EnsureMachineKey with a %d-byte key = nil error, want error", n)
			}
			if got := readFile(t, path); !bytes.Equal(got, malformed) {
				t.Errorf("malformed key was rewritten: %x -> %x", malformed, got)
			}
		})
	}
}

func TestLoadMachineKeyMissingReturnsErrNoMachineKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.key")

	_, err := LoadMachineKey(path)
	if !errors.Is(err, ErrNoMachineKey) {
		t.Fatalf("LoadMachineKey() error = %v, want ErrNoMachineKey", err)
	}
	if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("LoadMachineKey left a file at %s (stat err = %v); D11 forbids silent auto-create on read", path, statErr)
	}
}

func TestLoadMachineKeyReturnsStoredKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.key")
	stored := bytes.Repeat([]byte{0xAB}, keyLen)
	writeFile(t, path, stored, 0o600)

	key, err := LoadMachineKey(path)
	if err != nil {
		t.Fatalf("LoadMachineKey: %v", err)
	}
	if !bytes.Equal(key, stored) {
		t.Errorf("LoadMachineKey() = %x, want %x", key, stored)
	}
}

func TestLoadMachineKeyRejectsMalformedLength(t *testing.T) {
	for _, n := range []int{0, keyLen - 1, keyLen + 1} {
		t.Run(fmt.Sprintf("%d_bytes", n), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "machine.key")
			writeFile(t, path, bytes.Repeat([]byte{7}, n), 0o600)

			_, err := LoadMachineKey(path)
			if err == nil {
				t.Fatalf("LoadMachineKey with a %d-byte key = nil error, want error", n)
			}
			// A malformed file is present-but-corrupt, not absent.
			if n != 0 && errors.Is(err, ErrNoMachineKey) {
				t.Errorf("LoadMachineKey with a %d-byte key = ErrNoMachineKey, want a corruption error", n)
			}
		})
	}
}

func TestResetMachineKeyRotatesToADifferentKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "machine.key")
	old, err := EnsureMachineKey(path)
	if err != nil {
		t.Fatalf("EnsureMachineKey: %v", err)
	}

	next, err := ResetMachineKey(path)
	if err != nil {
		t.Fatalf("ResetMachineKey: %v", err)
	}

	if len(next) != keyLen {
		t.Fatalf("len(key) = %d, want %d", len(next), keyLen)
	}
	// Full 32-byte comparison: a partial match would mean a non-random generator.
	if bytes.Equal(next, old) {
		t.Fatalf("ResetMachineKey kept the old key %x", old)
	}

	onDisk := readFile(t, path)
	if !bytes.Equal(onDisk, next) {
		t.Errorf("file = %x, want the returned key %x", onDisk, next)
	}
	if bytes.Equal(onDisk, old) {
		t.Error("file still holds the old key")
	}
	if perm := filePerm(t, path); perm != 0o600 {
		t.Errorf("key perm = %o, want 600", perm)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "machine.key" {
		t.Errorf("directory contains %d entries (%v), want only the key file: an atomic replace must not leave temp files behind", len(entries), entries)
	}
}

func TestResetMachineKeyTightensContainingDirTo0700(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "secrets")
	writeLooseDir(t, dir)
	path := filepath.Join(dir, "machine.key")
	writeFile(t, path, bytes.Repeat([]byte{0x22}, keyLen), 0o600)

	if _, err := ResetMachineKey(path); err != nil {
		t.Fatalf("ResetMachineKey: %v", err)
	}
	if perm := filePerm(t, dir); perm != 0o700 {
		t.Errorf("dir perm = %o, want 700 (D15 forces the directory holding the key, not only the file)", perm)
	}
}

// TestResetMachineKeyRenameFailureLeavesNoTempFile drives the atomic-replace
// failure path: a non-empty directory at the target path makes rename fail
// (EISDIR/ENOTEMPTY on Linux). The temp file must be removed and the target
// directory untouched, otherwise every failed rotate leaks key material into
// the data dir.
func TestResetMachineKeyRenameFailureLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "machine.key")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", target, err)
	}
	keep := filepath.Join(target, "keep")
	writeFile(t, keep, []byte("keep"), 0o600)

	if _, err := ResetMachineKey(target); err == nil {
		t.Fatal("ResetMachineKey onto a non-empty directory = nil error, want a rename error")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir %s: %v", dir, err)
	}
	if len(entries) != 1 || entries[0].Name() != "machine.key" {
		t.Errorf("after a failed rename %s holds %d entries (%v), want only machine.key: no .machine.key-* temp may survive", dir, len(entries), entries)
	}
	if fi, err := os.Stat(target); err != nil {
		t.Errorf("target dir %s vanished: %v", target, err)
	} else if !fi.IsDir() {
		t.Errorf("target %s is no longer a directory (mode %v)", target, fi.Mode())
	}
	if got := readFile(t, keep); string(got) != "keep" {
		t.Errorf("target dir content = %q, want %q: a failed reset must not touch it", got, "keep")
	}
}

func TestResetMachineKeyCreatesKeyWhenAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "machine.key")

	key, err := ResetMachineKey(path)
	if err != nil {
		t.Fatalf("ResetMachineKey: %v", err)
	}

	if len(key) != keyLen {
		t.Fatalf("len(key) = %d, want %d", len(key), keyLen)
	}
	if !bytes.Equal(readFile(t, path), key) {
		t.Error("file content differs from the returned key")
	}
	if perm := filePerm(t, path); perm != 0o600 {
		t.Errorf("key perm = %o, want 600", perm)
	}
}
