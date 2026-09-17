// Package config resolves the client's XDG locations and owns the machine key
// lifecycle (secrets-spec.md §5, DECISIONS.md D11/D15). It deliberately does
// not create anything on read: the CLI decides when a key may be generated.
package config

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	// machineKeyLen is the AES-256 key size required by spec §1.
	machineKeyLen = 32
	// dirPerm is the mode forced on every directory holding client data (D15).
	dirPerm = 0o700
	// keyPerm is the mode forced on machine.key (D15).
	keyPerm = 0o600
)

// ErrNoMachineKey reports that machine.key does not exist. Reads fail with it
// instead of generating a key (D11): creating one behind the caller's back
// would silently make an existing cache unreadable.
var ErrNoMachineKey = errors.New("machine key not found")

// Paths are the client's on-disk locations (spec §5). Resolving them is pure:
// none of the files or directories has to exist yet.
type Paths struct {
	DataDir    string
	ConfigDir  string
	CacheDB    string
	MachineKey string
	ConfigFile string
}

// ResolvePaths derives the client paths from $XDG_DATA_HOME and
// $XDG_CONFIG_HOME, falling back to $HOME/.local/share and $HOME/.config. A
// location must be absolute: a non-empty relative value is rejected (naming
// the offending variable) instead of being silently anchored to whatever
// working directory the CLI happened to run in.
func ResolvePaths() (Paths, error) {
	dataHome := os.Getenv("XDG_DATA_HOME")
	configHome := os.Getenv("XDG_CONFIG_HOME")
	if dataHome != "" && !filepath.IsAbs(dataHome) {
		return Paths{}, fmt.Errorf("XDG_DATA_HOME must be an absolute path, got %q", dataHome)
	}
	if configHome != "" && !filepath.IsAbs(configHome) {
		return Paths{}, fmt.Errorf("XDG_CONFIG_HOME must be an absolute path, got %q", configHome)
	}
	if dataHome == "" || configHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return Paths{}, fmt.Errorf("resolve secrets paths: %w", err)
		}
		if !filepath.IsAbs(home) {
			return Paths{}, fmt.Errorf("HOME must be an absolute path, got %q", home)
		}
		if dataHome == "" {
			dataHome = filepath.Join(home, ".local", "share")
		}
		if configHome == "" {
			configHome = filepath.Join(home, ".config")
		}
	}

	dataDir := filepath.Join(dataHome, "secrets")
	configDir := filepath.Join(configHome, "secrets")
	return Paths{
		DataDir:    dataDir,
		ConfigDir:  configDir,
		CacheDB:    filepath.Join(dataDir, "cache.db"),
		MachineKey: filepath.Join(dataDir, "machine.key"),
		ConfigFile: filepath.Join(configDir, "config.toml"),
	}, nil
}

// EnsureDataDir creates dir (and any missing parents) and forces it to 0700.
// The mode is set explicitly rather than left to umask, and parents are
// created with the same mode, so nothing is ever widened (D15).
func EnsureDataDir(dir string) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create data dir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		return fmt.Errorf("tighten data dir %s: %w", dir, err)
	}
	return nil
}

// LoadMachineKey reads the 32-byte machine key. It never creates, repairs or
// rotates the file: a missing key returns ErrNoMachineKey, a key of the wrong
// length is a corruption error naming the file.
func LoadMachineKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNoMachineKey, path)
		}
		return nil, fmt.Errorf("read machine key %s: %w", path, err)
	}
	if len(key) != machineKeyLen {
		return nil, fmt.Errorf("machine key %s is %d bytes, want %d", path, len(key), machineKeyLen)
	}
	return key, nil
}

// EnsureMachineKey returns the stored key, tightening its mode to 0600, and
// generates a fresh one (atomically, 0600) only when the file is absent. A
// file of the wrong length is reported as an error, never rewritten: silently
// replacing a key would lose every value encrypted with it (D11).
func EnsureMachineKey(path string) ([]byte, error) {
	key, err := LoadMachineKey(path)
	if err == nil {
		if err := ensureKeyDir(path); err != nil {
			return nil, err
		}
		if err := os.Chmod(path, keyPerm); err != nil {
			return nil, fmt.Errorf("tighten machine key %s: %w", path, err)
		}
		return key, nil
	}
	if !errors.Is(err, ErrNoMachineKey) {
		return nil, err
	}
	return writeMachineKey(path)
}

// ResetMachineKey rotates machine.key: it always writes a fresh key (0600) and
// returns it, forcing the containing directory to 0700 like EnsureMachineKey.
// The old key is unrecoverable, so any cache encrypted with it must be
// re-fetched by the caller (spec §5, `login --reset-key`).
func ResetMachineKey(path string) ([]byte, error) {
	return writeMachineKey(path)
}

// ensureKeyDir forces the directory holding a key file to 0700 through
// EnsureDataDir, so creation and mode-tightening live in one place (D15).
// A key path without an absolute directory is refused rather than resolved
// against the working directory.
func ensureKeyDir(path string) error {
	dir := filepath.Dir(path)
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("machine key path %q must be absolute", path)
	}
	return EnsureDataDir(dir)
}

// writeMachineKey generates a key and installs it atomically: a temp file in
// the same directory (so the rename cannot cross filesystems), 0600 from the
// first byte, fsync, then rename. Every failure path removes the temp file, so
// the directory never accumulates leftovers (D15).
func writeMachineKey(path string) ([]byte, error) {
	key := make([]byte, machineKeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate machine key: %w", err)
	}

	dir := filepath.Dir(path)
	if err := ensureKeyDir(path); err != nil {
		return nil, err
	}

	f, err := os.CreateTemp(dir, ".machine.key-*")
	if err != nil {
		return nil, fmt.Errorf("create temp machine key in %s: %w", dir, err)
	}
	tmp := f.Name()
	fail := func(cause error) ([]byte, error) {
		_ = f.Close() // no-op when already closed
		_ = os.Remove(tmp)
		return nil, cause
	}

	if err := f.Chmod(keyPerm); err != nil {
		return fail(fmt.Errorf("chmod %s: %w", tmp, err))
	}
	if _, err := f.Write(key); err != nil {
		return fail(fmt.Errorf("write %s: %w", tmp, err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("sync %s: %w", tmp, err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return nil, fmt.Errorf("replace machine key %s: %w", path, err)
	}
	return key, nil
}
