// Review-fix round for M1-T4: these tests lock the failure modes that the
// first implementation leaves open. They are additive — topical coverage stays
// in cli_test.go / key_test.go / export_test.go — so the red set of this review
// round is readable in one place.
//
// Contracts under test: secrets-spec.md §1 (no silent local caching), §5 (fail
// closed, no half-printed export), §6 (exit codes; `--raw` on get and the
// global `--plain` are compatibility flags), §11, DECISIONS.md D11 (a key is
// never regenerated while a cache exists), D13/D21 (shell formats) and D23
// (SECRETS_NOCACHE fails closed in offline M1). D22 keeps `ls --tree/--long`
// out of M1, so those flags are deliberately not exercised here.
//
// Values are synthetic markers, every case runs in its own XDG sandbox, and no
// test spawns a process except the established `sh` quoting helpers.
package cli_test

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestSetFailsClosedWhenMachineKeyIsMissing pins D11 from the write side: a
// cache without its key is not a cache to "repair" by generating a new key —
// the old ciphertext would become permanently unreadable.
func TestSetFailsClosedWhenMachineKeyIsMissing(t *testing.T) {
	e := newEnv(t)
	const path = "fixture/key/present"
	old := marker(t, "OLD")
	e.seed(path, old)

	ctBefore, nonceBefore, _ := cacheRow(t, e.cacheDB(), path)
	if err := os.Remove(e.machineKey()); err != nil {
		t.Fatalf("remove machine.key: %v", err)
	}

	newValue := marker(t, "NEW")
	inv := e.run(newValue, "set", path, "--stdin")
	if inv.code != 1 {
		t.Errorf("set with the key deleted = %d, want 1 (D11: the write must fail, not re-key the cache)", inv.code)
	}
	if inv.stdout != "" {
		t.Errorf("set wrote %q to stdout, want nothing (§6)", snippet(inv.stdout))
	}
	if strings.TrimSpace(inv.stderr) == "" {
		t.Errorf("set failed without a diagnostic on stderr")
	}
	assertNoLeak(t, "stderr", inv.stderr, newValue)

	if _, err := os.Stat(e.machineKey()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("machine.key was recreated after a failed set (stat err = %v); D11 forbids it while a cache exists", err)
	}

	ctAfter, nonceAfter, deletedAfter := cacheRow(t, e.cacheDB(), path)
	if !bytes.Equal(ctBefore, ctAfter) || !bytes.Equal(nonceBefore, nonceAfter) || deletedAfter != 0 {
		t.Errorf("the existing row changed: ciphertext %d->%d bytes, nonce %d->%d bytes, deleted=%d, want it untouched",
			len(ctBefore), len(ctAfter), len(nonceBefore), len(nonceAfter), deletedAfter)
	}

	// The old value is still stored, it is merely unreadable without the key —
	// and a failed read must not spill it.
	failed := e.run("", "get", path)
	assertFailure(t, failed, old)
	assertNoLeak(t, "stderr", failed.stderr, old)
}

// TestExportRefusesValuesWithNUL pins §5 for values a shell cannot represent: a
// NUL inside a single-quoted assignment is silently truncated by the shell, so
// emitting it would lose the key without any error. The shell formats must
// refuse before the first byte reaches stdout.
func TestExportRefusesValuesWithNUL(t *testing.T) {
	e := newEnv(t)
	sibling := marker(t, "SIBLING")
	nulValue := marker(t, "NUL-PRE") + "\x00" + marker(t, "NUL-POST")
	e.seed("sks/fixture/sibling", sibling)
	e.seed("sks/fixture/nul", nulValue)

	for _, format := range []string{"dotenv", "dotenv-export", "shell"} {
		t.Run(format, func(t *testing.T) {
			inv := e.run("", "export", "--format", format)
			// assertFailure also proves the valid sibling never reached stdout.
			assertFailure(t, inv, sibling, nulValue)
			if inv.code != 1 {
				t.Errorf("export --format %s with a NUL value = %d, want 1 (§6: only a missing key is 2)", format, inv.code)
			}
		})
	}

	// The stored bytes themselves are legal: only the shell rendering is not.
	if got := e.mustRun("", "get", "sks/fixture/nul"); got.stdout != nulValue {
		t.Errorf("get of the NUL value = %q, want the exact bytes %q", snippet(got.stdout), snippet(nulValue))
	}
}

// TestExportJSONRefusesInvalidUTF8 pins §5 for the JSON format: encoding/json
// replaces invalid UTF-8 with U+FFFD instead of failing, so the export would
// hand back a different value than was stored. That is data loss disguised as
// success, and it must be refused before stdout.
func TestExportJSONRefusesInvalidUTF8(t *testing.T) {
	e := newEnv(t)
	sibling := marker(t, "JSON-SIBLING")
	badValue := marker(t, "BAD-UTF8") + "\xff\xfe"
	e.seed("sks/fixture/sibling", sibling)
	e.seed("sks/fixture/bad-utf8", badValue)

	inv := e.run("", "export", "--format", "json")
	assertFailure(t, inv, sibling)
	if inv.code != 1 {
		t.Errorf("json export with invalid UTF-8 = %d, want 1 (§6: only a missing key is 2)", inv.code)
	}
	if strings.Contains(inv.stdout, "\ufffd") {
		t.Errorf("json export replaced the invalid bytes with U+FFFD instead of failing: %q", snippet(inv.stdout))
	}

	// The raw bytes stay retrievable through `get`.
	if got := e.mustRun("", "get", "sks/fixture/bad-utf8"); got.stdout != badValue {
		t.Errorf("get of the invalid-UTF-8 value = %q, want the exact bytes %q", snippet(got.stdout), snippet(badValue))
	}
}

// TestNoCacheEnvFailsClosed pins D23: while M1 has no server, every path that
// could read or write a local value must refuse when SECRETS_NOCACHE is set,
// instead of quietly filling a cache the flag exists to prevent.
func TestNoCacheEnvFailsClosed(t *testing.T) {
	type invocationCase struct {
		name  string
		stdin string
		args  []string
	}

	t.Run("fresh environment", func(t *testing.T) {
		e := newEnv(t)
		t.Setenv("SECRETS_NOCACHE", "1")
		m := marker(t, "NOCACHE")

		for _, tc := range []invocationCase{
			{"set", m, []string{"set", "fixture/nocache", "--stdin"}},
			{"get", "", []string{"get", "fixture/nocache"}},
			{"ls", "", []string{"ls"}},
			{"rm", "", []string{"rm", "fixture/nocache"}},
			{"export", "", []string{"export"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				inv := e.run(tc.stdin, tc.args...)
				if inv.code != 1 {
					t.Errorf("Main(%q) = %d with SECRETS_NOCACHE set, want 1 (D23)", tc.args, inv.code)
				}
				if inv.stdout != "" {
					t.Errorf("Main(%q) wrote %q to stdout, want nothing (D23)", tc.args, snippet(inv.stdout))
				}
				if strings.TrimSpace(inv.stderr) == "" {
					t.Errorf("Main(%q) failed without a diagnostic on stderr", tc.args)
				}
				assertNoANSI(t, "stderr", inv.stderr)
				assertNoLeak(t, "stderr", inv.stderr, m)
			})
		}

		// D23: no local cache and no machine key may appear because of the flag.
		for _, path := range []string{e.cacheDB(), e.machineKey()} {
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("%s exists with SECRETS_NOCACHE set (stat err = %v), want no local cache/key", path, err)
			}
		}
		if entries, err := os.ReadDir(e.dataDir()); err == nil && len(entries) > 0 {
			t.Errorf("the data dir holds %d entries with SECRETS_NOCACHE set, want none", len(entries))
		}
	})

	t.Run("existing cache stays untouched", func(t *testing.T) {
		e := newEnv(t)
		const path = "fixture/nocache/present"
		old := marker(t, "NOCACHE-OLD")
		e.seed(path, old) // seeded with the flag off

		ctBefore, nonceBefore, _ := cacheRow(t, e.cacheDB(), path)
		t.Setenv("SECRETS_NOCACHE", "1")

		for _, tc := range []invocationCase{
			{"set", marker(t, "NOCACHE-NEW"), []string{"set", path, "--stdin"}},
			{"get", "", []string{"get", path}},
			{"ls", "", []string{"ls"}},
			{"rm", "", []string{"rm", path}},
			{"export", "", []string{"export"}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				inv := e.run(tc.stdin, tc.args...)
				if inv.code != 1 {
					t.Errorf("Main(%q) = %d with SECRETS_NOCACHE set, want 1 (D23)", tc.args, inv.code)
				}
				if inv.stdout != "" {
					t.Errorf("Main(%q) wrote %q to stdout, want nothing (D23)", tc.args, snippet(inv.stdout))
				}
				if strings.TrimSpace(inv.stderr) == "" {
					t.Errorf("Main(%q) failed without a diagnostic on stderr", tc.args)
				}
				assertNoLeak(t, "stderr", inv.stderr, old)
			})
		}

		// rm must not tombstone, set must not overwrite: failing closed means
		// the cache is left exactly as it was.
		ctAfter, nonceAfter, deletedAfter := cacheRow(t, e.cacheDB(), path)
		if !bytes.Equal(ctBefore, ctAfter) || !bytes.Equal(nonceBefore, nonceAfter) || deletedAfter != 0 {
			t.Errorf("the cache changed: ciphertext %d->%d bytes, nonce %d->%d bytes, deleted=%d, want it untouched",
				len(ctBefore), len(ctAfter), len(nonceBefore), len(nonceAfter), deletedAfter)
		}
	})
}

// TestCompatibilityFlagsAreNoOps pins the §6 flags that M1 accepts but does not
// need yet: `get --raw` and the global `--plain` must be accepted and must not
// change the output, so `eval "$(secrets export --plain)"` and a scripted
// `secrets get --raw` keep working when the styled UI lands in M4 (D20). Only
// the pre-subcommand position of --plain is pinned here (that is what "global"
// means); D22 keeps `ls --tree/--long` out of M1.
func TestCompatibilityFlagsAreNoOps(t *testing.T) {
	e := newEnv(t)
	const path = "sks/fixture/flags"
	value := marker(t, "FLAGS")
	e.seed(path, value)
	e.seed("sks/fixture/other", marker(t, "OTHER"))

	plainLS := e.mustRun("", "ls").stdout
	plainExport := e.mustRun("", "export").stdout

	cases := []struct {
		name string
		args []string
		want string
	}{
		{"get --raw", []string{"get", path, "--raw"}, value},
		{"get --plain", []string{"get", path, "--plain"}, value},
		{"--plain get", []string{"--plain", "get", path}, value},
		{"--plain ls", []string{"--plain", "ls"}, plainLS},
		{"--plain export", []string{"--plain", "export"}, plainExport},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inv := e.run("", tc.args...)
			if inv.code != 0 {
				t.Fatalf("Main(%q) = %d, want 0 (%s is a compatibility flag in M1)\nstderr=%q",
					tc.args, inv.code, tc.name, snippet(inv.stderr))
			}
			if inv.stdout != tc.want {
				t.Errorf("Main(%q) = %q, want the unchanged output %q", tc.args, snippet(inv.stdout), snippet(tc.want))
			}
			assertNoANSI(t, "stdout", inv.stdout)
		})
	}
}
