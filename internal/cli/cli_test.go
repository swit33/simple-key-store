// Package cli_test pins the M1 CLI contract (M1-T4) test-first, before the
// production `internal/cli` package exists.
//
// Sources of truth: secrets-spec.md §5 (offline cache, key recovery, the
// "never print a half export" rule, the 1 MiB value limit), §6 (command set,
// exit codes 0/1/2, stdout carries only values and exports, "no ANSI when
// stdout is a pipe", `eval "$(secrets export)"`) and §11 (CLI contract row);
// DECISIONS.md D2 (path alphabet → exit 1, missing key → exit 2), D11 (a
// missing machine.key is a hard error on reads and is never generated behind
// the caller's back) and D13/D21 (export mapping and limits).
//
// These tests are the API: `cli.Main(args []string, stdin io.Reader, stdout,
// stderr io.Writer) int`, called in-process against an XDG sandbox built from
// t.TempDir + t.Setenv. The real HOME, ~/.local/share/secrets and ~/.zshenv
// are never read or written, and every value is a synthetic marker (D13,
// agent-loop-guide.md §5.2).
package cli_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/swit33/simple-key-store/internal/cli"
	_ "modernc.org/sqlite"
)

// invocation is one in-process CLI run with both streams captured.
type invocation struct {
	args           []string
	code           int
	stdout, stderr string
}

// cliEnv is an isolated client environment: XDG_DATA_HOME, XDG_CONFIG_HOME and
// HOME all point inside one t.TempDir, so a test can never reach the real
// ~/.local/share/secrets or ~/.zshenv (guide §3.3).
type cliEnv struct {
	t        *testing.T
	root     string
	dataHome string
	confHome string
}

func newEnv(t *testing.T) *cliEnv {
	t.Helper()
	root := t.TempDir()
	e := &cliEnv{
		t:        t,
		root:     root,
		dataHome: filepath.Join(root, "xdg-data"),
		confHome: filepath.Join(root, "xdg-config"),
	}
	t.Setenv("HOME", root)
	t.Setenv("XDG_DATA_HOME", e.dataHome)
	t.Setenv("XDG_CONFIG_HOME", e.confHome)
	// §1 keeps SECRETS_NOCACHE=1 as the "no local cache" switch; a leaked value
	// from the ambient environment must not change what M1 stores.
	t.Setenv("SECRETS_NOCACHE", "")
	return e
}

// dataDir is the client data directory of §5: $XDG_DATA_HOME/secrets.
func (e *cliEnv) dataDir() string { return filepath.Join(e.dataHome, "secrets") }

// cacheDB is the encrypted cache of §5.
func (e *cliEnv) cacheDB() string { return filepath.Join(e.dataDir(), "cache.db") }

// machineKey is the 32-byte client key of §1/§5, stored next to the cache.
func (e *cliEnv) machineKey() string { return filepath.Join(e.dataDir(), "machine.key") }

// run invokes cli.Main with stdin as a pipe (never a TTY) and captures stdout
// and stderr separately.
func (e *cliEnv) run(stdin string, args ...string) invocation {
	e.t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.Main(args, strings.NewReader(stdin), &stdout, &stderr)
	return invocation{
		args:   args,
		code:   code,
		stdout: stdout.String(),
		stderr: stderr.String(),
	}
}

// mustRun fails the test unless the invocation succeeds with exit 0.
func (e *cliEnv) mustRun(stdin string, args ...string) invocation {
	e.t.Helper()
	inv := e.run(stdin, args...)
	if inv.code != 0 {
		e.t.Fatalf("Main(%q) = %d, want 0 (exit 0 is the §6 success code)\nstdout=%q\nstderr=%q",
			args, inv.code, snippet(inv.stdout), snippet(inv.stderr))
	}
	return inv
}

// seed stores value at path the only way §6 allows a value in: on stdin.
func (e *cliEnv) seed(path, value string) {
	e.t.Helper()
	e.mustRun(value, "set", path, "--stdin")
}

// lsLines returns the paths `ls` printed, one per line, tolerating only a
// missing final newline. It fails the test if ls does not exit 0 or emits ANSI.
func (e *cliEnv) lsLines() []string {
	e.t.Helper()
	inv := e.mustRun("", "ls")
	assertNoANSI(e.t, "ls stdout", inv.stdout)
	if inv.stdout == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(inv.stdout, "\n"), "\n")
}

// marker builds a synthetic value marker that is unique to the calling test.
// Real values from the user's ~/.zshenv must never enter the repository, a log
// or a fixture (D13, guide §5.2).
func marker(t *testing.T, kind string) string {
	t.Helper()
	name := strings.ToUpper(strings.NewReplacer("/", "-", " ", "-").Replace(t.Name()))
	return "SKS-FIXTURE-" + kind + "-" + name + "-MARKER"
}

// assertNoANSI is the §6/§7 contract: everything written to a pipe is bare
// text, no escape sequences.
func assertNoANSI(t *testing.T, label, s string) {
	t.Helper()
	if strings.ContainsRune(s, 0x1b) {
		t.Errorf("%s contains an ANSI escape sequence: %q", label, snippet(s))
	}
}

// assertNoLeak is the §1/§6 contract: no value ever reaches stderr.
func assertNoLeak(t *testing.T, label, s string, values ...string) {
	t.Helper()
	for _, v := range values {
		if v == "" {
			continue
		}
		if strings.Contains(s, v) {
			t.Errorf("%s leaks the value %q: %q", label, snippet(v), snippet(s))
		}
	}
}

// assertFailure enforces the §6 contract shared by every failing invocation:
// non-zero exit, empty stdout (a partially printed export or value is worse
// than an error), a diagnostic on stderr, no ANSI and no value on stderr.
func assertFailure(t *testing.T, inv invocation, values ...string) {
	t.Helper()
	if inv.code == 0 {
		t.Errorf("Main(%q) = 0, want a non-zero exit code", inv.args)
	}
	if inv.stdout != "" {
		t.Errorf("Main(%q) wrote %q to stdout, want nothing (§6: only values and exports)", inv.args, snippet(inv.stdout))
	}
	if strings.TrimSpace(inv.stderr) == "" {
		t.Errorf("Main(%q) failed with code %d but printed no diagnostic on stderr", inv.args, inv.code)
	}
	assertNoANSI(t, fmt.Sprintf("Main(%q) stderr", inv.args), inv.stderr)
	assertNoLeak(t, fmt.Sprintf("Main(%q) stderr", inv.args), inv.stderr, values...)
}

// assertNotFound pins the §6 exit code 2 ("нет такого ключа"): the path is
// legal but absent, so the missing value is reported on stderr and nothing
// reaches stdout.
func assertNotFound(t *testing.T, inv invocation) {
	t.Helper()
	if inv.code != 2 {
		t.Errorf("Main(%q) = %d, want 2 (missing key path, §6)", inv.args, inv.code)
	}
	if inv.stdout != "" {
		t.Errorf("Main(%q) wrote %q to stdout, want empty", inv.args, snippet(inv.stdout))
	}
	if strings.TrimSpace(inv.stderr) == "" {
		t.Errorf("Main(%q) = 2 without a diagnostic on stderr", inv.args)
	}
}

// snippet truncates long strings for failure messages, so a 1 MiB payload does
// not end up in the test log.
func snippet(s string) string {
	const max = 160
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("...(%d bytes)", len(s))
}

// cacheRow reads one row of local_secrets (§5) straight out of cache.db. The
// schema is part of the §5 contract; keeping the read in one helper keeps the
// coupling in one place.
func cacheRow(t *testing.T, dbPath, path string) (ciphertext, nonce []byte, deleted int) {
	t.Helper()
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("cache.db is missing: %v", err)
	}
	db, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatalf("open cache.db: %v", err)
	}
	defer func() { _ = db.Close() }()

	err = db.QueryRowContext(context.Background(),
		`SELECT ciphertext, nonce, deleted FROM local_secrets WHERE path = ?`, path).
		Scan(&ciphertext, &nonce, &deleted)
	if err != nil {
		t.Fatalf("read local_secrets row %q: %v", path, err)
	}
	return ciphertext, nonce, deleted
}

func TestSetGetExactBytes(t *testing.T) {
	e := newEnv(t)
	m := marker(t, "VALUE")
	cases := []struct {
		name, value string
	}{
		{"plain", m},
		{"trailing-newline", m + "\n"},
		{"leading-and-inner-newlines", "\n" + m + "\n\n"},
		{"crlf-and-tab", m + "\r\n\t" + m},
		{"shell-metacharacters", m + ` ' " \ $ ` + "`" + ` ; & | > < * ? ~ #`},
		{"utf8", "ключ-" + m + "-🔑"},
		{"empty", ""},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("fixture/roundtrip/%d", i)
			inv := e.mustRun(tc.value, "set", path, "--stdin")
			if inv.stdout != "" {
				t.Errorf("set wrote %q to stdout, want nothing (§6)", snippet(inv.stdout))
			}
			got := e.run("", "get", path)
			if got.code != 0 {
				t.Fatalf("get %q = %d, want 0 (stdout=%q stderr=%q)", path, got.code, snippet(got.stdout), snippet(got.stderr))
			}
			// Exact bytes: `get` adds no newline (§5) and preserves embedded
			// newlines (§6), so byte equality is the whole contract here.
			if got.stdout != tc.value {
				t.Errorf("get %q = %q, want %q", path, snippet(got.stdout), snippet(tc.value))
			}
			assertNoANSI(t, "get stdout", got.stdout)
		})
	}
}

func TestSetStdinPreservesRawBytes(t *testing.T) {
	e := newEnv(t)
	// NUL and high bytes: the value is an opaque blob, not text, so the cache
	// must round-trip it without truncating at the first NUL (§5).
	value := marker(t, "RAW") + "\x00\x01\xff\xfe\x00tail"
	e.seed("fixture/roundtrip/raw-bytes", value)
	got := e.mustRun("", "get", "fixture/roundtrip/raw-bytes")
	if got.stdout != value {
		t.Errorf("get of raw bytes = %q, want %q", snippet(got.stdout), snippet(value))
	}
}

func TestSetValueNeverFromArgv(t *testing.T) {
	e := newEnv(t)
	e.seed("fixture/present", marker(t, "PRESENT"))
	argvValue := marker(t, "ARGV")

	// §6: the value is never taken from argv (it would leak into `ps` and
	// shell history), so a second positional argument must be rejected rather
	// than stored — and must not be echoed back on stderr either.
	inv := e.run("", "set", "fixture/argv", argvValue)
	assertFailure(t, inv, argvValue)
	assertNotFound(t, e.run("", "get", "fixture/argv"))
	if slices.Contains(e.lsLines(), "fixture/argv") {
		t.Errorf("ls lists fixture/argv, but the argv value must never have been stored")
	}
}

func TestSetPromptRequiresTTY(t *testing.T) {
	e := newEnv(t)
	e.seed("fixture/present", marker(t, "PRESENT"))
	piped := marker(t, "PIPED")

	// The default and --prompt are interactive (prompt without echo, §6). With
	// stdin piped and stdout captured there is no terminal to prompt on, so the
	// command must fail instead of silently treating the pipe as the answer.
	// Pipes are what --stdin is for.
	for _, args := range [][]string{
		{"set", "fixture/prompt-default"},
		{"set", "fixture/prompt-flag", "--prompt"},
	} {
		inv := e.run(piped+"\n", args...)
		assertFailure(t, inv, piped)
		assertNotFound(t, e.run("", "get", args[1]))
	}
}

func TestSetValidatesPath(t *testing.T) {
	e := newEnv(t)
	e.seed("fixture/present", marker(t, "PRESENT"))

	invalid := []string{
		"",
		"UPPER",
		"Mixed/Case",
		"/leading",
		"trailing/",
		"double//slash",
		"dot/../segment",
		"..",
		"./x",
		"white space",
		"tab\tkey",
		"unicode-ключ",
		`slash\back`,
		"dash/../../escape",
		strings.Repeat("a", 513),
	}
	for _, path := range invalid {
		t.Run(fmt.Sprintf("%q", path), func(t *testing.T) {
			inv := e.run("", "set", path, "--stdin")
			// D2: an invalid path is a usage/validation error (exit 1), never a
			// silent write of whatever string was given.
			if inv.code != 1 {
				t.Errorf("set %q = %d, want 1 (invalid argument, D2)", path, inv.code)
			}
			if inv.stdout != "" {
				t.Errorf("set %q wrote %q to stdout, want nothing", path, snippet(inv.stdout))
			}
			if strings.TrimSpace(inv.stderr) == "" {
				t.Errorf("set %q failed without a diagnostic on stderr", path)
			}
			assertNoANSI(t, "stderr", inv.stderr)
			if got := e.run("", "get", path); got.code == 0 || got.stdout != "" {
				t.Errorf("get %q = %d stdout %q, want a non-zero exit and empty stdout (nothing was stored)",
					path, got.code, snippet(got.stdout))
			}
			if slices.Contains(e.lsLines(), path) {
				t.Errorf("ls lists the invalid path %q", path)
			}
		})
	}

	valid := []string{
		"a",
		"prod/pullmd/token",
		"a.b/c_d/e-1",
		"0/1/2",
		strings.Repeat("a", 512),
	}
	for i, path := range valid {
		t.Run("valid/"+fmt.Sprintf("%d", i), func(t *testing.T) {
			value := marker(t, fmt.Sprintf("VALID%d", i))
			e.seed(path, value)
			if got := e.mustRun("", "get", path); got.stdout != value {
				t.Errorf("get %q = %q, want %q", path, snippet(got.stdout), snippet(value))
			}
		})
	}
}

func TestSetStdinSizeLimit(t *testing.T) {
	e := newEnv(t)
	m := marker(t, "SIZE")
	e.seed("fixture/present", m)

	// §4: a value of at most 1 MiB is accepted.
	const limit = 1 << 20
	atLimit := strings.Repeat("A", limit)
	e.mustRun(atLimit, "set", "fixture/at-limit", "--stdin")
	if got := e.mustRun("", "get", "fixture/at-limit"); got.stdout != atLimit {
		t.Errorf("get of a 1 MiB value returned %d bytes, want %d", len(got.stdout), len(atLimit))
	}

	// One byte more is rejected before anything is written.
	over := strings.Repeat("B", limit+1)
	inv := e.run(over, "set", "fixture/over-limit", "--stdin")
	assertFailure(t, inv)
	if strings.Contains(inv.stderr, over[:64]) {
		t.Errorf("stderr echoes the rejected oversized value (§1)")
	}
	assertNotFound(t, e.run("", "get", "fixture/over-limit"))
	// The rejected write left no debris: an unrelated value is still readable
	// and the oversized path never showed up under ls.
	if got := e.mustRun("", "get", "fixture/present"); got.stdout != m {
		t.Errorf("an unrelated value changed after the rejected write: %q, want %q", snippet(got.stdout), snippet(m))
	}
	if slices.Contains(e.lsLines(), "fixture/over-limit") {
		t.Errorf("ls lists fixture/over-limit although the write was rejected")
	}
}

func TestGetMissingPathExit2(t *testing.T) {
	e := newEnv(t)
	e.seed("fixture/present", marker(t, "PRESENT"))

	assertNotFound(t, e.run("", "get", "fixture/absent"))
	assertNotFound(t, e.run("", "get", "fixture/absent/deep"))

	// An illegal path is a validation error (exit 1), never "not found".
	inv := e.run("", "get", "UPPER")
	if inv.code != 1 {
		t.Errorf("get UPPER = %d, want 1 (invalid path, D2)", inv.code)
	}
	if inv.stdout != "" {
		t.Errorf("get UPPER wrote %q to stdout, want nothing", snippet(inv.stdout))
	}
}

func TestFreshEnvironmentFailsClosed(t *testing.T) {
	e := newEnv(t)

	// Nothing exists yet: every command must fail closed. §5/§6 fix "non-zero
	// plus empty stdout" for this case; whether a missing *cache* reports 1
	// (config) or 2 (no such key) is not pinned by the spec, so only the
	// fail-closed part is asserted here (exit 2 for an absent path inside an
	// existing cache is pinned by TestGetMissingPathExit2).
	assertFailure(t, e.run("", "get", "fixture/absent"))
	assertFailure(t, e.run("", "export"))

	// D11: a read never generates machine.key. Only login (§5) and the first
	// local write may create it; generating one here would silently invalidate
	// an existing cache later.
	if _, err := os.Stat(e.machineKey()); !os.IsNotExist(err) {
		t.Errorf("a read created %s (stat err = %v); D11 allows generation only on login or the first local write",
			e.machineKey(), err)
	}
}

func TestLSSortedPathsOnly(t *testing.T) {
	e := newEnv(t)
	paths := []string{"prod/pullmd/token", "alpha", "prod/zeta", "deep/a/b/c", "beta.2"}
	values := map[string]string{}
	for i, p := range paths {
		values[p] = marker(t, fmt.Sprintf("LS%d", i))
		e.seed(p, values[p])
	}

	want := slices.Sorted(slices.Values(paths))
	got := e.lsLines()
	if !slices.Equal(got, want) {
		t.Errorf("ls = %q, want the sorted paths %q", got, want)
	}
	for _, p := range paths {
		if strings.Contains(strings.Join(got, "\n"), values[p]) {
			t.Errorf("ls printed the value of %q (only paths may be listed)", p)
		}
	}

	// A tombstoned path is gone from ls but not from the cache (§2).
	e.mustRun("", "rm", "alpha")
	want = slices.DeleteFunc(want, func(p string) bool { return p == "alpha" })
	if got := e.lsLines(); !slices.Equal(got, want) {
		t.Errorf("ls after rm = %q, want %q", got, want)
	}
}

func TestRMTombstonesPath(t *testing.T) {
	e := newEnv(t)
	const path = "fixture/rm/me"
	e.seed(path, marker(t, "RM"))

	inv := e.mustRun("", "rm", path)
	if inv.stdout != "" {
		t.Errorf("rm wrote %q to stdout, want nothing (§6)", snippet(inv.stdout))
	}
	assertNotFound(t, e.run("", "get", path))
	if slices.Contains(e.lsLines(), path) {
		t.Errorf("ls still lists the removed path %q", path)
	}

	// §2: removal is a tombstone, so it can reach other machines; the row is
	// not physically deleted.
	if _, _, deleted := cacheRow(t, e.cacheDB(), path); deleted != 1 {
		t.Errorf("local_secrets.deleted for the removed path = %d, want 1 (tombstone, §2)", deleted)
	}

	// A missing path is exit 2, whether it never existed or is already a
	// tombstone.
	assertNotFound(t, e.run("", "rm", "fixture/rm/never"))
	assertNotFound(t, e.run("", "rm", path))

	// An illegal path is exit 1 (D2).
	inv = e.run("", "rm", "UPPER")
	if inv.code != 1 {
		t.Errorf("rm UPPER = %d, want 1 (invalid path, D2)", inv.code)
	}
	if inv.stdout != "" {
		t.Errorf("rm UPPER wrote %q to stdout, want nothing", snippet(inv.stdout))
	}
}

func TestSetOverwritesSamePath(t *testing.T) {
	e := newEnv(t)
	first, second := marker(t, "FIRST"), marker(t, "SECOND")
	e.seed("fixture/overwrite", first)
	e.seed("fixture/overwrite", second)

	if got := e.mustRun("", "get", "fixture/overwrite"); got.stdout != second {
		t.Errorf("get after overwrite = %q, want %q", snippet(got.stdout), snippet(second))
	}
	if got := e.lsLines(); !slices.Equal(got, []string{"fixture/overwrite"}) {
		t.Errorf("ls = %q, want exactly one entry", got)
	}
	// set clears the tombstone: the path is live again.
	e.mustRun("", "rm", "fixture/overwrite")
	e.seed("fixture/overwrite", first)
	if got := e.mustRun("", "get", "fixture/overwrite"); got.stdout != first {
		t.Errorf("get after re-set = %q, want %q", snippet(got.stdout), snippet(first))
	}
}

func TestPipedOutputHasNoANSI(t *testing.T) {
	e := newEnv(t)
	m := marker(t, "ANSI")
	e.seed("sks/fixture/ansi", m)

	cases := []struct {
		stdin string
		args  []string
	}{
		{"", []string{"ls"}},
		{"", []string{"get", "sks/fixture/ansi"}},
		{"", []string{"get", "sks/fixture/absent"}},
		{"", []string{"export"}},
		{"", []string{"set", "sks/fixture/ansi"}}, // prompt without a TTY fails
		{m, []string{"set", "sks/fixture/ansi2", "--stdin"}},
		{"", []string{"rm", "sks/fixture/ansi2"}},
		{"", []string{"rm", "sks/fixture/ansi2"}}, // already tombstoned
	}
	for _, tc := range cases {
		inv := e.run(tc.stdin, tc.args...)
		assertNoANSI(t, fmt.Sprintf("Main(%q) stdout", tc.args), inv.stdout)
		assertNoANSI(t, fmt.Sprintf("Main(%q) stderr", tc.args), inv.stderr)
	}
}
