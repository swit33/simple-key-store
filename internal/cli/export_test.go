// `export` contract for M1-T4: secrets-spec.md §4 (value limit), §5 (offline,
// fail closed: a partially printed export is silently lost keys), §6 (formats,
// the `eval "$(secrets export)"` line for .zshenv, POSIX-safe quoting, exit
// codes), §11 (`export | sh -n` clean, `eval "$(secrets export)"` yields the
// expected variables) and DECISIONS.md D13 (uppercase mapping, collision = hard
// error, empty cache = hard error) and D21 (only valid POSIX names; a leading
// digit is an error unless --prefix fixes it).
//
// Fixtures are synthetic: SKS_FIXTURE_* names and marker values only, never a
// value from the user's ~/.zshenv (D13, guide §5.2). `sh` is spawned only to
// prove quoting (guide §3.3).
package cli_test

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// fixtureEntry is one path → value pair of the synthetic .zshenv stand-in.
type fixtureEntry struct{ path, value string }

// exportFixture returns the synthetic stand-in for the user's .zshenv. The
// paths cover every mapping rule of D13 (`/`, `.`, `-` → `_`, digits and `_`
// kept as-is) without producing a name collision among themselves; the values
// cover quoting, newlines, metacharacters and the crypto-legal empty value.
func exportFixture(t *testing.T) []fixtureEntry {
	t.Helper()
	return []fixtureEntry{
		{"sks/fixture/token", marker(t, "TOKEN")},
		{"sks/fixture/password", marker(t, "PASSWORD")},
		{"sks/fixture/quote", marker(t, "QUOTE-PRE") + "'" + marker(t, "QUOTE-POST")},
		{"sks/fixture/multiline", marker(t, "LINE1") + "\n" + marker(t, "LINE2")},
		{"sks/fixture/metachars", "$HOME `id` \\ \" ; & | > < * ? ~ # " + marker(t, "META")},
		{"sks/fixture/empty", ""},
		{"sks.dotted.name", marker(t, "DOTTED")},
		{"sks-hyphen-name", marker(t, "HYPHEN")},
		{"sks_plain_string", marker(t, "PLAIN")},
		{"sks/fixture/nums1", marker(t, "NUMS1")},
	}
}

func seedFixture(t *testing.T, e *cliEnv, entries []fixtureEntry) {
	t.Helper()
	for _, entry := range entries {
		e.seed(entry.path, entry.value)
	}
}

// envName is the D13 mapping, implemented independently of the CLI: uppercase,
// with `/`, `.` and `-` replaced by `_`.
func envName(path string) string {
	return strings.ToUpper(strings.NewReplacer("/", "_", ".", "_", "-", "_").Replace(path))
}

// shQuote is the §6 quoting rule, implemented independently of the CLI: the
// value is single-quoted, and every embedded single quote is closed, escaped
// and reopened the POSIX way.
func shQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func splitLines(out string) []string {
	if out == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(out, "\n"), "\n")
}

// sameSet compares two line collections as sets, so the tests do not pin the
// order export happens to use (nothing in §6 fixes one).
func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := make(map[string]int, len(a))
	for _, s := range a {
		count[s]++
	}
	for _, s := range b {
		if count[s] == 0 {
			return false
		}
		count[s]--
	}
	return true
}

// shPath resolves the POSIX shell used for the quoting proofs.
func shPath(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("sh")
	if err != nil {
		t.Fatalf("POSIX sh not found: %v (§6/§11 prove the export contract with `sh -n` and a clean shell)", err)
	}
	return p
}

func shCmd(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(shPath(t), args...)
	// A minimal environment: a leaked value from the ambient environment must
	// not be able to make the round-trip comparison pass.
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	return cmd
}

// shNoSyntaxCheck runs `sh -n` over script, which §11 requires to be clean.
func shNoSyntaxCheck(t *testing.T, script string) {
	t.Helper()
	cmd := shCmd(t, "-n")
	cmd.Stdin = strings.NewReader(script)
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		t.Errorf("`sh -n` rejected the export (§6/§11): %v\n%s\nexport:\n%s", err, errBuf.String(), snippet(script))
	}
}

// shValue evaluates script in a clean POSIX shell and reads one variable back,
// proving that `eval "$(secrets export)"` yields exactly the stored value. The
// script goes in on stdin, not as a `-c` argument: a 1 MiB export would blow
// the per-argument limit of execve on Linux (MAX_ARG_STRLEN, 128 KiB).
func shValue(t *testing.T, script, name string) string {
	t.Helper()
	cmd := shCmd(t)
	cmd.Stdin = strings.NewReader(script + "\nprintf '%s' \"$" + name + "\"\n")
	var out, errBuf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	if err := cmd.Run(); err != nil {
		t.Fatalf("evaluating the export for %s failed: %v\n%s\nexport:\n%s", name, err, errBuf.String(), snippet(script))
	}
	return out.String()
}

func TestExportDefaultIsDotenvExport(t *testing.T) {
	e := newEnv(t)
	// A multi-line value makes one export line span two physical lines, which a
	// line-set comparison cannot express; that case is covered by the sh
	// round-trip in TestExportFormatsAreValidPOSIXShell instead.
	fx := slices.DeleteFunc(exportFixture(t), func(f fixtureEntry) bool {
		return strings.Contains(f.value, "\n")
	})
	seedFixture(t, e, fx)

	// §6: the .zshenv line is `eval "$(secrets export)"`, so the default format
	// must be dotenv-export: one `export NAME='value'` line per entry.
	inv := e.mustRun("", "export")
	got := splitLines(inv.stdout)
	want := make([]string, 0, len(fx))
	for _, f := range fx {
		want = append(want, "export "+envName(f.path)+"="+shQuote(f.value))
	}
	if !sameSet(got, want) {
		t.Errorf("export lines\n got: %q\nwant: %q", got, want)
	}
	assertNoANSI(t, "export stdout", inv.stdout)
	assertNoANSI(t, "export stderr", inv.stderr)

	// The output is stable: the same cache exports the same bytes.
	if again := e.mustRun("", "export"); again.stdout != inv.stdout {
		t.Errorf("export is not deterministic:\nfirst: %q\nsecond: %q", snippet(inv.stdout), snippet(again.stdout))
	}
}

func TestExportFormatsAreValidPOSIXShell(t *testing.T) {
	e := newEnv(t)
	fx := exportFixture(t)
	seedFixture(t, e, fx)

	for _, format := range []string{"dotenv", "dotenv-export", "shell"} {
		t.Run(format, func(t *testing.T) {
			inv := e.mustRun("", "export", "--format", format)
			assertNoANSI(t, "export stdout", inv.stdout)
			if strings.TrimSpace(inv.stdout) == "" {
				t.Fatalf("export --format %s printed nothing, want every live value", format)
			}
			shNoSyntaxCheck(t, inv.stdout)
			for _, f := range fx {
				name := envName(f.path)
				if !envNameRe.MatchString(name) {
					t.Fatalf("fixture name %q is not a POSIX name; fix the fixture, D21", name)
				}
				if got := shValue(t, inv.stdout, name); got != f.value {
					t.Errorf("--format %s: $%s = %q, want %q", format, name, snippet(got), snippet(f.value))
				}
			}
		})
	}
}

func TestExportDotenvExportEscapesSingleQuotes(t *testing.T) {
	e := newEnv(t)
	const path = "sks/fixture/quote"
	value := marker(t, "ESC-PRE") + "'" + marker(t, "ESC-POST")
	e.seed(path, value)

	// §6 pins the exact form: `export KEY='...'` with `'` escaped as `'\''`.
	want := "export " + envName(path) + "=" + shQuote(value)
	inv := e.mustRun("", "export")
	if got := splitLines(inv.stdout); !sameSet(got, []string{want}) {
		t.Errorf("export = %q, want exactly %q", got, want)
	}
	if got := shValue(t, inv.stdout, envName(path)); got != value {
		t.Errorf("eval of the escaped export gives %q, want %q", snippet(got), snippet(value))
	}
}

func TestExportMapping(t *testing.T) {
	e := newEnv(t)
	cases := []struct{ path, name string }{
		{"sks/fixture/token", "SKS_FIXTURE_TOKEN"},
		{"sks.dotted.name", "SKS_DOTTED_NAME"},
		{"sks-hyphen-name", "SKS_HYPHEN_NAME"},
		{"sks_plain_string", "SKS_PLAIN_STRING"},
		{"sks/fixture/nums1", "SKS_FIXTURE_NUMS1"},
	}
	value := marker(t, "MAP")
	for _, c := range cases {
		e.seed(c.path, value)
	}

	got := map[string]bool{}
	for _, line := range splitLines(e.mustRun("", "export").stdout) {
		name, _, ok := strings.Cut(strings.TrimPrefix(line, "export "), "=")
		if !ok {
			t.Fatalf("export line %q is not `export NAME=...`", line)
		}
		got[name] = true
	}
	for _, c := range cases {
		if !got[c.name] {
			t.Errorf("export --format dotenv-export did not emit %s for path %q (names: %v)", c.name, c.path, keys(got))
		}
	}
	if len(got) != len(cases) {
		t.Errorf("export emitted %d names for %d paths: %v", len(got), len(cases), keys(got))
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestExportNameCollisionFailsBeforeStdout(t *testing.T) {
	e := newEnv(t)
	const (
		first  = "sks/collide/one"
		second = "sks.collide.one" // same mapped name: SKS_COLLIDE_ONE
	)
	va, vb := marker(t, "COLLIDE-A"), marker(t, "COLLIDE-B")
	e.seed("sks/fixture/sibling", marker(t, "SIBLING"))
	e.seed(first, va)
	e.seed(second, vb)

	// D13: a collision is an error, not "last one wins" (that silently loses a
	// key). The buffering matters as much as the code: the valid sibling value
	// must not reach stdout before the failure is detected.
	inv := e.run("", "export")
	assertFailure(t, inv, va, vb)
	if !strings.Contains(inv.stderr, first) || !strings.Contains(inv.stderr, second) {
		t.Errorf("stderr must name both colliding paths, got %q", snippet(inv.stderr))
	}

	// json keeps the original paths as keys, so there is nothing to collide.
	jsonInv := e.mustRun("", "export", "--format", "json")
	var object map[string]string
	if err := json.Unmarshal([]byte(jsonInv.stdout), &object); err != nil {
		t.Fatalf("json export is not a flat object keyed by path: %v\noutput: %s", err, snippet(jsonInv.stdout))
	}
	for _, path := range []string{first, second} {
		if _, ok := object[path]; !ok {
			t.Errorf("json export dropped the original path key %q", path)
		}
	}
}

func TestExportLeadingDigitPathIsError(t *testing.T) {
	e := newEnv(t)
	e.seed("sks/fixture/valid", marker(t, "VALID"))
	e.seed("0fixture/key", marker(t, "DIGIT"))

	// D21: `0fixture/key` maps to 0FIXTURE_KEY, which is not a POSIX name;
	// export refuses (exit 1, empty stdout) instead of emitting something
	// `sh -n` would reject.
	inv := e.run("", "export")
	if inv.code != 1 {
		t.Errorf("export with a leading-digit path = %d, want 1 (D21)", inv.code)
	}
	if inv.stdout != "" {
		t.Errorf("export wrote %q to stdout before failing, want nothing (D13/§5: fail closed)", snippet(inv.stdout))
	}
	if !strings.Contains(inv.stderr, "0fixture/key") && !strings.Contains(inv.stderr, "0FIXTURE_KEY") {
		t.Errorf("stderr must name the offending path (or its mapped name), got %q", snippet(inv.stderr))
	}
	assertNoLeak(t, "stderr", inv.stderr, marker(t, "VALID"), marker(t, "DIGIT"))
}

func TestExportPrefix(t *testing.T) {
	e := newEnv(t)
	value := marker(t, "PREFIX")
	e.seed("0fixture/key", value) // rescued by the prefix below

	inv := e.mustRun("", "export", "--prefix", "sks_fix_")
	lines := splitLines(inv.stdout)
	if len(lines) != 1 {
		t.Fatalf("export with --prefix printed %q, want exactly one line", lines)
	}
	name, _, ok := strings.Cut(strings.TrimPrefix(lines[0], "export "), "=")
	if !ok {
		t.Fatalf("export line %q is not `export NAME=...`", lines[0])
	}
	if !envNameRe.MatchString(name) {
		// The name goes into a `sh` script below, so refuse anything else.
		t.Fatalf("prefixed name %q is not a valid POSIX name (D21)", name)
	}
	// D21 fixes that the prefix goes in front of the mapped name but not
	// whether it is upper-cased on the way, so both spellings are accepted.
	if name != "sks_fix_0FIXTURE_KEY" && name != "SKS_FIX_0FIXTURE_KEY" {
		t.Errorf("prefixed name = %q, want sks_fix_0FIXTURE_KEY (or SKS_FIX_0FIXTURE_KEY)", name)
	}
	shNoSyntaxCheck(t, inv.stdout)
	if got := shValue(t, inv.stdout, name); got != value {
		t.Errorf("eval of the prefixed export gives %q, want %q", snippet(got), snippet(value))
	}

	// Without the prefix the very same cache cannot be exported (D21).
	plain := e.run("", "export")
	if plain.code != 1 || plain.stdout != "" {
		t.Errorf("export without --prefix = %d stdout %q, want 1 and empty stdout", plain.code, snippet(plain.stdout))
	}

	// A prefix itself must match [A-Za-z_][A-Za-z0-9_]*.
	for _, prefix := range []string{"1bad", "bad-prefix", "bad prefix", "bad.prefix", ""} {
		t.Run("prefix/"+prefix, func(t *testing.T) {
			inv := e.run("", "export", "--prefix", prefix)
			if inv.code != 1 {
				t.Errorf("export --prefix %q = %d, want 1 (D21)", prefix, inv.code)
			}
			if inv.stdout != "" {
				t.Errorf("export --prefix %q wrote %q to stdout, want nothing", prefix, snippet(inv.stdout))
			}
			if strings.TrimSpace(inv.stderr) == "" {
				t.Errorf("export --prefix %q failed without a diagnostic on stderr", prefix)
			}
		})
	}
}

func TestExportJSONPreservesPathsAndValues(t *testing.T) {
	e := newEnv(t)
	fx := exportFixture(t)
	seedFixture(t, e, fx)

	inv := e.mustRun("", "export", "--format", "json")
	if !json.Valid([]byte(inv.stdout)) {
		t.Fatalf("--format json is not valid JSON: %s", snippet(inv.stdout))
	}
	var object map[string]string
	if err := json.Unmarshal([]byte(inv.stdout), &object); err != nil {
		t.Fatalf("json export is not a flat object keyed by path: %v\noutput: %s", err, snippet(inv.stdout))
	}
	if len(object) != len(fx) {
		t.Errorf("json export has %d keys, want %d", len(object), len(fx))
	}
	for _, f := range fx {
		got, ok := object[f.path]
		if !ok {
			t.Errorf("json export lost the original path key %q (D13: no mapping in json)", f.path)
			continue
		}
		if got != f.value {
			t.Errorf("json export %q = %q, want %q", f.path, snippet(got), snippet(f.value))
		}
	}
	assertNoANSI(t, "json stdout", inv.stdout)
}

func TestExportEmptyLiveCacheFailsClosed(t *testing.T) {
	t.Run("fresh environment", func(t *testing.T) {
		e := newEnv(t)
		// D13/§5: an empty export looks like success to `eval` and silently
		// drops every key, so it must fail with an empty stdout.
		assertFailure(t, e.run("", "export"))
		assertFailure(t, e.run("", "export", "--format", "json"))
	})

	t.Run("everything tombstoned", func(t *testing.T) {
		e := newEnv(t)
		m := marker(t, "TOMB")
		e.seed("sks/fixture/gone", m)
		e.mustRun("", "rm", "sks/fixture/gone")
		assertFailure(t, e.run("", "export"), m)
		assertFailure(t, e.run("", "export", "--format", "json"), m)
	})
}

func TestExportUnknownFormatIsInputError(t *testing.T) {
	e := newEnv(t)
	m := marker(t, "FORMAT")
	e.seed("sks/fixture/format", m)

	assertFailure(t, e.run("", "export", "--format", "yaml"), m)
}

// TestExportValueLimitMaterialisesBeforeStdout documents the §4 limit from the
// export side: the largest accepted value survives into the export intact.
func TestExportValueLimitMaterialisesBeforeStdout(t *testing.T) {
	e := newEnv(t)
	const limit = 1 << 20
	value := strings.Repeat("E", limit)
	e.seed("sks/fixture/big", value)

	inv := e.mustRun("", "export")
	want := "export SKS_FIXTURE_BIG=" + shQuote(value)
	if got := splitLines(inv.stdout); !sameSet(got, []string{want}) {
		t.Fatalf("export of a 1 MiB value does not match the expected line (got %d lines, %d bytes)",
			len(got), len(inv.stdout))
	}
	shNoSyntaxCheck(t, inv.stdout)
	if got := shValue(t, inv.stdout, "SKS_FIXTURE_BIG"); got != value {
		t.Fatalf("eval of a 1 MiB export gives %d bytes, want %d", len(got), len(value))
	}
}
