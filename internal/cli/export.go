package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"

	"github.com/swit33/simple-key-store/internal/crypto"
)

// Export formats of §6. `dotenv` and `dotenv-export` differ only in the
// `export` keyword; `shell` is the same POSIX-safe rendering as
// `dotenv-export`, so `eval "$(secrets export)"` and `sh -n` both hold.
const (
	formatDotenv       = "dotenv"
	formatDotenvExport = "dotenv-export"
	formatJSON         = "json"
	formatShell        = "shell"
)

// envNameRe is the POSIX identifier of D21, applied to every emitted name.
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// entry is one decrypted live row.
type entry struct {
	path  string
	value []byte
}

func exportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "print every live value as shell assignments, JSON or dotenv lines",
		Args:  cobra.NoArgs,
		RunE:  runExport,
	}
	cmd.Flags().String("format", formatDotenvExport,
		"output format: dotenv, dotenv-export, json or shell")
	cmd.Flags().String("prefix", "",
		"prefix for every environment variable name (validated, then uppercased with the name)")
	return cmd
}

func runExport(cmd *cobra.Command, _ []string) error {
	format, err := cmd.Flags().GetString("format")
	if err != nil {
		return err
	}
	if !validFormat(format) {
		return fmt.Errorf("unknown export format %q, want dotenv, dotenv-export, json or shell", format)
	}

	// D21: a prefix is validated as it was typed, before it is joined with a
	// mapped name. An empty --prefix is an error, not "no prefix".
	var prefix string
	if cmd.Flags().Changed("prefix") {
		if prefix, err = cmd.Flags().GetString("prefix"); err != nil {
			return err
		}
		if !envNameRe.MatchString(prefix) {
			return fmt.Errorf("--prefix %q must match %s", prefix, envNameRe.String())
		}
	}

	st, key, err := openCache()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	records, err := st.List(cmd.Context())
	if err != nil {
		return err
	}
	if len(records) == 0 {
		// D13/§5: an empty export looks like success to `eval` and silently
		// drops every key, so it is a failure with nothing on stdout.
		return errors.New("local cache holds no live value, refusing to export nothing")
	}

	// Decrypt every live row into memory first. §5 forbids a half-printed
	// export: stdout is touched only once the whole cache is readable and
	// validated, so a failure can never leave the shell holding half the keys.
	values := make([]entry, 0, len(records))
	for _, rec := range records {
		value, err := crypto.Open(key, crypto.LocalDomain, rec.Path, rec.Ciphertext, rec.Nonce)
		if err != nil {
			return fmt.Errorf("decrypt %q: %w", rec.Path, err)
		}
		values = append(values, entry{path: rec.Path, value: value})
	}

	if format == formatJSON {
		return writeJSON(cmd.OutOrStdout(), values)
	}
	return writeAssignments(cmd.OutOrStdout(), format, prefix, values)
}

// validFormat reports whether format is one of the four §6 formats.
func validFormat(format string) bool {
	switch format {
	case formatDotenv, formatDotenvExport, formatJSON, formatShell:
		return true
	default:
		return false
	}
}

// writeJSON renders the flat path → value object of D13. The original paths
// are the keys, so there is no mapping, no collision and no D21 name check;
// encoding/json sorts the keys, so the output is deterministic.
//
// A value that is not valid UTF-8 is refused first: encoding/json would replace
// the bad bytes with U+FFFD and hand back a different value than was stored,
// which is data loss disguised as a successful export (§5).
func writeJSON(out io.Writer, values []entry) error {
	object := make(map[string]string, len(values))
	for _, e := range values {
		if !utf8.Valid(e.value) {
			return fmt.Errorf("value of %q is not valid UTF-8 and cannot be exported as JSON", e.path)
		}
		object[e.path] = string(e.value)
	}
	blob, err := json.Marshal(object)
	if err != nil {
		return err
	}
	blob = append(blob, '\n')
	_, err = out.Write(blob)
	return err
}

// writeAssignments renders the shell formats. Every line is built, mapped and
// checked before the first byte reaches stdout: a name collision (D13), a name
// that is not a POSIX identifier (D21) or a value the shell cannot carry
// aborts the export with nothing printed.
func writeAssignments(out io.Writer, format, prefix string, values []entry) error {
	lines := make([]string, 0, len(values))
	owners := make(map[string]string, len(values))
	for _, e := range values {
		// A NUL makes the assignment unrepresentable: the shell truncates the
		// value at the NUL, so exporting it would silently lose the key (§5).
		if bytes.IndexByte(e.value, 0) >= 0 {
			return fmt.Errorf("value of %q contains a NUL byte, which a shell variable cannot carry", e.path)
		}
		// D13: uppercase, `/`, `.` and `-` become `_`; D13/D21: the prefix goes
		// in front of the mapped name and is uppercased with it.
		name := strings.ToUpper(prefix + envName(e.path))
		if !envNameRe.MatchString(name) {
			return fmt.Errorf("path %q maps to %q, which is not a valid environment name: set --prefix",
				e.path, name)
		}
		if prev, ok := owners[name]; ok {
			return fmt.Errorf("paths %q and %q both map to %s", prev, e.path, name)
		}
		owners[name] = e.path

		line := name + "=" + quote(string(e.value))
		if format != formatDotenv {
			line = "export " + line
		}
		lines = append(lines, line)
	}
	_, err := io.WriteString(out, joinLines(lines))
	return err
}

// envName is the D13 mapping: uppercase, with `/`, `.` and `-` replaced by `_`.
func envName(path string) string {
	return strings.ToUpper(strings.NewReplacer("/", "_", ".", "_", "-", "_").Replace(path))
}

// quote renders a value as a POSIX-safe single-quoted string: every embedded
// `'` is closed, escaped and reopened (§6), so `eval "$(secrets export)"` and
// `sh -n` both see exactly the stored bytes, including newlines and
// metacharacters.
func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// joinLines joins lines with newlines and terminates the last one.
func joinLines(lines []string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}
