// Package cli implements the offline M1 command set of secrets-spec.md §6 --
// set, get, ls, rm, export -- over the machine-key-encrypted local cache of §5.
//
// Everything it does is local: no network, no login, no styling. The one
// entry point is Main, which takes its three streams as arguments so the tests
// can drive it in-process against an XDG sandbox.
package cli

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/swit33/simple-key-store/internal/config"
	"github.com/swit33/simple-key-store/internal/store"
)

// Exit codes of §6.
const (
	exitOK       = 0
	exitError    = 1 // validation, config, IO or crypto failure
	exitNotFound = 2 // no such path
)

// maxValue is the §4 limit on a single value (1 MiB).
const maxValue = 1 << 20

// noCacheVar is the paranoid switch of §1. M1 has no server to fall back to, so
// with it set every command that could read or write a local value refuses
// (D23) instead of quietly filling the cache the flag exists to prevent.
const noCacheVar = "SECRETS_NOCACHE"

// helpCommand is the name of cobra's built-in help command, which stays
// usable even when the value commands refuse (D23).
const helpCommand = "help"

// Main runs args as one `secrets` invocation and returns the §6 exit code.
// A fresh command tree is built per call, so no flag or argument state leaks
// between invocations. The framework itself prints nothing: on failure Main
// writes exactly one sanitized diagnostic to stderr.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if args == nil {
		// cobra falls back to os.Args[1:] for a nil slice, which would make a
		// bare Main(nil, ...) parse the caller's own flags.
		args = []string{}
	}
	root := newRoot(stdin, stdout, stderr)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		_, _ = fmt.Fprintln(stderr, diagnostic(err))
		return exitCode(err)
	}
	return exitOK
}

// newRoot builds the command tree of §6. Errors and usage are silenced: the
// caller (Main) owns the single stderr line, and a misuse must not spill a
// usage block into the channel `eval` reads.
func newRoot(stdin io.Reader, stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "secrets",
		Short:         "read and write secrets in the local encrypted cache",
		SilenceErrors: true,
		SilenceUsage:  true,
		// The single choke point for D23: it runs before any command body, so
		// no path is resolved and no cache or key is opened while the flag is
		// set. Cobra answers --help before this hook and the help command is
		// exempt below, so usage stays available.
		PersistentPreRunE: checkNoCache,
		RunE: func(*cobra.Command, []string) error {
			return errors.New("no command given, see `secrets --help`")
		},
	}
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	// §6 compatibility flag: M1 output is plain anyway and the styled UI lands
	// in M4 (D20), so --plain is accepted and changes nothing. It is persistent
	// so `secrets --plain get x` works as well as `secrets get x --plain`.
	root.PersistentFlags().Bool("plain", false, "never style output (the M1 default)")
	root.AddCommand(setCmd(), getCmd(), lsCmd(), rmCmd(), exportCmd())
	return root
}

// checkNoCache is the root PersistentPreRunE that enforces D23.
func checkNoCache(cmd *cobra.Command, _ []string) error {
	// `help` describes commands, it does not touch a value path.
	if cmd.Name() == helpCommand || os.Getenv(noCacheVar) == "" {
		return nil
	}
	return fmt.Errorf("%s is set and M1 has no server to fall back to: refusing to touch the local cache", noCacheVar)
}

// openCache loads the machine key and opens the local cache. Every read path
// (get/ls/rm/export) goes through it, so a cache whose key is missing or
// malformed fails closed before a row is touched. The key is only ever read
// here, never generated: D11 forbids repairing it behind the caller's back.
func openCache() (*store.Store, []byte, error) {
	paths, err := config.ResolvePaths()
	if err != nil {
		return nil, nil, err
	}
	key, err := config.LoadMachineKey(paths.MachineKey)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(paths.DataDir)
	if err != nil {
		return nil, nil, err
	}
	return st, key, nil
}

// openCacheForWrite opens the cache for `set`. It is the only place that may
// generate a machine key, and only while no cache exists yet (D11): silently
// creating a key next to an existing cache would make that cache unreadable.
func openCacheForWrite() (*store.Store, []byte, error) {
	paths, err := config.ResolvePaths()
	if err != nil {
		return nil, nil, err
	}
	key, err := keyForWrite(paths)
	if err != nil {
		return nil, nil, err
	}
	st, err := store.Open(paths.DataDir)
	if err != nil {
		return nil, nil, err
	}
	return st, key, nil
}

// keyForWrite picks the key policy for `set` from the presence of the cache.
func keyForWrite(paths config.Paths) ([]byte, error) {
	switch _, err := os.Stat(paths.CacheDB); {
	case err == nil:
		return config.LoadMachineKey(paths.MachineKey)
	case errors.Is(err, fs.ErrNotExist):
		return config.EnsureMachineKey(paths.MachineKey)
	default:
		return nil, fmt.Errorf("stat %s: %w", paths.CacheDB, err)
	}
}

// readValue reads a value from r, enforcing the §4 limit of 1 MiB. The limit
// is applied to the read itself (1 MiB + 1 byte), so an endless stream cannot
// exhaust memory, and the rejected bytes are never echoed into the error
// (§1: no value in stderr).
func readValue(r io.Reader) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(r, maxValue+1))
	if err != nil {
		return nil, fmt.Errorf("read value: %w", err)
	}
	if err := checkValueSize(value); err != nil {
		return nil, err
	}
	return value, nil
}

// checkValueSize enforces the §4 limit on a complete value. The rejected bytes
// are never echoed: the error names only the limit (§1).
func checkValueSize(value []byte) error {
	if len(value) > maxValue {
		return fmt.Errorf("value is larger than the %d byte limit", maxValue)
	}
	return nil
}

// promptValue reads a value from the terminal without echo (§6: the default
// way to set a value). A piped stdin is refused instead of being silently
// treated as the answer -- that is what --stdin is for -- so the prompt cannot
// end up in a pipeline by accident.
func promptValue(cmd *cobra.Command) ([]byte, error) {
	tty, ok := cmd.InOrStdin().(*os.File)
	if !ok || !term.IsTerminal(int(tty.Fd())) {
		return nil, errors.New("no terminal to prompt on: use `set <path> --stdin`")
	}
	if _, err := fmt.Fprint(cmd.ErrOrStderr(), "value: "); err != nil {
		return nil, err
	}
	value, err := term.ReadPassword(int(tty.Fd()))
	_, _ = fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return nil, fmt.Errorf("read value: %w", err)
	}
	// A terminal read has no natural bound, so §4's limit applies here too: a
	// paste must not smuggle an oversized value past the check --stdin gets.
	if err := checkValueSize(value); err != nil {
		return nil, fmt.Errorf("%w (use `set <path> --stdin` for large values)", err)
	}
	return value, nil
}

// diagnostic renders the single stderr line of a failed invocation. It never
// carries a value (§1), and control characters -- including a stray escape
// sequence smuggled in through a path or a flag -- become spaces so that one
// failure stays one line (§6).
func diagnostic(err error) string {
	message := err.Error()
	if errors.Is(err, config.ErrNoMachineKey) {
		message += " (recover with `secrets login --reset-key`)"
	}
	return "secrets: " + sanitize(message)
}

// sanitize replaces control characters with spaces.
func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}

// exitCode maps an error to the §6 exit code: only "no such key" is 2, every
// other failure is 1.
func exitCode(err error) int {
	if errors.Is(err, store.ErrNotFound) {
		return exitNotFound
	}
	return exitError
}
