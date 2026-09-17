package cli

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/swit33/simple-key-store/internal/crypto"
	"github.com/swit33/simple-key-store/internal/store"
	"github.com/swit33/simple-key-store/internal/ui"
)

// setCmd stores one value. The value never comes from argv (§6): it would leak
// into `ps` and into the shell history, so the only sources are --stdin and a
// no-echo terminal prompt.
func setCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set <path>",
		Short: "store a value read from stdin or from a no-echo prompt",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSet(cmd, args[0])
		},
	}
	cmd.Flags().Bool("stdin", false, "read the value from stdin")
	cmd.Flags().Bool("prompt", false, "prompt for the value on the terminal (the default)")
	return cmd
}

func runSet(cmd *cobra.Command, path string) error {
	// D2: an illegal path is a validation error before anything is read or
	// written, so `set UPPER` can never store whatever string it was given.
	if err := store.ValidatePath(path); err != nil {
		return err
	}
	fromStdin, err := cmd.Flags().GetBool("stdin")
	if err != nil {
		return err
	}
	fromPrompt, err := cmd.Flags().GetBool("prompt")
	if err != nil {
		return err
	}
	if fromStdin && fromPrompt {
		return errors.New("--stdin and --prompt are mutually exclusive")
	}

	var value []byte
	if fromStdin {
		value, err = readValue(cmd.InOrStdin())
	} else {
		value, err = promptValue(cmd)
	}
	if err != nil {
		return err
	}

	// The value is complete and legal before the key or the cache is touched:
	// a rejected write leaves neither a machine key nor an empty cache behind.
	st, key, err := openCacheForWrite()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ciphertext, nonce, err := crypto.Seal(key, crypto.LocalDomain, path, value)
	if err != nil {
		return err
	}
	// Only the ciphertext and its nonce reach the cache (§1).
	return st.Set(cmd.Context(), path, ciphertext, nonce)
}

// getCmd prints one value, byte for byte.
func getCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get <path>",
		Short: "print a value to stdout, byte for byte and without a newline",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGet(cmd, args[0])
		},
	}
	// §6 compatibility flag: `get` never styles its output, in M1 or later, so
	// --raw is accepted and changes nothing (D20 lands the styled UI).
	cmd.Flags().Bool("raw", false, "print the value without styling (always true for get)")
	return cmd
}

func runGet(cmd *cobra.Command, path string) error {
	st, key, err := openCache()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	ciphertext, nonce, err := st.Get(cmd.Context(), path)
	if err != nil {
		return err
	}
	value, err := crypto.Open(key, crypto.LocalDomain, path, ciphertext, nonce)
	if err != nil {
		return err
	}
	// §5: no added newline, no styling, no escaping -- the exact bytes, so a
	// caller can pipe or capture them as they were stored.
	_, err = cmd.OutOrStdout().Write(value)
	return err
}

// lsCmd lists the live paths of the cache.
func lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "list the live paths, one per line",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLS(cmd)
		},
	}
}

func runLS(cmd *cobra.Command) error {
	st, _, err := openCache()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	records, err := st.List(cmd.Context())
	if err != nil {
		return err
	}
	if len(records) == 0 {
		// An empty listing is not an error here: it is a plain "nothing".
		return nil
	}
	// Paths only, never values, and store.List already orders them by path, so
	// the output is deterministic. Sorted by §6.
	paths := make([]string, len(records))
	for i, rec := range records {
		paths[i] = rec.Path
	}
	text := joinLines(paths)
	return ui.Print(cmd.OutOrStdout(), text, text)
}

// rmCmd tombstones a path.
func rmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <path>",
		Short: "remove a path (a tombstone, so the removal can reach other machines)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRM(cmd, args[0])
		},
	}
}

func runRM(cmd *cobra.Command, path string) error {
	st, _, err := openCache()
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	// §2: the row is marked deleted, never dropped, so the deletion syncs.
	return st.Delete(cmd.Context(), path)
}
