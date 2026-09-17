// Package ui owns the single output helper of secrets-spec.md §7: one function
// decides between the styled and the plain rendering, so no command can forget
// the "no ANSI when stdout is a pipe" rule of §6.
//
// M1 carries no styles yet (lipgloss lands in M4, DECISIONS.md D20), but the
// TTY branch is wired now so a caller can pass a styled string without leaking
// escape sequences into `secrets ... | grep` or `eval "$(secrets export)"`.
package ui

import (
	"io"
	"os"

	"golang.org/x/term"
)

// Print writes text to out, choosing the styled or the plain rendering. The
// styled form is used only when out is a real terminal; a pipe, a regular
// file, an in-memory buffer or a set NO_COLOR all select plain (§6). The
// writer's error is returned unchanged: a half-written export must never look
// like success (§5).
func Print(out io.Writer, styled, plain string) error {
	text := plain
	if !noColor() && isTerminal(out) {
		text = styled
	}
	_, err := io.WriteString(out, text)
	return err
}

// noColor reports whether NO_COLOR is set to a non-empty value. It is read on
// every call, so a later flag or a test can flip it without global state.
func noColor() bool {
	return os.Getenv("NO_COLOR") != ""
}

// isTerminal reports whether out is a character device we may style for. Only
// *os.File carries a file descriptor, so every other writer is plain by
// construction.
func isTerminal(out io.Writer) bool {
	f, ok := out.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}
