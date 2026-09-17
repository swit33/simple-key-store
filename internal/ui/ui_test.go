// Package ui_test pins the M1 pipe contract of the single output helper
// (M1-T5): secrets-spec.md §6 ("styles only when stdout is a TTY and NO_COLOR
// is unset, bare text otherwise", "get/export never write anything but the
// values", "no ANSI when piped") and §7 (`ui.Print(out io.Writer, styled,
// plain string)`, one helper so a command cannot forget the pipe case).
//
// These tests are the API: `ui.Print(out io.Writer, styled, plain string)
// error`. M1 only needs the non-TTY branch — every command in the pipeline
// writes into a pipe — so a real terminal is deliberately not faked here; the
// lipgloss styling itself lands in M4 (DECISIONS.md D20).
package ui_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/swit33/simple-key-store/internal/ui"
)

const (
	styledLine = "\x1b[1;31mSKS-UI-STYLED\x1b[0m"
	plainLine  = "SKS-UI-PLAIN"
)

// assertPlain is the whole point of the helper: a piped read gets the plain
// string, byte for byte, with no escape sequence anywhere.
func assertPlain(t *testing.T, label string, out bytes.Buffer) {
	t.Helper()
	if got := out.String(); got != plainLine {
		t.Errorf("%s wrote %q, want the plain string %q", label, got, plainLine)
	}
	if strings.ContainsRune(out.String(), 0x1b) {
		t.Errorf("%s contains an ANSI escape sequence: %q", label, out.String())
	}
	if strings.Contains(out.String(), styledLine) {
		t.Errorf("%s wrote the styled string into a pipe", label)
	}
}

func TestPrintToBufferEmitsPlain(t *testing.T) {
	var out bytes.Buffer
	if err := ui.Print(&out, styledLine, plainLine); err != nil {
		t.Fatalf("Print = %v, want nil", err)
	}
	assertPlain(t, "Print(bytes.Buffer)", out)
}

func TestPrintWithNoColorEmitsPlain(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var out bytes.Buffer
	if err := ui.Print(&out, styledLine, plainLine); err != nil {
		t.Fatalf("Print = %v, want nil", err)
	}
	assertPlain(t, "Print(NO_COLOR=1)", out)
}

func TestPrintToPipeEmitsPlain(t *testing.T) {
	// `secrets ... | grep` and `eval "$(secrets export)"` are the M1 use cases:
	// a real pipe is not a terminal, so no escape sequence may reach it.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if err := ui.Print(w, styledLine, plainLine); err != nil {
		_ = w.Close()
		_ = r.Close()
		t.Fatalf("Print = %v, want nil", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}
	piped, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatalf("read pipe: %v", err)
	}
	if got := string(piped); got != plainLine {
		t.Errorf("pipe received %q, want the plain string %q", got, plainLine)
	}
}

// failingWriter models a closed/broken stdout (`| head`, a full pipe): the
// caller has to learn about it, because §5 forbids treating a half-written
// export as success.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestPrintPropagatesWriteError(t *testing.T) {
	if err := ui.Print(failingWriter{}, styledLine, plainLine); err == nil {
		t.Error("Print = nil, want the writer's error")
	}
}
