// Command secrets is the client CLI of secrets-spec.md. It is a thin main over
// internal/cli (DECISIONS.md D10): argument parsing and the exit code only.
package main

import (
	"os"

	"github.com/swit33/simple-key-store/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
