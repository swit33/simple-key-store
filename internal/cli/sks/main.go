package main

import (
	"os"

	s "github.com/swit33/simple-key-store/internal/store"
)

func main() {
	allArgs := os.Args

	Main(allArgs[1:])
}

func Main(args []string) int {
	if len(args) == 0 {
		return usage()
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "set":
		return cmdSet(rest)
	case "get":
		return cmdGet(rest)
	default:
		return usage()
	}
}

func cmdSet(args []string) int {
	if len(args) != 1 {
		return usage()
	}

	store, err := s.Open(".")
	if err != nil {
		os.Stderr.WriteString("db not found\n")
		return 1
	}
	defer store.Close()

	return 0
}

func cmdGet(args []string) int {
	os.Stdout.WriteString("set called\n")
	return 0
}

func usage() int {
	os.Stderr.WriteString("sks: a simple key-value store\n\n")
	os.Stderr.WriteString("Usage: sks <command> [args...]\n")
	os.Stderr.WriteString("Commands:\n")
	os.Stderr.WriteString("  set <key> <value>\n")
	os.Stderr.WriteString("  get <key>\n")
	return 1
}
