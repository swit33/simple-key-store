package main

import (
	"fmt"
	"os"

	s "github.com/swit33/simple-key-store/internal/store"
)

func main() {
	os.Exit(Main(os.Args[1:]))
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
		fmt.Fprintln(os.Stderr, "db not found")
		return 1
	}
	defer func() { _ = store.Close() }()

	return 0
}

func cmdGet(args []string) int {
	fmt.Println("set called")
	return 0
}

func usage() int {
	fmt.Fprintln(os.Stderr, "sks: a simple key-value store")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Usage: sks <command> [args...]")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  set <key> <value>")
	fmt.Fprintln(os.Stderr, "  get <key>")
	return 1
}
