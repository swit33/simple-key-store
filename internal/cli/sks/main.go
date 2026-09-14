package main

import (
	"os"
)

func main() {
	allArgs := os.Args

	Main(allArgs[1:])
}

func Main(args []string) int {
	if len(args) == 0 {
		//TODO: print usage
		usage()
		return 1
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "set":
		return cmdSet(rest)
	case "get":
		return cmdGet(rest)
	default:
		//TODO: print usage
		usage()
		return 1
	}
}

func cmdSet(args []string) int {
	os.Stdout.WriteString("set called\n")
	return 0
}

func cmdGet(args []string) int {
	os.Stdout.WriteString("set called\n")
	return 0
}

func usage() {
	os.Stderr.WriteString("sks: a simple key-value store\n\n")
	os.Stderr.WriteString("Usage: sks <command> [args...]\n")
	os.Stderr.WriteString("Commands:\n")
	os.Stderr.WriteString("  set <key> <value>\n")
	os.Stderr.WriteString("  get <key>\n")
}
