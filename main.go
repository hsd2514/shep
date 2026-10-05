// shep is an SSH host manager with two faces over one ~/.ssh/config:
// plain non-interactive commands with JSON output for coding agents, and
// human-only commands for editing hosts and the rules agents run under.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

const version = "0.1.0"

const (
	exitError    = 1
	exitUsage    = 2
	exitDenied   = 101
	exitNotFound = 102
	exitTimeout  = 103
)

var (
	stdout  io.Writer = os.Stdout
	stderr  io.Writer = os.Stderr
	jsonOut bool
)

// cliError carries the exit code and, for agents, a machine-readable kind.
// A silent error only sets the exit code; its output was already written.
type cliError struct {
	code   int
	kind   string
	msg    string
	hint   string
	silent bool
}

func (e *cliError) Error() string { return e.msg }

var commands map[string]func([]string) error

func init() {
	commands = map[string]func([]string) error{
		"list":    cmdList,
		"ls":      cmdList,
		"show":    cmdShow,
		"run":     cmdRun,
		"check":   cmdCheck,
		"log":     cmdLog,
		"guide":   cmdGuide,
		"add":     cmdAdd,
		"set":     cmdSet,
		"rm":      cmdRm,
		"scope":   cmdScope,
		"connect": cmdConnect,
	}
}

const usageText = `shep - SSH hosts for humans and agents

For agents (never prompt, add --json for machine-readable output):
  shep list [--tag T]             hosts visible in the current scope
  shep show <host>                details, policy and notes for one host
  shep run <host> <command>       run a command, subject to the host policy
  shep check <host>               test that a host is reachable without prompts
  shep log [-n N] [--host H]      recent commands run through shep
  shep guide                      instructions to paste into CLAUDE.md / AGENTS.md

For humans (need an interactive terminal):
  shep add <name> --host <addr> [--user U] [--port P] [--key FILE]
                  [--tags a,b] [--policy P] [--note TEXT]
  shep set <host> [--policy P] [--tags a,b] [--note TEXT]
                  [--allow "cmd prefix"]... [--clear-allow]
  shep rm <host> [--yes]
  shep scope [name|all]           show or set the default scope
  shep connect <host>             open an interactive SSH session

Policies: blocked (agents cannot run anything), readonly (allow-listed
read-only commands, the default), full (any command).

Scope: set SHEP_SCOPE=work to limit shep to hosts tagged "work".
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	jsonOut = false
	if len(args) == 0 {
		fmt.Fprint(stdout, usageText)
		return 0
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usageText)
		return 0
	case "version", "--version":
		fmt.Fprintln(stdout, "shep "+version)
		return 0
	}
	fn, ok := commands[args[0]]
	if !ok {
		fmt.Fprintf(stderr, "shep: unknown command %q\n\n%s", args[0], usageText)
		return exitUsage
	}
	return report(fn(args[1:]))
}

func report(err error) int {
	if err == nil {
		return 0
	}
	var ce *cliError
	if !errors.As(err, &ce) {
		ce = &cliError{code: exitError, kind: "error", msg: err.Error()}
	}
	if ce.silent {
		return ce.code
	}
	if jsonOut {
		writeJSON(map[string]any{
			"ok":    false,
			"error": map[string]string{"kind": ce.kind, "message": ce.msg, "hint": ce.hint},
		})
		return ce.code
	}
	fmt.Fprintf(stderr, "shep: %s\n", ce.msg)
	if ce.hint != "" {
		fmt.Fprintf(stderr, "  %s\n", ce.hint)
	}
	return ce.code
}

func writeJSON(v any) {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func newFS(name, usageLine string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: shep %s\n", usageLine)
		fs.PrintDefaults()
	}
	return fs
}

func flagError(err error) error {
	if errors.Is(err, flag.ErrHelp) {
		return &cliError{code: 0, silent: true}
	}
	return &cliError{code: exitUsage, silent: true}
}

// parseAnywhere parses flags wherever they sit among the positional
// arguments, so "shep add web --host 1.2.3.4" works.
func parseAnywhere(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, flagError(err)
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func usageErr(fs *flag.FlagSet, msg string) error {
	fmt.Fprintf(stderr, "shep: %s\n", msg)
	fs.Usage()
	return &cliError{code: exitUsage, silent: true}
}
