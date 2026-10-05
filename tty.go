package main

import (
	"os"

	"golang.org/x/term"
)

// isInteractive reports whether a person is at the keyboard. Agents run shep
// with pipes or NUL attached, so this is how human-only commands tell the
// two apart. It is a variable so tests can replace it.
var isInteractive = func() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}
