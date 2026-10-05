package main

import (
	"fmt"
	"strings"
)

const (
	PolicyBlocked  = "blocked"
	PolicyReadonly = "readonly"
	PolicyFull     = "full"

	fallbackPolicy = PolicyReadonly
)

func validPolicy(p string) bool {
	return p == PolicyBlocked || p == PolicyReadonly || p == PolicyFull
}

// Commands a readonly host accepts, matched as "cmd" or "cmd <args>".
var prefixAllow = []string{
	"ls", "cat", "head", "tail", "grep", "wc", "sort", "uniq", "cut",
	"df", "du", "free", "id", "uname", "date", "ps", "top -b", "stat",
	"file", "find", "which", "lsblk", "lscpu", "nproc", "vmstat", "iostat",
	"dmesg", "echo", "ss", "netstat", "journalctl",
	"systemctl status", "systemctl is-active", "systemctl is-enabled",
	"systemctl list-units",
	"docker ps", "docker logs", "docker images", "docker inspect",
	"docker stats --no-stream", "docker compose ps", "docker compose logs",
	"ip addr show", "ip route show",
	"git status", "git log", "git diff", "git rev-parse",
	"git branch --show-current",
}

// Commands a readonly host accepts only when typed exactly like this.
var exactAllow = []string{
	"hostname", "hostname -f", "hostname -I", "whoami", "uptime", "pwd",
	"ip a", "ip addr", "ip route", "nginx -t", "true",
}

// Arguments that turn an otherwise harmless command into one that writes.
var deniedArgs = map[string][]string{
	"find":       {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf", "-fls"},
	"date":       {"-s", "--set"},
	"sort":       {"-o", "--output"},
	"journalctl": {"--vacuum", "--rotate", "--flush", "--sync", "--relinquish", "--setup-keys"},
	"dmesg":      {"-C", "-c", "--clear", "--read-clear", "-n", "--console-level", "-D", "-E"},
	"ss":         {"-K", "--kill"},
	"git":        {"--output"},
}

const shellMeta = ";&`$><(){}\n\r"

// checkCommand applies the rules that hold for every policy.
func checkCommand(command string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("no command given")
	}
	// ssh re-reads options after the host name, so a leading dash would be
	// taken as an ssh option (ProxyCommand and friends) and run locally.
	if strings.HasPrefix(strings.TrimSpace(command), "-") {
		return fmt.Errorf("a command cannot start with a dash")
	}
	return nil
}

// checkReadonly reports why command is not acceptable on a readonly host,
// or nil. This is a filter on the command text, not a sandbox: the real
// limit is what the remote user account is allowed to do.
func checkReadonly(command string, extra []string) error {
	if i := strings.IndexAny(command, shellMeta); i >= 0 {
		return fmt.Errorf("character %q is not allowed on a read-only host (no chaining, redirection or substitution)", command[i])
	}
	for _, seg := range strings.Split(command, "|") {
		seg = strings.Join(strings.Fields(seg), " ")
		if seg == "" {
			return fmt.Errorf("empty command in pipeline")
		}
		if !segmentAllowed(seg, extra) {
			return fmt.Errorf("%q is not on the read-only allow list", firstWords(seg))
		}
		if err := checkArgs(seg); err != nil {
			return err
		}
	}
	return nil
}

func segmentAllowed(seg string, extra []string) bool {
	for _, e := range exactAllow {
		if seg == e {
			return true
		}
	}
	for _, list := range [][]string{prefixAllow, extra} {
		for _, p := range list {
			p = strings.Join(strings.Fields(p), " ")
			if p != "" && (seg == p || strings.HasPrefix(seg, p+" ")) {
				return true
			}
		}
	}
	return false
}

func checkArgs(seg string) error {
	fields := strings.Fields(seg)
	cmd, args := fields[0], fields[1:]
	for _, a := range args {
		for _, d := range deniedArgs[cmd] {
			long := strings.HasPrefix(d, "--")
			if a == d || strings.HasPrefix(a, d+"=") || (long && strings.HasPrefix(a, d)) {
				return fmt.Errorf("%s %s is not allowed on a read-only host", cmd, d)
			}
		}
		// "sort -uo out.txt": -o hidden inside a cluster of short flags.
		if cmd == "sort" && len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.Contains(a, "o") {
			return fmt.Errorf("sort -o is not allowed on a read-only host")
		}
		// "uniq in out" writes to its second file argument.
		if cmd == "uniq" && !strings.HasPrefix(a, "-") {
			return fmt.Errorf("uniq with file arguments is not allowed on a read-only host; pipe into it instead")
		}
	}
	return nil
}

func firstWords(seg string) string {
	f := strings.Fields(seg)
	if len(f) > 2 {
		f = f[:2]
	}
	return strings.Join(f, " ")
}
