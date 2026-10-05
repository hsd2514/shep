package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	defaultRunTimeout = 60 * time.Second
	checkTimeout      = 20 * time.Second
	maxCapture        = 1 << 20
)

type hostView struct {
	Alias         string   `json:"alias"`
	HostName      string   `json:"hostname,omitempty"`
	User          string   `json:"user,omitempty"`
	Port          string   `json:"port,omitempty"`
	Policy        string   `json:"policy"`
	Tags          []string `json:"tags"`
	Note          string   `json:"note,omitempty"`
	Allow         []string `json:"allow,omitempty"`
	IdentityFiles []string `json:"identity_files,omitempty"`
}

type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ",") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// capBuf keeps the first max bytes written to it and drops the rest.
type capBuf struct {
	buf       bytes.Buffer
	truncated bool
}

func (c *capBuf) Write(p []byte) (int, error) {
	if room := maxCapture - c.buf.Len(); room < len(p) {
		c.truncated = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

func activeScope(s *State) string {
	sc := os.Getenv("SHEP_SCOPE")
	if sc == "" {
		sc = s.DefaultScope
	}
	if sc == "all" {
		return ""
	}
	return sc
}

func inScope(m *Meta, scope string) bool {
	if scope == "" {
		return true
	}
	for _, t := range m.Tags {
		if t == scope {
			return true
		}
	}
	return false
}

func effectivePolicy(m *Meta, s *State) string {
	if validPolicy(m.Policy) {
		return m.Policy
	}
	if validPolicy(s.DefaultPolicy) {
		return s.DefaultPolicy
	}
	return fallbackPolicy
}

func caller() string {
	if v := os.Getenv("SHEP_CALLER"); v != "" {
		return v
	}
	if os.Getenv("CLAUDECODE") != "" {
		return "claude-code"
	}
	if isInteractive() {
		return "human"
	}
	return "agent"
}

func view(h Host, m *Meta, s *State) hostView {
	tags := m.Tags
	if tags == nil {
		tags = []string{}
	}
	return hostView{
		Alias: h.Alias, HostName: h.HostName, User: h.User, Port: h.Port,
		Policy: effectivePolicy(m, s), Tags: tags, Note: m.Note, Allow: m.Allow,
		IdentityFiles: h.IdentityFiles,
	}
}

func loadAll() ([]Host, *State, error) {
	hosts, err := loadHosts()
	if err != nil {
		return nil, nil, err
	}
	state, err := loadState()
	if err != nil {
		return nil, nil, err
	}
	return hosts, state, nil
}

// findHost returns a host only if it exists and is visible in the scope.
func findHost(alias string) (Host, *Meta, *State, error) {
	hosts, state, err := loadAll()
	if err != nil {
		return Host{}, nil, nil, err
	}
	scope := activeScope(state)
	for _, h := range hosts {
		if h.Alias != alias {
			continue
		}
		m := state.meta(alias)
		if !inScope(m, scope) {
			return Host{}, nil, nil, &cliError{code: exitNotFound, kind: "out_of_scope",
				msg:  fmt.Sprintf("host %q is not available in scope %q", alias, scope),
				hint: "Run `shep list` to see the hosts you can use."}
		}
		return h, m, state, nil
	}
	return Host{}, nil, nil, &cliError{code: exitNotFound, kind: "not_found",
		msg:  fmt.Sprintf("no host named %q", alias),
		hint: "Run `shep list` to see the hosts you can use."}
}

func requireHuman(action string) error {
	if isInteractive() {
		return nil
	}
	return &cliError{code: exitDenied, kind: "human_only",
		msg:  fmt.Sprintf("`shep %s` only runs in an interactive terminal", action),
		hint: "It changes hosts or the rules agents run under. Ask the user to run it themselves."}
}

func splitTags(s string) []string {
	var tags []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			tags = append(tags, t)
		}
	}
	return tags
}

func sshArgs(alias string, batch bool) []string {
	var args []string
	if p := os.Getenv("SHEP_SSH_CONFIG"); p != "" {
		args = append(args, "-F", p)
	}
	if batch {
		args = append(args, "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10")
	}
	return append(args, alias)
}

func cmdList(args []string) error {
	fs := newFS("list", "list [--json] [--tag T]")
	fs.BoolVar(&jsonOut, "json", false, "print JSON")
	tag := fs.String("tag", "", "only hosts with this tag")
	if _, err := parseAnywhere(fs, args); err != nil {
		return err
	}
	hosts, state, err := loadAll()
	if err != nil {
		return err
	}
	scope := activeScope(state)
	views := []hostView{}
	for _, h := range hosts {
		m := state.meta(h.Alias)
		if !inScope(m, scope) || (*tag != "" && !inScope(m, *tag)) {
			continue
		}
		views = append(views, view(h, m, state))
	}
	if jsonOut {
		sc := scope
		if sc == "" {
			sc = "all"
		}
		writeJSON(map[string]any{"ok": true, "scope": sc, "hosts": views})
		return nil
	}
	if len(views) == 0 {
		fmt.Fprintln(stdout, "No hosts. Add one with: shep add <name> --host <address>")
		return nil
	}
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tADDRESS\tUSER\tPOLICY\tTAGS\tNOTE")
	for _, v := range views {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", v.Alias, v.HostName, v.User, v.Policy, strings.Join(v.Tags, ","), v.Note)
	}
	return w.Flush()
}

func cmdShow(args []string) error {
	fs := newFS("show", "show <host> [--json]")
	fs.BoolVar(&jsonOut, "json", false, "print JSON")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErr(fs, "expected one host name")
	}
	h, m, state, err := findHost(pos[0])
	if err != nil {
		return err
	}
	v := view(h, m, state)
	if jsonOut {
		writeJSON(map[string]any{"ok": true, "host": v})
		return nil
	}
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(w, "Name\t%s\n", v.Alias)
	fmt.Fprintf(w, "Address\t%s\n", v.HostName)
	fmt.Fprintf(w, "User\t%s\n", v.User)
	fmt.Fprintf(w, "Port\t%s\n", v.Port)
	fmt.Fprintf(w, "Keys\t%s\n", strings.Join(v.IdentityFiles, ", "))
	fmt.Fprintf(w, "Policy\t%s\n", v.Policy)
	fmt.Fprintf(w, "Tags\t%s\n", strings.Join(v.Tags, ", "))
	fmt.Fprintf(w, "Extra allowed\t%s\n", strings.Join(v.Allow, "; "))
	fmt.Fprintf(w, "Note\t%s\n", v.Note)
	return w.Flush()
}

func cmdRun(args []string) error {
	fs := newFS("run", "run [--json] [--timeout 60s] <host> <command>")
	fs.BoolVar(&jsonOut, "json", false, "print JSON with captured output")
	timeout := fs.Duration("timeout", defaultRunTimeout, "stop the command after this long")
	if err := fs.Parse(args); err != nil {
		return flagError(err)
	}
	rest := fs.Args()
	if len(rest) < 2 {
		return usageErr(fs, "expected a host and a command")
	}
	alias, command := rest[0], strings.Join(rest[1:], " ")
	_, m, state, err := findHost(alias)
	if err != nil {
		return err
	}
	policy := effectivePolicy(m, state)
	entry := AuditEntry{Caller: caller(), Scope: activeScope(state), Host: alias, Command: command, Policy: policy}

	deny := func(reason, hint string) error {
		entry.Decision, entry.Reason = "denied", reason
		appendAudit(entry)
		return &cliError{code: exitDenied, kind: "policy_denied", msg: reason, hint: hint}
	}
	if err := checkCommand(command); err != nil {
		return deny(err.Error(), "")
	}
	switch policy {
	case PolicyBlocked:
		return deny(fmt.Sprintf("host %q is blocked: commands cannot be run on it through shep", alias),
			"Only the user can change this, with `shep set`.")
	case PolicyReadonly:
		if err := checkReadonly(command, m.Allow); err != nil {
			return deny(err.Error(),
				fmt.Sprintf("Host %q is read-only. The user can widen it with `shep set %s --allow \"<command>\"` or `--policy full`.", alias, alias))
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	c := exec.CommandContext(ctx, "ssh", append(sshArgs(alias, true), command)...)
	c.WaitDelay = 2 * time.Second
	var outBuf, errBuf capBuf
	if jsonOut {
		c.Stdout, c.Stderr = &outBuf, &errBuf
	} else {
		c.Stdout, c.Stderr = stdout, stderr
	}
	start := time.Now()
	runErr := c.Run()
	elapsed := time.Since(start).Milliseconds()
	timedOut := ctx.Err() == context.DeadlineExceeded

	code := 0
	var ee *exec.ExitError
	switch {
	case timedOut:
		code = exitTimeout
	case errors.As(runErr, &ee):
		code = ee.ExitCode()
	case runErr != nil:
		entry.Decision, entry.Reason = "failed", runErr.Error()
		appendAudit(entry)
		return &cliError{code: exitError, kind: "ssh_unavailable", msg: "could not start ssh: " + runErr.Error()}
	}
	entry.Decision, entry.ExitCode, entry.DurationMs = "allowed", &code, elapsed
	if timedOut {
		entry.Reason = "timed out"
	}
	appendAudit(entry)

	if jsonOut {
		writeJSON(map[string]any{
			"ok": code == 0, "host": alias, "command": command, "exit_code": code,
			"stdout": outBuf.buf.String(), "stderr": errBuf.buf.String(),
			"duration_ms": elapsed, "timed_out": timedOut,
			"truncated": outBuf.truncated || errBuf.truncated,
		})
	} else if timedOut {
		fmt.Fprintf(stderr, "shep: stopped after %s (use --timeout to allow longer)\n", *timeout)
	} else if code == 255 {
		fmt.Fprintf(stderr, "shep: ssh could not connect. Run `shep check %s` to see why.\n", alias)
	}
	if code != 0 {
		return &cliError{code: code, silent: true}
	}
	return nil
}

// diagnose turns ssh's stderr into a reason an agent can act on.
func diagnose(stderrText string) (reason, hint string) {
	t := strings.ToLower(stderrText)
	switch {
	case strings.Contains(t, "host key verification failed"):
		return "unknown_host_key", "The user must connect once themselves to accept the server fingerprint: `shep connect <host>`."
	case strings.Contains(t, "permission denied"):
		return "auth_failed", "No accepted key. The user should load the key with `ssh-add` and check it is authorized on the server."
	case strings.Contains(t, "could not resolve hostname"):
		return "unknown_address", "The address in the SSH config does not resolve."
	case strings.Contains(t, "connection refused"):
		return "refused", "The server refused the connection. Check the port and that sshd is running."
	case strings.Contains(t, "timed out"):
		return "timeout", "No answer from the server. Check the address, network or VPN."
	}
	return "failed", ""
}

func cmdCheck(args []string) error {
	fs := newFS("check", "check <host> [--json]")
	fs.BoolVar(&jsonOut, "json", false, "print JSON")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErr(fs, "expected one host name")
	}
	alias := pos[0]
	_, m, state, err := findHost(alias)
	if err != nil {
		return err
	}
	if effectivePolicy(m, state) == PolicyBlocked {
		return &cliError{code: exitDenied, kind: "policy_denied",
			msg: fmt.Sprintf("host %q is blocked", alias), hint: "Only the user can change this, with `shep set`."}
	}
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, "ssh", append(sshArgs(alias, true), "exit")...)
	c.WaitDelay = 2 * time.Second
	var errBuf capBuf
	c.Stderr = &errBuf
	runErr := c.Run()
	detail := strings.TrimSpace(errBuf.buf.String())

	ok := runErr == nil
	reason, hint := "", ""
	if !ok {
		if ctx.Err() == context.DeadlineExceeded {
			detail = "timed out"
		} else if detail == "" {
			detail = runErr.Error()
		}
		reason, hint = diagnose(detail)
	}
	if jsonOut {
		writeJSON(map[string]any{"ok": ok, "host": alias, "reason": reason, "detail": detail, "hint": hint})
	} else if ok {
		fmt.Fprintf(stdout, "%s: reachable, no prompts needed\n", alias)
	} else {
		fmt.Fprintf(stdout, "%s: not usable (%s)\n  %s\n", alias, reason, detail)
		if hint != "" {
			fmt.Fprintf(stdout, "  %s\n", hint)
		}
	}
	if !ok {
		return &cliError{code: exitError, silent: true}
	}
	return nil
}

func cmdLog(args []string) error {
	fs := newFS("log", "log [-n 20] [--host H] [--json]")
	fs.BoolVar(&jsonOut, "json", false, "print JSON")
	n := fs.Int("n", 20, "number of entries")
	host := fs.String("host", "", "only this host")
	if _, err := parseAnywhere(fs, args); err != nil {
		return err
	}
	all, err := readAudit()
	if err != nil {
		return err
	}
	entries := []AuditEntry{}
	for _, e := range all {
		if *host == "" || e.Host == *host {
			entries = append(entries, e)
		}
	}
	if *n > 0 && len(entries) > *n {
		entries = entries[len(entries)-*n:]
	}
	if jsonOut {
		writeJSON(map[string]any{"ok": true, "entries": entries})
		return nil
	}
	if len(entries) == 0 {
		fmt.Fprintln(stdout, "No commands logged yet.")
		return nil
	}
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "TIME\tCALLER\tHOST\tRESULT\tCOMMAND")
	for _, e := range entries {
		result := e.Decision
		if e.ExitCode != nil {
			result = fmt.Sprintf("exit %d", *e.ExitCode)
		}
		ts := e.Time
		if t, err := time.Parse(time.RFC3339, e.Time); err == nil {
			ts = t.Format("2006-01-02 15:04:05")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", ts, e.Caller, e.Host, result, e.Command)
	}
	return w.Flush()
}

func cmdAdd(args []string) error {
	fs := newFS("add", "add <name> --host <addr> [--user U] [--port P] [--key FILE] [--tags a,b] [--policy P] [--note TEXT]")
	host := fs.String("host", "", "IP address or domain (required)")
	user := fs.String("user", "", "remote user name")
	port := fs.String("port", "", "port, if not 22")
	key := fs.String("key", "", "private key file, e.g. ~/.ssh/id_work")
	tags := fs.String("tags", "", "comma-separated tags, e.g. work,staging")
	policy := fs.String("policy", "", "blocked, readonly or full")
	note := fs.String("note", "", "what this host is, for you and for agents")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if err := requireHuman("add"); err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErr(fs, "expected one host name")
	}
	if *policy != "" && !validPolicy(*policy) {
		return usageErr(fs, "policy must be blocked, readonly or full")
	}
	h := Host{Alias: pos[0], HostName: *host, User: *user, Port: *port}
	if *key != "" {
		h.IdentityFiles = []string{*key}
	}
	state, err := loadState()
	if err != nil {
		return err
	}
	if err := addHost(h); err != nil {
		return err
	}
	m := &Meta{Tags: splitTags(*tags), Policy: *policy, Note: *note}
	state.Hosts[h.Alias] = m
	if err := saveState(state); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Added %s (policy: %s). Connect once with `shep connect %s` to accept its fingerprint.\n",
		h.Alias, effectivePolicy(m, state), h.Alias)
	return nil
}

func cmdSet(args []string) error {
	fs := newFS("set", `set <host> [--policy P] [--tags a,b] [--note TEXT] [--allow "cmd prefix"]... [--clear-allow]`)
	policy := fs.String("policy", "", "blocked, readonly or full")
	tags := fs.String("tags", "", "comma-separated tags (replaces the current ones)")
	note := fs.String("note", "", "what this host is")
	var allow stringList
	fs.Var(&allow, "allow", "extra command prefix a readonly host accepts (repeatable)")
	clearAllow := fs.Bool("clear-allow", false, "remove all extra allowed commands")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if err := requireHuman("set"); err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErr(fs, "expected one host name")
	}
	alias := pos[0]
	hosts, state, err := loadAll()
	if err != nil {
		return err
	}
	found := false
	for _, h := range hosts {
		found = found || h.Alias == alias
	}
	if !found {
		return &cliError{code: exitNotFound, kind: "not_found", msg: fmt.Sprintf("no host named %q", alias)}
	}
	m := state.meta(alias)
	changed := false
	var bad error
	fs.Visit(func(f *flag.Flag) {
		changed = true
		switch f.Name {
		case "policy":
			if !validPolicy(*policy) {
				bad = usageErr(fs, "policy must be blocked, readonly or full")
			}
			m.Policy = *policy
		case "tags":
			m.Tags = splitTags(*tags)
		case "note":
			m.Note = *note
		case "clear-allow":
			if *clearAllow {
				m.Allow = nil
			}
		}
	})
	if bad != nil {
		return bad
	}
	if !changed {
		return usageErr(fs, "nothing to change")
	}
	m.Allow = append(m.Allow, allow...)
	state.Hosts[alias] = m
	if err := saveState(state); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Updated %s: policy %s, tags [%s]\n", alias, effectivePolicy(m, state), strings.Join(m.Tags, ","))
	return nil
}

func cmdRm(args []string) error {
	fs := newFS("rm", "rm <host> [--yes]")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if err := requireHuman("rm"); err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErr(fs, "expected one host name")
	}
	alias := pos[0]
	if !*yes {
		fmt.Fprintf(stdout, "Remove %s from %s? [y/N] ", alias, sshConfigPath())
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(stdout, "Cancelled.")
			return nil
		}
	}
	state, err := loadState()
	if err != nil {
		return err
	}
	if err := removeHost(alias); err != nil {
		return err
	}
	delete(state.Hosts, alias)
	if err := saveState(state); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Removed %s. A backup of the previous config sits next to it.\n", alias)
	return nil
}

func cmdScope(args []string) error {
	fs := newFS("scope", "scope [name|all]")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	state, err := loadState()
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		def := state.DefaultScope
		if def == "" {
			def = "all"
		}
		fmt.Fprintf(stdout, "default scope: %s\n", def)
		if env := os.Getenv("SHEP_SCOPE"); env != "" {
			fmt.Fprintf(stdout, "SHEP_SCOPE in this terminal: %s (overrides the default)\n", env)
		}
		tags := map[string]bool{}
		for _, m := range state.Hosts {
			for _, t := range m.Tags {
				tags[t] = true
			}
		}
		names := make([]string, 0, len(tags))
		for t := range tags {
			names = append(names, t)
		}
		sort.Strings(names)
		fmt.Fprintf(stdout, "tags in use: %s\n", strings.Join(names, ", "))
		return nil
	}
	if err := requireHuman("scope"); err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErr(fs, "expected one scope name")
	}
	state.DefaultScope = pos[0]
	if pos[0] == "all" {
		state.DefaultScope = ""
	}
	if err := saveState(state); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "default scope set to %s\n", pos[0])
	return nil
}

func cmdConnect(args []string) error {
	fs := newFS("connect", "connect <host>")
	pos, err := parseAnywhere(fs, args)
	if err != nil {
		return err
	}
	if err := requireHuman("connect"); err != nil {
		return err
	}
	if len(pos) != 1 {
		return usageErr(fs, "expected one host name")
	}
	alias := pos[0]
	_, m, state, err := findHost(alias)
	if err != nil {
		return err
	}
	appendAudit(AuditEntry{Caller: caller(), Scope: activeScope(state), Host: alias,
		Command: "(interactive session)", Policy: effectivePolicy(m, state), Decision: "allowed"})
	c := exec.Command("ssh", sshArgs(alias, false)...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	var ee *exec.ExitError
	if err := c.Run(); errors.As(err, &ee) {
		return &cliError{code: ee.ExitCode(), silent: true}
	} else if err != nil {
		return &cliError{code: exitError, kind: "ssh_unavailable", msg: "could not start ssh: " + err.Error()}
	}
	return nil
}

const guideText = `## Remote servers (shep)

Use the ` + "`shep`" + ` command for anything on a remote server. Do not call ` + "`ssh`" + `, ` + "`scp`" + ` or ` + "`sftp`" + ` directly.

- ` + "`shep list --json`" + `: the hosts you may use, with policy, tags and a note on what each one is.
- ` + "`shep show <host> --json`" + `: details for one host.
- ` + "`shep check <host> --json`" + `: test the connection before relying on it.
- ` + "`shep run --json <host> <command>`" + `: run a command. Returns stdout, stderr and exit_code.
- ` + "`shep log --json`" + `: what has been run so far.

Rules:
- Every host has a policy. ` + "`readonly`" + ` accepts only allow-listed read-only commands with no ` + "`;`" + `, ` + "`&&`" + `, redirection or ` + "`$`" + ` (pipes are fine). ` + "`full`" + ` accepts anything. ` + "`blocked`" + ` accepts nothing.
- shep never prompts. If a command is refused or a host is unreachable, the JSON ` + "`error`" + ` or ` + "`hint`" + ` field says why. Report it to the user instead of working around it.
- ` + "`shep add`" + `, ` + "`set`" + `, ` + "`rm`" + `, ` + "`scope`" + ` and ` + "`connect`" + ` are for the user only. Ask them to run these.
- Commands stop after 60 seconds; pass ` + "`--timeout 5m`" + ` before the host name for longer ones. Avoid commands that never finish, such as ` + "`tail -f`" + `.
`

func cmdGuide(args []string) error {
	fmt.Fprint(stdout, guideText)
	return nil
}
