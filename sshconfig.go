package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Host is one concrete (non-wildcard) entry from the SSH config.
type Host struct {
	Alias         string
	HostName      string
	User          string
	Port          string
	IdentityFiles []string
}

const maxBackups = 10

var aliasRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func sshConfigPath() string {
	if p := os.Getenv("SHEP_SSH_CONFIG"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ssh", "config")
}

// splitKV splits an ssh_config line into a lowercased keyword and its value.
// Both "Key Value" and "Key=Value" forms are accepted.
func splitKV(line string) (string, string) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", ""
	}
	i := strings.IndexAny(line, " \t=")
	if i < 0 {
		return strings.ToLower(line), ""
	}
	key := strings.ToLower(line[:i])
	val := strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
	if len(val) >= 2 && strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`) {
		val = val[1 : len(val)-1]
	}
	return key, val
}

func isPattern(s string) bool {
	return strings.ContainsAny(s, "*?!")
}

// parseSSHConfig returns the concrete hosts in the file, in file order.
// Wildcard Host lines and Match blocks are skipped. As in ssh itself, the
// first value seen for a keyword wins.
func parseSSHConfig(data string) []Host {
	var hosts []Host
	index := map[string]int{}
	var current []int

	for _, line := range strings.Split(data, "\n") {
		key, val := splitKV(line)
		switch key {
		case "":
			continue
		case "host":
			current = nil
			for _, p := range strings.Fields(val) {
				if isPattern(p) {
					continue
				}
				i, ok := index[p]
				if !ok {
					hosts = append(hosts, Host{Alias: p})
					i = len(hosts) - 1
					index[p] = i
				}
				current = append(current, i)
			}
		case "match":
			current = nil
		default:
			for _, i := range current {
				h := &hosts[i]
				switch key {
				case "hostname":
					if h.HostName == "" {
						h.HostName = val
					}
				case "user":
					if h.User == "" {
						h.User = val
					}
				case "port":
					if h.Port == "" {
						h.Port = val
					}
				case "identityfile":
					h.IdentityFiles = append(h.IdentityFiles, val)
				}
			}
		}
	}
	return hosts
}

func readSSHConfig() (string, error) {
	b, err := os.ReadFile(sshConfigPath())
	if os.IsNotExist(err) {
		return "", nil
	}
	return string(b), err
}

func loadHosts() ([]Host, error) {
	data, err := readSSHConfig()
	if err != nil {
		return nil, err
	}
	return parseSSHConfig(data), nil
}

// backupSSHConfig copies the config next to itself before an edit and keeps
// only the newest maxBackups copies.
func backupSSHConfig(path, data string) error {
	if data == "" {
		return nil
	}
	base := path + ".shep-bak-" + time.Now().Format("20060102-150405.000")
	name := base
	for i := 1; ; i++ {
		if _, err := os.Stat(name); os.IsNotExist(err) {
			break
		}
		name = fmt.Sprintf("%s-%d", base, i)
	}
	if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
		return err
	}
	old, _ := filepath.Glob(path + ".shep-bak-*")
	sort.Strings(old)
	for len(old) > maxBackups {
		os.Remove(old[0])
		old = old[1:]
	}
	return nil
}

func writeSSHConfig(path, old, updated string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if err := backupSSHConfig(path, old); err != nil {
		return fmt.Errorf("backup failed, config left untouched: %w", err)
	}
	return os.WriteFile(path, []byte(updated), 0o600)
}

func validateHost(h Host) error {
	if !aliasRe.MatchString(h.Alias) {
		return fmt.Errorf("invalid name %q: use letters, digits, dot, dash or underscore", h.Alias)
	}
	if h.HostName == "" {
		return fmt.Errorf("--host is required (IP address or domain)")
	}
	for label, v := range map[string]string{"--host": h.HostName, "--user": h.User, "--port": h.Port} {
		if strings.ContainsAny(v, " \t\r\n\"#") {
			return fmt.Errorf("%s must not contain spaces, quotes or #", label)
		}
	}
	if h.Port != "" && !regexp.MustCompile(`^[0-9]{1,5}$`).MatchString(h.Port) {
		return fmt.Errorf("--port must be a number")
	}
	for _, k := range h.IdentityFiles {
		if strings.ContainsAny(k, "\r\n\"") {
			return fmt.Errorf("--key must not contain quotes or line breaks")
		}
	}
	return nil
}

// addHost appends a Host block to the SSH config, leaving the rest of the
// file byte-for-byte as it was.
func addHost(h Host) error {
	if err := validateHost(h); err != nil {
		return err
	}
	path := sshConfigPath()
	old, err := readSSHConfig()
	if err != nil {
		return err
	}
	for _, e := range parseSSHConfig(old) {
		if e.Alias == h.Alias {
			return fmt.Errorf("host %q already exists in %s", h.Alias, path)
		}
	}
	nl := "\n"
	if strings.Contains(old, "\r\n") {
		nl = "\r\n"
	}
	var b strings.Builder
	b.WriteString(old)
	if old != "" {
		if !strings.HasSuffix(old, "\n") {
			b.WriteString(nl)
		}
		b.WriteString(nl)
	}
	b.WriteString("Host " + h.Alias + nl)
	b.WriteString("    HostName " + h.HostName + nl)
	if h.User != "" {
		b.WriteString("    User " + h.User + nl)
	}
	if h.Port != "" {
		b.WriteString("    Port " + h.Port + nl)
	}
	for _, k := range h.IdentityFiles {
		if strings.Contains(k, " ") {
			k = `"` + k + `"`
		}
		b.WriteString("    IdentityFile " + k + nl)
	}
	if len(h.IdentityFiles) > 0 {
		b.WriteString("    IdentitiesOnly yes" + nl)
	}
	return writeSSHConfig(path, old, b.String())
}

// removeHost deletes the Host block for alias. Comments and blank lines that
// sit directly above the next block are kept, since they belong to it.
func removeHost(alias string) error {
	path := sshConfigPath()
	old, err := readSSHConfig()
	if err != nil {
		return err
	}
	lines := strings.SplitAfter(old, "\n")
	start := -1
	for i, line := range lines {
		key, val := splitKV(line)
		if key != "host" {
			continue
		}
		patterns := strings.Fields(val)
		for _, p := range patterns {
			if p != alias {
				continue
			}
			if len(patterns) > 1 {
				return fmt.Errorf("%q shares its Host line with other names; edit %s by hand", alias, path)
			}
			start = i
		}
		if start >= 0 {
			break
		}
	}
	if start < 0 {
		return fmt.Errorf("host %q not found in %s", alias, path)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		if key, _ := splitKV(lines[i]); key == "host" || key == "match" {
			end = i
			break
		}
	}
	if end < len(lines) {
		for end > start+1 {
			t := strings.TrimSpace(lines[end-1])
			if t != "" && !strings.HasPrefix(t, "#") {
				break
			}
			end--
		}
	}
	updated := strings.Join(append(append([]string{}, lines[:start]...), lines[end:]...), "")
	return writeSSHConfig(path, old, updated)
}
