package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleConfig = `# my servers
Host *
    ServerAliveInterval 60

Host web1 web2
    HostName 10.0.0.1
    User deploy

# database box
Host db
    HostName=db.example.com
    Port 2222
    IdentityFile ~/.ssh/id_work

Host old
    HostName 10.0.0.9

# trailing comment for the next block
Host last
    HostName 10.0.0.5
`

func TestParseSSHConfig(t *testing.T) {
	hosts := parseSSHConfig(sampleConfig)
	var names []string
	for _, h := range hosts {
		names = append(names, h.Alias)
	}
	if got := strings.Join(names, ","); got != "web1,web2,db,old,last" {
		t.Fatalf("aliases = %s", got)
	}
	if hosts[1].HostName != "10.0.0.1" || hosts[1].User != "deploy" {
		t.Errorf("web2 = %+v", hosts[1])
	}
	db := hosts[2]
	if db.HostName != "db.example.com" || db.Port != "2222" || len(db.IdentityFiles) != 1 {
		t.Errorf("db = %+v", db)
	}
}

func TestReadonlyPolicy(t *testing.T) {
	allowed := []string{
		"df -h",
		"ls -la /var/log",
		"ps aux | grep nginx | wc -l",
		"docker ps",
		"systemctl status nginx",
		"hostname",
		"tail -n 50 /var/log/syslog",
		"sort -u names.txt | uniq -c",
	}
	for _, c := range allowed {
		if err := checkReadonly(c, nil); err != nil {
			t.Errorf("%q should be allowed: %v", c, err)
		}
	}
	denied := []string{
		"rm -rf /tmp/x",
		"ls; rm x",
		"ls && rm x",
		"cat /etc/passwd > /tmp/out",
		"echo $(whoami)",
		"echo `id`",
		"sudo ls",
		"ls | sh",
		"ls ||",
		"find / -name x -delete",
		"find . -exec rm {} +",
		"sort -o out.txt in.txt",
		"sort -uo out.txt in.txt",
		"uniq in.txt out.txt",
		"date -s 2020-01-01",
		"hostname evil",
		"systemctl restart nginx",
		"docker rm web",
		"journalctl --vacuum-size=1M",
		"lsx",
	}
	for _, c := range denied {
		if err := checkReadonly(c, nil); err == nil {
			t.Errorf("%q should be denied", c)
		}
	}
	if err := checkReadonly("docker compose restart api", []string{"docker compose restart"}); err != nil {
		t.Errorf("per-host allow not honoured: %v", err)
	}
	if err := checkCommand("-oProxyCommand=calc"); err == nil {
		t.Error("leading dash must be rejected")
	}
}

// sandbox points shep at a temp SSH config and state dir.
func sandbox(t *testing.T, interactive bool) (*bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config")
	if err := os.WriteFile(cfg, []byte(sampleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SHEP_SSH_CONFIG", cfg)
	t.Setenv("SHEP_HOME", filepath.Join(dir, "shep"))
	t.Setenv("SHEP_SCOPE", "")
	out, errw := &bytes.Buffer{}, &bytes.Buffer{}
	prevOut, prevErr, prevTTY := stdout, stderr, isInteractive
	stdout, stderr = out, errw
	isInteractive = func() bool { return interactive }
	t.Cleanup(func() { stdout, stderr, isInteractive = prevOut, prevErr, prevTTY })
	return out, errw
}

func TestAddAndRemoveKeepRestOfFile(t *testing.T) {
	out, _ := sandbox(t, true)
	code := run([]string{"add", "api", "--host", "1.2.3.4", "--user", "me", "--key", "~/.ssh/id_work", "--tags", "work", "--policy", "full"})
	if code != 0 {
		t.Fatalf("add exit %d: %s", code, out)
	}
	data, _ := readSSHConfig()
	if !strings.HasPrefix(data, sampleConfig) {
		t.Error("add changed existing content")
	}
	if !strings.Contains(data, "Host api\n    HostName 1.2.3.4\n    User me\n    IdentityFile ~/.ssh/id_work\n    IdentitiesOnly yes\n") {
		t.Errorf("unexpected block:\n%s", data)
	}
	if run([]string{"add", "api", "--host", "1.2.3.4"}) == 0 {
		t.Error("duplicate add should fail")
	}

	if code := run([]string{"rm", "old", "--yes"}); code != 0 {
		t.Fatalf("rm exit %d", code)
	}
	data, _ = readSSHConfig()
	if strings.Contains(data, "Host old") || strings.Contains(data, "10.0.0.9") {
		t.Error("old block still present")
	}
	if !strings.Contains(data, "# trailing comment for the next block\nHost last") {
		t.Errorf("comment of next block lost:\n%s", data)
	}
	if run([]string{"rm", "web1", "--yes"}) == 0 {
		t.Error("rm of a shared Host line should fail")
	}
	backups, _ := filepath.Glob(sshConfigPath() + ".shep-bak-*")
	if len(backups) != 2 {
		t.Errorf("want 2 backups, got %d", len(backups))
	}
}

func TestAgentCannotEdit(t *testing.T) {
	_, errw := sandbox(t, false)
	for _, args := range [][]string{
		{"add", "x", "--host", "1.2.3.4"},
		{"set", "db", "--policy", "full"},
		{"rm", "db", "--yes"},
		{"scope", "work"},
		{"connect", "db"},
	} {
		if code := run(args); code != exitDenied {
			t.Errorf("%v: exit %d, want %d (%s)", args, code, exitDenied, errw)
		}
	}
	data, _ := readSSHConfig()
	if data != sampleConfig {
		t.Error("config changed by a non-interactive caller")
	}
}

func TestScopeAndPolicyEnforcement(t *testing.T) {
	out, _ := sandbox(t, true)
	run([]string{"set", "db", "--tags", "work", "--policy", "blocked", "--note", "prod database"})
	run([]string{"set", "web1", "--tags", "personal"})
	isInteractive = func() bool { return false }

	out.Reset()
	t.Setenv("SHEP_SCOPE", "work")
	if code := run([]string{"list", "--json"}); code != 0 {
		t.Fatalf("list exit %d", code)
	}
	var listed struct {
		Scope string
		Hosts []hostView
	}
	if err := json.Unmarshal(out.Bytes(), &listed); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if listed.Scope != "work" || len(listed.Hosts) != 1 || listed.Hosts[0].Alias != "db" ||
		listed.Hosts[0].Policy != "blocked" || listed.Hosts[0].Note != "prod database" {
		t.Errorf("list = %+v", listed)
	}

	// Out of scope, blocked and read-only refusals never reach ssh.
	cases := []struct {
		scope string
		args  []string
		code  int
		kind  string
	}{
		{"work", []string{"run", "--json", "web1", "ls"}, exitNotFound, "out_of_scope"},
		{"work", []string{"run", "--json", "db", "ls"}, exitDenied, "policy_denied"},
		{"personal", []string{"run", "--json", "web1", "rm -rf /"}, exitDenied, "policy_denied"},
		{"all", []string{"run", "--json", "nope", "ls"}, exitNotFound, "not_found"},
		{"all", []string{"run", "--json", "web2", "-oProxyCommand=calc"}, exitDenied, "policy_denied"},
	}
	for _, c := range cases {
		out.Reset()
		t.Setenv("SHEP_SCOPE", c.scope)
		code := run(c.args)
		var res struct {
			OK    bool
			Error struct{ Kind, Message, Hint string }
		}
		if err := json.Unmarshal(out.Bytes(), &res); err != nil {
			t.Fatalf("%v: bad JSON: %v\n%s", c.args, err, out)
		}
		if code != c.code || res.Error.Kind != c.kind || res.OK {
			t.Errorf("%v: exit %d kind %q, want %d %q", c.args, code, res.Error.Kind, c.code, c.kind)
		}
	}

	entries, err := readAudit()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 audit entries (the denied runs on known hosts), got %d", len(entries))
	}
	for _, e := range entries {
		if e.Decision != "denied" || e.Reason == "" {
			t.Errorf("audit entry = %+v", e)
		}
	}
}
