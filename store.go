package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// Meta is what shep knows about a host beyond the SSH config.
type Meta struct {
	Tags   []string `json:"tags,omitempty"`
	Policy string   `json:"policy,omitempty"`
	Note   string   `json:"note,omitempty"`
	Allow  []string `json:"allow,omitempty"`
}

type State struct {
	DefaultScope  string           `json:"default_scope,omitempty"`
	DefaultPolicy string           `json:"default_policy,omitempty"`
	Hosts         map[string]*Meta `json:"hosts"`
}

// AuditEntry is one line of audit.jsonl.
type AuditEntry struct {
	Time       string `json:"time"`
	Caller     string `json:"caller"`
	Scope      string `json:"scope,omitempty"`
	Host       string `json:"host"`
	Command    string `json:"command"`
	Policy     string `json:"policy"`
	Decision   string `json:"decision"`
	Reason     string `json:"reason,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

func shepHome() string {
	if p := os.Getenv("SHEP_HOME"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".shep")
}

func statePath() string { return filepath.Join(shepHome(), "shep.json") }
func auditPath() string { return filepath.Join(shepHome(), "audit.jsonl") }

func loadState() (*State, error) {
	s := &State{Hosts: map[string]*Meta{}}
	b, err := os.ReadFile(statePath())
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, err
	}
	if s.Hosts == nil {
		s.Hosts = map[string]*Meta{}
	}
	return s, nil
}

func saveState(s *State) error {
	if err := os.MkdirAll(shepHome(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := statePath() + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, statePath())
}

func (s *State) meta(alias string) *Meta {
	if m, ok := s.Hosts[alias]; ok && m != nil {
		return m
	}
	return &Meta{}
}

func appendAudit(e AuditEntry) error {
	if err := os.MkdirAll(shepHome(), 0o700); err != nil {
		return err
	}
	e.Time = time.Now().Format(time.RFC3339)
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(auditPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(b, '\n'))
	return err
}

func readAudit() ([]AuditEntry, error) {
	f, err := os.Open(auditPath())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var entries []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			entries = append(entries, e)
		}
	}
	return entries, sc.Err()
}
