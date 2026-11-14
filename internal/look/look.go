// Package look runs SQL detections over exe.dev Look In tables (HTTP
// requests through the exe.dev proxy, per-VM metrics, SSH logins) and turns
// result rows into warden alerts.
//
// Queries go through the duckdb CLI so warden stays a static, cgo-free
// binary. Each rule's SQL sees a {since} placeholder: the start of the
// window to examine. Rows are de-duplicated by the rule's key columns
// across polls and restarts.
package look

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Rule is one SQL detection.
type Rule struct {
	ID          string   `yaml:"id"`
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Severity    string   `yaml:"severity"`
	MITRE       string   `yaml:"mitre"`
	Tables      []string `yaml:"tables"` // skipped until every table exists
	Key         []string `yaml:"key"`    // columns identifying one finding
	SQL         string   `yaml:"sql"`
	Disabled    bool     `yaml:"disabled"`
}

// Finding is one result row of a rule.
type Finding struct {
	Rule *Rule
	Key  string
	Row  map[string]any
}

type Options struct {
	Endpoint string // e.g. look.int.exe.xyz
	Bucket   string // e.g. look
	DuckDB   string // path to the duckdb CLI
	StateDir string // extension cache + dedupe state
	Lookback time.Duration
	// Ephemeral skips loading and saving dedupe state (one-off queries).
	Ephemeral bool
}

type Engine struct {
	opt   Options
	rules []*Rule
	mu    sync.Mutex
	seen  map[string]time.Time // finding key -> first reported
	since time.Time
}

func ParseRules(data []byte) ([]*Rule, error) {
	var rs []*Rule
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, err
	}
	for _, r := range rs {
		if r.ID == "" || r.SQL == "" || len(r.Key) == 0 {
			return nil, fmt.Errorf("look rule %q: id, sql and key are required", r.ID)
		}
		if !strings.Contains(r.SQL, "{since}") {
			return nil, fmt.Errorf("look rule %s: sql must filter on timestamp >= {since}", r.ID)
		}
	}
	return rs, nil
}

func New(opt Options, sets ...[]*Rule) *Engine {
	if opt.DuckDB == "" {
		opt.DuckDB = "duckdb"
	}
	if opt.Lookback == 0 {
		opt.Lookback = time.Hour
	}
	byID := map[string]*Rule{}
	var order []string
	for _, set := range sets {
		for _, r := range set {
			if _, ok := byID[r.ID]; !ok {
				order = append(order, r.ID)
			}
			byID[r.ID] = r
		}
	}
	e := &Engine{opt: opt, seen: map[string]time.Time{}}
	for _, id := range order {
		if !byID[id].Disabled {
			e.rules = append(e.rules, byID[id])
		}
	}
	e.load()
	return e
}

func (e *Engine) Rules() []*Rule { return e.rules }

// Discover finds a look integration through the in-VM reflection service.
func Discover(ctx context.Context) (endpoint, bucket string, err error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://reflection.int.exe.xyz/integrations", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	var body struct {
		Integrations []struct {
			Name string `json:"name"`
			Type string `json:"type"`
			Help string `json:"help"`
		} `json:"integrations"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", "", err
	}
	for _, in := range body.Integrations {
		if in.Type != "look" {
			continue
		}
		endpoint = in.Name + ".int.exe.xyz"
		if strings.Contains(in.Help, in.Name+".team.exe.xyz") {
			endpoint = in.Name + ".team.exe.xyz"
		}
		return endpoint, in.Name, nil
	}
	return "", "", fmt.Errorf("no look integration attached to this VM")
}

// Tables lists the tables that exist so far (a table appears with its first row).
func (e *Engine) Tables(ctx context.Context) (map[string]bool, error) {
	u := fmt.Sprintf("https://%s/%s/?list-type=2&delimiter=/", e.opt.Endpoint, e.opt.Bucket)
	req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("list %s: %s", u, resp.Status)
	}
	var l struct {
		Prefixes []struct {
			Prefix string `xml:"Prefix"`
		} `xml:"CommonPrefixes"`
	}
	if err := xml.Unmarshal(b, &l); err != nil {
		return nil, err
	}
	m := map[string]bool{}
	for _, p := range l.Prefixes {
		m[strings.TrimSuffix(p.Prefix, "/")] = true
	}
	return m, nil
}

func (e *Engine) setup(tables map[string]bool) string {
	var b strings.Builder
	ext := filepath.Join(e.opt.StateDir, "duckdb-extensions")
	fmt.Fprintf(&b, "SET extension_directory='%s';\n", ext)
	fmt.Fprintf(&b, "SET s3_endpoint='%s';\nSET s3_url_style='path';\nSET TimeZone='UTC';\n", e.opt.Endpoint)
	for t := range tables {
		fmt.Fprintf(&b, "CREATE OR REPLACE VIEW %s AS FROM iceberg_scan('s3://%s/%s', allow_moved_paths = true);\n", t, e.opt.Bucket, t)
	}
	b.WriteString("CREATE OR REPLACE MACRO increase(cur, prev) AS CASE WHEN cur < prev THEN cur ELSE cur - prev END;\n")
	return b.String()
}

// query runs one SQL statement after the setup and returns its rows. A
// table version published mid-read (ETag) or a 5xx is retried, per the
// Look In docs.
func (e *Engine) query(ctx context.Context, tables map[string]bool, sql string) ([]map[string]any, error) {
	if err := os.MkdirAll(filepath.Join(e.opt.StateDir, "duckdb-extensions"), 0o750); err != nil {
		return nil, err
	}
	script := e.setup(tables) + strings.TrimRight(strings.TrimSpace(sql), ";") + ";\n"
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		cmd := exec.CommandContext(cctx, e.opt.DuckDB, "-json")
		cmd.Env = append(os.Environ(), "HOME="+e.opt.StateDir)
		cmd.Stdin = strings.NewReader(script)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		cancel()
		msg := strings.TrimSpace(errb.String())
		if err == nil && !strings.Contains(msg, "Error") {
			return lastResult(out.Bytes())
		}
		lastErr = fmt.Errorf("duckdb: %v: %s", err, firstLine(msg))
		if !strings.Contains(msg, "ETag") && !strings.Contains(msg, "HTTP 5") {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 2 * time.Second)
	}
	return nil, lastErr
}

// lastResult decodes the final JSON array duckdb printed (earlier
// statements in the script print nothing or their own arrays).
func lastResult(b []byte) ([]map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var last []map[string]any
	for {
		var rows []map[string]any
		if err := dec.Decode(&rows); err == io.EOF {
			return last, nil
		} else if err != nil {
			return nil, fmt.Errorf("decoding duckdb output: %w", err)
		}
		last = rows
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}

func rowKey(r *Rule, row map[string]any) string {
	h := sha256.New()
	h.Write([]byte(r.ID))
	for _, k := range r.Key {
		fmt.Fprintf(h, "|%v", row[k])
	}
	return r.ID + ":" + hex.EncodeToString(h.Sum(nil))[:16]
}

// Poll runs every rule once over the window since the previous poll (with
// overlap for late-arriving rows) and returns findings not reported before.
func (e *Engine) Poll(ctx context.Context) ([]Finding, error) {
	tables, err := e.Tables(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	e.mu.Lock()
	since := e.since
	e.mu.Unlock()
	if since.IsZero() || now.Sub(since) > e.opt.Lookback {
		since = now.Add(-e.opt.Lookback)
	}
	// Look In publishes within ~20s and each VM's newest reading can be a
	// minute old: re-read a margin and rely on de-duplication.
	window := since.Add(-5 * time.Minute).Format("2006-01-02 15:04:05")
	lit := "TIMESTAMPTZ '" + window + "+00'"

	var out []Finding
	ok := true
	for _, r := range e.rules {
		missing := ""
		for _, t := range r.Tables {
			if !tables[t] {
				missing = t
			}
		}
		if missing != "" {
			slog.Debug("look rule skipped, table not present yet", "rule", r.ID, "table", missing)
			continue
		}
		rows, err := e.query(ctx, tables, strings.ReplaceAll(r.SQL, "{since}", lit))
		if err != nil {
			slog.Warn("look rule failed", "rule", r.ID, "err", err)
			ok = false
			continue
		}
		for _, row := range rows {
			k := rowKey(r, row)
			e.mu.Lock()
			_, dup := e.seen[k]
			if !dup {
				e.seen[k] = now
			}
			e.mu.Unlock()
			if !dup {
				out = append(out, Finding{Rule: r, Key: k, Row: row})
			}
		}
	}
	e.mu.Lock()
	if ok {
		e.since = now
	}
	for k, t := range e.seen {
		if now.Sub(t) > 8*24*time.Hour {
			delete(e.seen, k)
		}
	}
	e.mu.Unlock()
	e.save()
	return out, nil
}

type state struct {
	Since time.Time            `json:"since"`
	Seen  map[string]time.Time `json:"seen"`
}

func (e *Engine) statePath() string { return filepath.Join(e.opt.StateDir, "look-state.json") }

func (e *Engine) load() {
	if e.opt.Ephemeral {
		return
	}
	b, err := os.ReadFile(e.statePath())
	if err != nil {
		return
	}
	var s state
	if json.Unmarshal(b, &s) == nil {
		e.since = s.Since
		if s.Seen != nil {
			e.seen = s.Seen
		}
	}
}

func (e *Engine) save() {
	if e.opt.Ephemeral {
		return
	}
	e.mu.Lock()
	b, _ := json.Marshal(state{Since: e.since, Seen: e.seen})
	e.mu.Unlock()
	if err := os.MkdirAll(e.opt.StateDir, 0o750); err != nil {
		return
	}
	tmp := e.statePath() + ".tmp"
	if os.WriteFile(tmp, b, 0o640) == nil {
		os.Rename(tmp, e.statePath())
	}
}
