// Package hunt runs short, passive, time-boxed analytics over the live event
// stream when Edgewatch asks for a follow-up on a VM that exe.dev's Look In
// telemetry flagged. A hunt only observes events that happen after it starts,
// and only the modes below exist: the task cannot name a command, path or rule.
package hunt

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/exedev/warden/internal/event"
)

const (
	MinSeconds = 60
	MaxSeconds = 900
	MaxActive  = 3
	maxKeys    = 500 // distinct aggregation keys per hunt, so a flood can't grow memory
	maxLines   = 40
	maxLine    = 200
)

// Modes is the closed set of hunts. Edgewatch picks one per Look observation.
var Modes = map[string]string{
	"net":    "network: outbound destinations, listeners, accepted connections, DNS names",
	"exec":   "processes: executables and arguments started, with temp/memfd/deleted/socket-stdio flags",
	"access": "access: privilege changes, sensitive file opens, shell commands, ptrace, modules, BPF loads",
}

// Report is what a finished hunt posts back. Lines are plain, bounded text.
type Report struct {
	TaskID  string    `json:"task_id"`
	Mode    string    `json:"mode"`
	Started time.Time `json:"started"`
	Ended   time.Time `json:"ended"`
	Events  int       `json:"events"`
	Notable int       `json:"notable"`
	Lines   []string  `json:"lines"`
}

type Task struct {
	ID      string `json:"id"`
	Mode    string `json:"mode"`
	Seconds int    `json:"seconds"`
}

// Clamp returns a valid task or an error. Unknown modes are rejected.
func (t Task) Clamp() (Task, error) {
	if _, ok := Modes[t.Mode]; !ok {
		return t, fmt.Errorf("unknown hunt mode %q", t.Mode)
	}
	if t.ID == "" || len(t.ID) > 64 {
		return t, fmt.Errorf("invalid task id")
	}
	t.Seconds = max(MinSeconds, min(MaxSeconds, t.Seconds))
	return t, nil
}

type counter struct {
	n   map[string]int
	cap int
}

func newCounter() *counter { return &counter{n: map[string]int{}, cap: maxKeys} }
func (c *counter) add(k string) {
	if _, ok := c.n[k]; ok || len(c.n) < c.cap {
		c.n[k]++
	}
}
func (c *counter) top(n int) []string {
	keys := make([]string, 0, len(c.n))
	for k := range c.n {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if c.n[keys[i]] != c.n[keys[j]] {
			return c.n[keys[i]] > c.n[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = fmt.Sprintf("%dx %s", c.n[k], k)
	}
	return out
}

// Hunt aggregates one mode's events. It is not safe for concurrent use; the
// Manager serializes calls.
type Hunt struct {
	Task    Task
	started time.Time
	events  int
	notable int
	// groups of aggregated lines, in report order
	groups  []string
	counts  map[string]*counter
	flagged *counter
}

func New(t Task, now time.Time) *Hunt {
	h := &Hunt{Task: t, started: now, counts: map[string]*counter{}, flagged: newCounter()}
	for _, g := range groupsFor(t.Mode) {
		h.groups = append(h.groups, g)
		h.counts[g] = newCounter()
	}
	return h
}

func groupsFor(mode string) []string {
	switch mode {
	case "net":
		return []string{"outbound (public)", "outbound (private)", "listening", "accepted from", "dns names"}
	case "exec":
		return []string{"executed"}
	}
	return []string{"privilege changes", "files opened", "shell commands", "ptrace / modules / bpf"}
}

func str(e *event.Event, k string) string {
	v, _ := e.Fields[k].(string)
	return v
}
func flag(e *event.Event, k string) bool { v, _ := e.Fields[k].(bool); return v }
func num(e *event.Event, k string) int   { v, _ := e.Fields[k].(int); return v }

func clip(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > n {
		s = strings.ToValidUTF8(s[:n], "") + "…"
	}
	return s
}

// A destination port outside this set, on a public address, is worth a line in
// the report. It is a pointer for the human, not a verdict.
var commonPorts = map[int]bool{22: true, 53: true, 80: true, 123: true, 443: true}

func (h *Hunt) note(group, line string, notable bool) {
	h.counts[group].add(clip(line, maxLine))
	if notable {
		h.notable++
		h.flagged.add(clip(group+": "+line, maxLine))
	}
}

// Observe feeds one event. Events of other modes are ignored.
func (h *Hunt) Observe(e *event.Event) {
	switch h.Task.Mode {
	case "net":
		h.observeNet(e)
	case "exec":
		h.observeExec(e)
	case "access":
		h.observeAccess(e)
	}
}

func (h *Hunt) observeNet(e *event.Event) {
	switch e.Type {
	case "connect":
		h.events++
		dst := fmt.Sprintf("%s:%d", str(e, "net.daddr"), num(e, "net.dport"))
		line := e.Comm + " → " + dst
		if flag(e, "net.daddr_private") {
			h.note("outbound (private)", line, false)
		} else {
			h.note("outbound (public)", line, !commonPorts[num(e, "net.dport")])
		}
	case "listen":
		h.events++
		h.note("listening", fmt.Sprintf("%s on %s:%d", e.Comm, str(e, "net.laddr"), num(e, "net.lport")), true)
	case "accept":
		h.events++
		h.note("accepted from", fmt.Sprintf("%s → %s (local port %d)", str(e, "net.daddr"), e.Comm, num(e, "net.sport")), false)
	case "dns":
		h.events++
		q := str(e, "dns.query")
		h.note("dns names", q, longLabel(q))
	}
}

func longLabel(q string) bool {
	for _, l := range strings.Split(q, ".") {
		if len(l) > 50 {
			return true
		}
	}
	return false
}

func (h *Hunt) observeExec(e *event.Event) {
	if e.Type != "exec" {
		return
	}
	h.events++
	var flags []string
	for _, f := range []struct{ k, n string }{{"exec.tmp_path", "tmp"}, {"exec.memfd", "memfd"}, {"exec.deleted", "deleted"}, {"exec.stdin_socket", "socket-stdio"}, {"exec.blocklisted", "blocklisted"}} {
		if flag(e, f.k) {
			flags = append(flags, f.n)
		}
	}
	line := fmt.Sprintf("%s %s", str(e, "exec.filename"), str(e, "exec.args"))
	if len(flags) > 0 {
		line += " [" + strings.Join(flags, ",") + "]"
	}
	h.note("executed", line, len(flags) > 0)
}

var sensitive = []string{"/etc/shadow", "/etc/sudoers", "/root/.ssh", "authorized_keys", "/.aws/", "/.kube/", "/etc/ld.so.preload"}

func (h *Hunt) observeAccess(e *event.Event) {
	switch e.Type {
	case "creds":
		h.events++
		h.note("privilege changes", fmt.Sprintf("%s uid %d→%d euid %d→%d", e.Comm, num32(e, "creds.old_uid"), num32(e, "creds.new_uid"), num32(e, "creds.old_euid"), num32(e, "creds.new_euid")), flag(e, "creds.gained_root"))
	case "file":
		h.events++
		p := str(e, "file.path")
		mode := "read"
		if flag(e, "file.write") {
			mode = "write"
		}
		hit := false
		for _, s := range sensitive {
			hit = hit || strings.Contains(p, s)
		}
		h.note("files opened", fmt.Sprintf("%s %s %s", e.Comm, mode, p), hit && mode == "write")
	case "shell_cmd":
		h.events++
		h.note("shell commands", str(e, "shell.line"), false)
	case "ptrace":
		h.events++
		h.note("ptrace / modules / bpf", fmt.Sprintf("ptrace by %s on %s", e.Comm, str(e, "target.comm")), true)
	case "module":
		h.events++
		h.note("ptrace / modules / bpf", "kernel module "+str(e, "module.name"), true)
	case "bpf":
		h.events++
		h.note("ptrace / modules / bpf", fmt.Sprintf("bpf %s load by %s", str(e, "bpf.prog_type"), e.Comm), true)
	}
}

func num32(e *event.Event, k string) uint32 { v, _ := e.Fields[k].(uint32); return v }

// Report summarizes everything seen so far.
func (h *Hunt) Report(now time.Time) Report {
	r := Report{TaskID: h.Task.ID, Mode: h.Task.Mode, Started: h.started, Ended: now, Events: h.events, Notable: h.notable}
	r.Lines = append(r.Lines, fmt.Sprintf("hunt %q for %s: %d events observed, %d notable (events before the hunt started are not visible)", h.Task.Mode, now.Sub(h.started).Round(time.Second), h.events, h.notable))
	if top := h.flagged.top(8); len(top) > 0 {
		r.Lines = append(r.Lines, "NOTABLE:")
		for _, l := range top {
			r.Lines = append(r.Lines, "  "+l)
		}
	}
	for _, g := range h.groups {
		if top := h.counts[g].top(6); len(top) > 0 {
			r.Lines = append(r.Lines, g+":")
			for _, l := range top {
				r.Lines = append(r.Lines, "  "+l)
			}
		}
	}
	if len(r.Lines) > maxLines {
		r.Lines = r.Lines[:maxLines]
	}
	return r
}

// Manager routes events to active hunts and finishes them on their deadline.
type Manager struct {
	mu     sync.Mutex
	active map[string]*running
	Done   func(Report)
}
type running struct {
	h        *Hunt
	deadline time.Time
}

func NewManager(done func(Report)) *Manager {
	return &Manager{active: map[string]*running{}, Done: done}
}

// Start registers a hunt. It reports false when the task is already running or
// too many hunts are active.
func (m *Manager) Start(t Task, now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.active[t.ID]; dup || len(m.active) >= MaxActive {
		return false
	}
	m.active[t.ID] = &running{h: New(t, now), deadline: now.Add(time.Duration(t.Seconds) * time.Second)}
	return true
}

// Observe is called for every event; it is a no-op when no hunt is active.
func (m *Manager) Observe(e *event.Event) {
	m.mu.Lock()
	for _, r := range m.active {
		r.h.Observe(e)
	}
	m.mu.Unlock()
}

// Finish ends every hunt whose deadline passed and hands its report to Done.
func (m *Manager) Finish(now time.Time) {
	m.mu.Lock()
	var done []Report
	for id, r := range m.active {
		if !now.Before(r.deadline) {
			done = append(done, r.h.Report(now))
			delete(m.active, id)
		}
	}
	m.mu.Unlock()
	for _, r := range done {
		m.Done(r)
	}
}

func (m *Manager) Active() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.active) }
