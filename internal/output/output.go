// Package output renders alerts and telemetry to stdout, files and webhooks.
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/exedev/warden/internal/event"
	"github.com/exedev/warden/internal/rules"
)

var SeverityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

type Alert struct {
	Time       time.Time      `json:"time"`
	Host       string         `json:"host"`
	Rule       *rules.Rule    `json:"rule"`
	Action     string         `json:"action"`
	Tree       string         `json:"process_tree"`
	SHA256     string         `json:"sha256,omitempty"`
	Suppressed int            `json:"suppressed_since_last,omitempty"`
	Event      *event.Event   `json:"event"`
	Extra      map[string]any `json:"extra,omitempty"`
}

type Options struct {
	Format      string
	AlertsFile  string
	EventsFile  string
	Webhook     string
	MinSeverity string
	Throttle    time.Duration
}

type Writer struct {
	opt     Options
	stdout  io.Writer
	alerts  *os.File
	events  *os.File
	hook    chan []byte
	mu      sync.Mutex
	last    map[string]time.Time
	dropped map[string]int
}

func New(opt Options) (*Writer, error) {
	w := &Writer{opt: opt, stdout: os.Stdout, last: map[string]time.Time{}, dropped: map[string]int{}}
	var err error
	if w.alerts, err = openAppend(opt.AlertsFile); err != nil {
		return nil, err
	}
	if w.events, err = openAppend(opt.EventsFile); err != nil {
		return nil, err
	}
	if opt.Webhook != "" {
		w.hook = make(chan []byte, 1024)
		go w.webhookLoop()
	}
	return w, nil
}

func openAppend(p string) (*os.File, error) {
	if p == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return nil, err
	}
	return os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
}

func (w *Writer) Event(e *event.Event) {
	if w.events == nil {
		return
	}
	b, _ := json.Marshal(e)
	w.mu.Lock()
	w.events.Write(append(b, '\n'))
	w.mu.Unlock()
}

// throttleKey groups repeats of the same rule on the same program and object.
func throttleKey(a *Alert) string {
	f := a.Event.Fields
	obj := ""
	for _, k := range []string{"look.key", "file.path", "net.daddr", "dns.query", "target.comm", "module.name"} {
		if v, ok := f[k]; ok {
			obj = fmt.Sprint(v)
			break
		}
	}
	return a.Rule.ID + "|" + fmt.Sprint(f["proc.exe"]) + "|" + obj
}

// Alert emits a unless it is below min severity or throttled. Returns
// whether it was emitted.
func (w *Writer) Alert(a *Alert) bool {
	if SeverityRank[a.Rule.Severity] < SeverityRank[w.opt.MinSeverity] {
		return false
	}
	w.mu.Lock()
	k := throttleKey(a)
	if t, ok := w.last[k]; ok && w.opt.Throttle > 0 && a.Time.Sub(t) < w.opt.Throttle {
		w.dropped[k]++
		w.mu.Unlock()
		return false
	}
	w.last[k] = a.Time
	a.Suppressed = w.dropped[k]
	delete(w.dropped, k)
	w.mu.Unlock()

	b, _ := json.Marshal(a)
	w.mu.Lock()
	if w.opt.Format == "json" {
		w.stdout.Write(append(b, '\n'))
	} else {
		w.text(a)
	}
	if w.alerts != nil {
		w.alerts.Write(append(b, '\n'))
	}
	w.mu.Unlock()
	if w.hook != nil {
		select {
		case w.hook <- b:
		default:
			slog.Warn("webhook queue full, dropping alert", "rule", a.Rule.ID)
		}
	}
	return true
}

var sevColor = map[string]string{"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}

func (w *Writer) text(a *Alert) {
	f := a.Event.Fields
	fmt.Fprintf(w.stdout, "%s %s%-8s\033[0m %s %s  [%s]\n", a.Time.Format("15:04:05"), sevColor[a.Rule.Severity],
		strings.ToUpper(a.Rule.Severity), a.Rule.ID, a.Rule.Title, a.Rule.MITRE)
	if a.Tree != "" {
		fmt.Fprintf(w.stdout, "    tree: %s\n", a.Tree)
	}
	if a.Event.TGID != 0 {
		fmt.Fprintf(w.stdout, "    proc: pid=%d uid=%d exe=%v cmd=%q", a.Event.TGID, a.Event.UID, f["proc.exe"], f["proc.cmdline"])
		if c, _ := f["container"].(string); c != "" {
			fmt.Fprintf(w.stdout, " container=%s", c)
		}
		fmt.Fprintln(w.stdout)
	}
	var keys []string
	for k := range f {
		if strings.HasPrefix(k, "proc.") || strings.HasPrefix(k, "parent.") || strings.HasPrefix(k, "ancestors.") ||
			k == "process_tree" || k == "container" || k == "cgroup_id" || k == "mntns" || k == "gid" || k == "exec.argv" || k == "look.key" {
			continue
		}
		if b, ok := f[k].(bool); ok && !b {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%v", k, f[k]))
	}
	if len(parts) > 0 {
		fmt.Fprintf(w.stdout, "    data: %s\n", strings.Join(parts, " "))
	}
	if a.SHA256 != "" {
		fmt.Fprintf(w.stdout, "    sha256: %s\n", a.SHA256)
	}
	if a.Action != "alert" {
		fmt.Fprintf(w.stdout, "    \033[1;35maction: %s\033[0m\n", a.Action)
	}
	if a.Suppressed > 0 {
		fmt.Fprintf(w.stdout, "    (%d similar suppressed)\n", a.Suppressed)
	}
}

func (w *Writer) webhookLoop() {
	cl := &http.Client{Timeout: 10 * time.Second}
	for b := range w.hook {
		for attempt := 0; attempt < 3; attempt++ {
			resp, err := cl.Post(w.opt.Webhook, "application/json", bytes.NewReader(b))
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode < 300 {
					break
				}
				err = fmt.Errorf("status %s", resp.Status)
			}
			slog.Warn("webhook post failed", "err", err, "attempt", attempt+1)
			time.Sleep(time.Duration(attempt+1) * time.Second)
		}
	}
}
