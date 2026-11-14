package hunt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/exedev/warden/internal/event"
)

func ev(typ, comm string, f map[string]any) *event.Event {
	return &event.Event{Type: typ, Comm: comm, Fields: f}
}

func TestClamp(t *testing.T) {
	if _, err := (Task{ID: "a", Mode: "rm -rf /", Seconds: 60}).Clamp(); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
	if _, err := (Task{Mode: "net", Seconds: 60}).Clamp(); err == nil {
		t.Fatal("missing id must be rejected")
	}
	for in, want := range map[int]int{-5: MinSeconds, 10: MinSeconds, 300: 300, 99999: MaxSeconds} {
		got, err := (Task{ID: "a", Mode: "exec", Seconds: in}).Clamp()
		if err != nil || got.Seconds != want {
			t.Fatalf("seconds %d → %d, %v", in, got.Seconds, err)
		}
	}
}

func TestNetHunt(t *testing.T) {
	h := New(Task{ID: "t", Mode: "net", Seconds: 60}, time.Now())
	pub := func(ip string, port int) *event.Event {
		return ev("connect", "curl", map[string]any{"net.daddr": ip, "net.dport": port, "net.daddr_private": false})
	}
	for range 5 {
		h.Observe(pub("203.0.113.9", 443)) // common port: counted, not notable
	}
	h.Observe(pub("203.0.113.66", 4444))
	h.Observe(ev("connect", "app", map[string]any{"net.daddr": "10.0.0.2", "net.dport": 5432, "net.daddr_private": true}))
	h.Observe(ev("listen", "nc", map[string]any{"net.laddr": "0.0.0.0", "net.lport": 9001}))
	h.Observe(ev("dns", "curl", map[string]any{"dns.query": strings.Repeat("a", 60) + ".evil.example"}))
	h.Observe(ev("exec", "sh", map[string]any{"exec.args": "ignored in net mode"}))
	r := h.Report(time.Now().Add(time.Minute))
	if r.Events != 9 || r.Notable != 3 {
		t.Fatalf("events=%d notable=%d\n%s", r.Events, r.Notable, strings.Join(r.Lines, "\n"))
	}
	text := strings.Join(r.Lines, "\n")
	for _, want := range []string{"NOTABLE:", "203.0.113.66:4444", "nc on 0.0.0.0:9001", "5x curl → 203.0.113.9:443"} {
		if !strings.Contains(text, want) {
			t.Errorf("report missing %q:\n%s", want, text)
		}
	}
}

func TestExecAndAccessHunts(t *testing.T) {
	h := New(Task{ID: "t", Mode: "exec", Seconds: 60}, time.Now())
	h.Observe(ev("exec", "ls", map[string]any{"exec.filename": "/bin/ls", "exec.args": "ls -l"}))
	h.Observe(ev("exec", "x", map[string]any{"exec.filename": "/tmp/x", "exec.args": "x\x1b[31m", "exec.tmp_path": true}))
	r := h.Report(time.Now())
	if r.Events != 2 || r.Notable != 1 || strings.ContainsAny(strings.Join(r.Lines, ""), "\x1b") {
		t.Fatalf("%+v", r)
	}
	a := New(Task{ID: "t", Mode: "access", Seconds: 60}, time.Now())
	a.Observe(ev("creds", "sudo", map[string]any{"creds.gained_root": true, "creds.old_uid": uint32(1000), "creds.new_uid": uint32(0)}))
	a.Observe(ev("file", "vi", map[string]any{"file.path": "/home/u/notes", "file.write": true}))
	a.Observe(ev("file", "vi", map[string]any{"file.path": "/root/.ssh/authorized_keys", "file.write": true}))
	a.Observe(ev("module", "insmod", map[string]any{"module.name": "rootkit"}))
	if r := a.Report(time.Now()); r.Notable != 3 {
		t.Fatalf("notable=%d %v", r.Notable, r.Lines)
	}
}

func TestBounds(t *testing.T) {
	h := New(Task{ID: "t", Mode: "exec", Seconds: 60}, time.Now())
	for i := range 5000 {
		h.Observe(ev("exec", "p", map[string]any{"exec.filename": "/bin/p", "exec.args": strings.Repeat("x", 50) + string(rune('a'+i%26)) + strings.Repeat("y", i%900)}))
	}
	if n := len(h.counts["executed"].n); n > maxKeys {
		t.Fatalf("keys %d", n)
	}
	r := h.Report(time.Now())
	if len(r.Lines) > maxLines {
		t.Fatalf("lines %d", len(r.Lines))
	}
	for _, l := range r.Lines {
		if len(l) > maxLine+16 {
			t.Fatalf("line length %d", len(l))
		}
	}
}

func TestManagerLimitsAndFinish(t *testing.T) {
	var mu sync.Mutex
	var got []Report
	m := NewManager(func(r Report) { mu.Lock(); got = append(got, r); mu.Unlock() })
	now := time.Now()
	for i := range MaxActive + 2 {
		ok := m.Start(Task{ID: string(rune('a' + i)), Mode: "exec", Seconds: 60}, now)
		if ok != (i < MaxActive) {
			t.Fatalf("start %d = %v", i, ok)
		}
	}
	if m.Start(Task{ID: "a", Mode: "exec", Seconds: 60}, now) {
		t.Fatal("duplicate task started")
	}
	m.Observe(ev("exec", "p", map[string]any{"exec.filename": "/bin/p"}))
	m.Finish(now.Add(30 * time.Second))
	if len(got) != 0 {
		t.Fatal("finished early")
	}
	m.Finish(now.Add(61 * time.Second))
	if len(got) != MaxActive || m.Active() != 0 || got[0].Events != 1 {
		t.Fatalf("%d reports, %d active", len(got), m.Active())
	}
}

func TestClientPollsAndReports(t *testing.T) {
	var mu sync.Mutex
	var posted []Report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "no", 401)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/api/ingest/warden/tasks":
			json.NewEncoder(w).Encode(map[string]any{"tasks": []Task{{ID: "ok1", Mode: "net", Seconds: 5}, {ID: "bad", Mode: "shell", Seconds: 60}}})
		case r.Method == "POST" && r.URL.Path == "/api/ingest/warden/tasks/ok1/result":
			var rep Report
			json.NewDecoder(r.Body).Decode(&rep)
			mu.Lock()
			posted = append(posted, rep)
			mu.Unlock()
			w.WriteHeader(202)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := NewClient(srv.URL+"/api/ingest/warden", "tok")
	now := time.Now()
	if err := c.Poll(now); err != nil {
		t.Fatal(err)
	}
	if c.Mgr.Active() != 1 {
		t.Fatalf("active=%d (unknown mode must be ignored, seconds clamped)", c.Mgr.Active())
	}
	c.Mgr.Observe(ev("connect", "curl", map[string]any{"net.daddr": "203.0.113.1", "net.dport": 443}))
	c.Mgr.Finish(now.Add(MinSeconds*time.Second + time.Second))
	mu.Lock()
	defer mu.Unlock()
	if len(posted) != 1 || posted[0].TaskID != "ok1" || posted[0].Events != 1 {
		t.Fatalf("%+v", posted)
	}
	if err := NewClient(srv.URL+"/api/ingest/warden", "wrong").Poll(now); err == nil {
		t.Fatal("bad token must fail")
	}
}
