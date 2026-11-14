package rules

import (
	"testing"

	"github.com/exedev/warden/internal/event"
)

func TestEval(t *testing.T) {
	rs, err := Parse([]byte(`
- id: T-1
  title: t
  severity: high
  event: exec
  match:
    all:
      - {field: exec.stdin_socket, eq: true}
      - {field: ancestors.name, in: [nginx, php-fpm]}
      - not: {field: proc.name, prefix: [safe]}
      - {field: uid, lt: 1000}
- id: T-2
  title: t
  severity: low
  event: connect
  match:
    any:
      - {field: net.daddr, cidr: [10.0.0.0/8]}
      - {field: net.dport, in: [3333]}
`))
	if err != nil {
		t.Fatal(err)
	}
	en := NewEngine([][]*Rule{rs}, nil)

	ev := &event.Event{Type: "exec", UID: 33, Fields: map[string]any{
		"exec.stdin_socket": true,
		"ancestors.name":    []string{"bash", "php-fpm", "systemd"},
		"proc.name":         "sh",
	}}
	if got := en.Match(ev); len(got) != 1 || got[0].ID != "T-1" {
		t.Fatalf("exec: got %v", got)
	}
	ev.Fields["proc.name"] = "safe-tool"
	if got := en.Match(ev); len(got) != 0 {
		t.Fatalf("not-prefix should suppress, got %v", got)
	}

	c := &event.Event{Type: "connect", Fields: map[string]any{"net.daddr": "10.1.2.3", "net.dport": 443}}
	if len(en.Match(c)) != 1 {
		t.Fatal("cidr should match")
	}
	c.Fields["net.daddr"], c.Fields["net.dport"] = "8.8.8.8", 3333
	if len(en.Match(c)) != 1 {
		t.Fatal("numeric in should match int field against yaml int")
	}
	c.Fields["net.dport"] = 443
	if len(en.Match(c)) != 0 {
		t.Fatal("should not match")
	}
}

func TestOverrideAndDisable(t *testing.T) {
	a, _ := Parse([]byte("- {id: X, title: a, severity: low, event: exec, match: {field: uid, eq: 0}}\n- {id: Y, title: y, severity: low, event: exec, match: {field: uid, eq: 0}}"))
	b, _ := Parse([]byte("- {id: X, title: b, severity: high, event: exec, match: {field: uid, eq: 0}}"))
	en := NewEngine([][]*Rule{a, b}, map[string]bool{"Y": true})
	if len(en.Rules) != 1 || en.Rules[0].Title != "b" {
		t.Fatalf("override/disable failed: %+v", en.Rules)
	}
}

func TestParseRejectsBadSeverity(t *testing.T) {
	if _, err := Parse([]byte("- {id: Z, title: z, severity: nope, event: exec, match: {field: uid, eq: 0}}")); err == nil {
		t.Fatal("expected severity error")
	}
}
