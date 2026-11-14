package config

import (
	"testing"

	"github.com/exedev/warden/internal/event"
	"github.com/exedev/warden/internal/rules"
)

func TestDefaults(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Watch.Read) == 0 || len(c.Shells) == 0 {
		t.Fatal("defaults missing watch/shells")
	}
	rs, err := rules.Parse(DefaultRules)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rs {
		if seen[r.ID] {
			t.Fatalf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
	}
}

// WD-023 allows systemd's generators to read PID 1's environment, and nothing broader.
func TestWD023SystemdGeneratorAllowlist(t *testing.T) {
	rs, err := rules.Parse(DefaultRules)
	if err != nil {
		t.Fatal(err)
	}
	en := rules.NewEngine([][]*rules.Rule{rs}, nil)
	read := func(path, exe, name string) *event.Event {
		return &event.Event{Type: "file", Fields: map[string]any{
			"file.path": path, "file.foreign_proc": true, "proc.exe": exe, "proc.name": name}}
	}
	fires := func(e *event.Event) bool {
		for _, r := range en.Match(e) {
			if r.ID == "WD-023" {
				return true
			}
		}
		return false
	}
	gen := "/usr/lib/systemd/system-generators/systemd-fstab-generator"
	for name, tc := range map[string]struct {
		ev   *event.Event
		want bool
	}{
		"generator reads PID 1 environ":             {read("/proc/1/environ", gen, "systemd-fstab-generator"), false},
		"user generator in /lib":                    {read("/proc/1/environ", "/lib/systemd/user-generators/x", "x"), false},
		"generator reads another process's environ": {read("/proc/2345/environ", gen, "systemd-fstab-generator"), true},
		"generator reads another process's memory":  {read("/proc/1/mem", gen, "systemd-fstab-generator"), true},
		"unrelated binary reads PID 1 environ":      {read("/proc/1/environ", "/usr/bin/python3", "python3"), true},
		"spoofed generator name in /tmp":            {read("/proc/1/environ", "/tmp/systemd-fstab-generator", "systemd-fstab-generator"), true},
		"path trick: lookalike directory":           {read("/proc/1/environ", "/usr/lib/systemd/system-generators-evil/x", "x"), true},
		"shell reads another process's environ":     {read("/proc/999/environ", "/usr/bin/bash", "bash"), true},
		"ps keeps its existing allowance":           {read("/proc/999/environ", "/usr/bin/ps", "ps"), false},
	} {
		if got := fires(tc.ev); got != tc.want {
			t.Errorf("%s: fired=%v, want %v", name, got, tc.want)
		}
	}
}
