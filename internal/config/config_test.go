package config

import (
	"testing"

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
