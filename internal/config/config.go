// Package config loads warden.yaml and the built-in defaults.
package config

import (
	_ "embed"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

//go:embed defaults/warden.yaml
var DefaultYAML []byte

//go:embed defaults/rules.yaml
var DefaultRules []byte

//go:embed defaults/look-rules.yaml
var DefaultLookRules []byte

type Config struct {
	Output struct {
		Format      string        `yaml:"format"`
		AlertsFile  string        `yaml:"alerts_file"`
		EventsFile  string        `yaml:"events_file"`
		Webhook     string        `yaml:"webhook"`
		MinSeverity string        `yaml:"min_severity"`
		Throttle    time.Duration `yaml:"throttle"`
	} `yaml:"output"`
	RulesFiles    []string `yaml:"rules_files"`
	DisableRules  []string `yaml:"disable_rules"`
	DisableProbes []string `yaml:"disable_probes"`
	Prevention    struct {
		KillReverseShell bool     `yaml:"kill_reverse_shell"`
		KillMemfdExec    bool     `yaml:"kill_memfd_exec"`
		KillDeletedExec  bool     `yaml:"kill_deleted_exec"`
		KillTmpExec      bool     `yaml:"kill_tmp_exec"`
		KillBlocklisted  bool     `yaml:"kill_blocklisted_exec"`
		BlockedExecPaths []string `yaml:"blocked_exec_paths"`
		BlockedCIDRs     []string `yaml:"blocked_cidrs"`
		BlockedPorts     []uint16 `yaml:"blocked_ports"`
		AllowRuleKill    bool     `yaml:"allow_rule_kill"`
	} `yaml:"prevention"`
	Look struct {
		Enabled      string        `yaml:"enabled"` // auto | true | false
		Interval     time.Duration `yaml:"interval"`
		Lookback     time.Duration `yaml:"lookback"`
		DuckDB       string        `yaml:"duckdb"`
		StateDir     string        `yaml:"state_dir"`
		RulesFiles   []string      `yaml:"rules_files"`
		DisableRules []string      `yaml:"disable_rules"`
	} `yaml:"look"`
	Shells []string `yaml:"shells"`
	Watch  struct {
		Read       []string `yaml:"read"`
		Write      []string `yaml:"write"`
		NamesRead  []string `yaml:"names_read"`
		NamesWrite []string `yaml:"names_write"`
	} `yaml:"watch"`
}

// Load parses path, or the embedded defaults when path is empty.
func Load(path string) (*Config, error) {
	data := DefaultYAML
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		data = b
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.Output.Format == "" {
		c.Output.Format = "text"
	}
	if c.Look.Enabled == "" {
		c.Look.Enabled = "auto"
	}
	if c.Look.Interval == 0 {
		c.Look.Interval = 5 * time.Minute
	}
	if c.Look.Lookback == 0 {
		c.Look.Lookback = time.Hour
	}
	if c.Look.StateDir == "" {
		c.Look.StateDir = "/var/lib/warden"
	}
	if c.Output.MinSeverity == "" {
		c.Output.MinSeverity = "low"
	}
	return &c, nil
}

func Set(l []string) map[string]bool {
	m := map[string]bool{}
	for _, s := range l {
		m[s] = true
	}
	return m
}
