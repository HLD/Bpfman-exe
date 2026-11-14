// Command warden is an eBPF host detection & response agent.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	"github.com/exedev/warden/internal/config"
	"github.com/exedev/warden/internal/event"
	"github.com/exedev/warden/internal/look"
	"github.com/exedev/warden/internal/output"
	"github.com/exedev/warden/internal/proc"
	"github.com/exedev/warden/internal/rules"
	"github.com/exedev/warden/internal/sensor"
)

const usage = `warden - eBPF host detection & response

usage:
  warden run   [-config warden.yaml] [-events] [-json]   start the agent
  warden caps  [-config warden.yaml]                     report what this kernel supports
  warden rules [-config warden.yaml]                     list active detection rules
  warden look  [-config warden.yaml] [-since 24h]        run exe.dev Look In detections once
  warden defaults                                        print the default config
`

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	cfgPath := fs.String("config", "", "config file (default: built-in)")
	allEvents := fs.Bool("events", false, "print every telemetry event to stdout as JSON")
	jsonOut := fs.Bool("json", false, "print alerts as JSON")
	since := fs.Duration("since", 24*time.Hour, "look: window to examine")
	fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(err)
	}
	switch cmd {
	case "run":
		if *jsonOut {
			cfg.Output.Format = "json"
		}
		fatal(run(cfg, *allEvents))
	case "caps":
		fatal(caps(cfg))
	case "rules":
		en, err := engine(cfg)
		if err != nil {
			fatal(err)
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tSEVERITY\tEVENT\tMITRE\tACTION\tTITLE")
		for _, r := range en.Rules {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, strings.Join(r.Events, ","), r.MITRE, r.Action, r.Title)
		}
		if le, err := lookEngine(cfg, look.Options{Ephemeral: true}); err == nil {
			for _, r := range le.Rules() {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Severity, "look:"+strings.Join(r.Tables, ","), r.MITRE, "alert", r.Title)
			}
		}
		tw.Flush()
	case "look":
		if *jsonOut {
			cfg.Output.Format = "json"
		}
		fatal(lookOnce(cfg, *since))
	case "defaults":
		os.Stdout.Write(config.DefaultYAML)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func fatal(err error) {
	if err != nil {
		slog.Error(err.Error())
		os.Exit(1)
	}
}

func engine(cfg *config.Config) (*rules.Engine, error) {
	base, err := rules.Parse(config.DefaultRules)
	if err != nil {
		return nil, fmt.Errorf("built-in rules: %w", err)
	}
	sets := [][]*rules.Rule{base}
	for _, f := range cfg.RulesFiles {
		rs, err := rules.ParseFile(f)
		if err != nil {
			return nil, err
		}
		sets = append(sets, rs)
	}
	return rules.NewEngine(sets, config.Set(cfg.DisableRules)), nil
}

func policy(cfg *config.Config) sensor.Policy {
	p := cfg.Prevention
	return sensor.Policy{
		KillMemfdExec:    p.KillMemfdExec,
		KillRevShell:     p.KillReverseShell,
		KillTmpExec:      p.KillTmpExec,
		KillDeletedExec:  p.KillDeletedExec,
		KillBlocklisted:  p.KillBlocklisted,
		WatchRead:        cfg.Watch.Read,
		WatchWrite:       cfg.Watch.Write,
		WatchNamesRead:   cfg.Watch.NamesRead,
		WatchNamesWrite:  cfg.Watch.NamesWrite,
		Shells:           cfg.Shells,
		BlockedExecPaths: p.BlockedExecPaths,
		BlockedCIDRs:     p.BlockedCIDRs,
		BlockedPorts:     p.BlockedPorts,
	}
}

func printStatus(s *sensor.Sensor) (ok, total int) {
	tw := tabwriter.NewWriter(os.Stderr, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PROBE\tKIND\tHOOK\tSTATUS")
	for _, st := range s.Status {
		status := "\033[32mattached\033[0m"
		if !st.OK {
			status = "\033[31mFAILED\033[0m " + st.Err
		} else {
			ok++
		}
		total++
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", st.Prog, st.Category, st.Hook, status)
	}
	tw.Flush()
	return ok, total
}

var procPathRe = regexp.MustCompile(`^/proc/([0-9]+)/`)

// systemResolvers returns nameservers from the host's resolver configs.
func systemResolvers() map[string]bool {
	m := map[string]bool{}
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			if fs := strings.Fields(line); len(fs) >= 2 && fs[0] == "nameserver" {
				m[fs[1]] = true
			}
		}
	}
	return m
}

var resolvers atomic.Pointer[map[string]bool]

func refreshResolvers() {
	m := systemResolvers()
	resolvers.Store(&m)
}

func enrich(e *event.Event) {
	if srv, ok := e.Fields["dns.server"].(string); ok {
		e.Set("dns.server_system", (*resolvers.Load())[srv])
	}
	if p, ok := e.Fields["file.path"].(string); ok {
		if m := procPathRe.FindStringSubmatch(p); m != nil {
			n, _ := strconv.ParseUint(m[1], 10, 32)
			e.Set("file.foreign_proc", uint32(n) != e.TGID)
		}
	}
}

func run(cfg *config.Config, allEvents bool) error {
	if os.Geteuid() != 0 {
		return errors.New("warden must run as root")
	}
	en, err := engine(cfg)
	if err != nil {
		return err
	}
	s, err := sensor.Load(config.Set(cfg.DisableProbes))
	if err != nil {
		return err
	}
	defer s.Close()
	ok, total := printStatus(s)
	if err := s.Apply(policy(cfg)); err != nil {
		return err
	}
	out, err := output.New(output.Options{
		Format: cfg.Output.Format, AlertsFile: cfg.Output.AlertsFile, EventsFile: cfg.Output.EventsFile,
		Webhook: cfg.Output.Webhook, MinSeverity: cfg.Output.MinSeverity, Throttle: cfg.Output.Throttle,
	})
	if err != nil {
		return err
	}
	refreshResolvers()
	procs := proc.NewTable()
	host, _ := os.Hostname()
	self := uint32(os.Getpid())
	if le, err := lookEngine(cfg, look.Options{}); err != nil {
		if cfg.Look.Enabled == "true" {
			return fmt.Errorf("look: %w", err)
		}
		slog.Info("look detections off", "reason", err)
	} else {
		slog.Info("look detections on", "rules", len(le.Rules()), "interval", cfg.Look.Interval)
		go lookLoop(le, cfg.Look.Interval, out, host)
	}
	slog.Info("warden running", "probes", fmt.Sprintf("%d/%d", ok, total), "rules", len(en.Rules), "pid", self,
		"kill_revshell", cfg.Prevention.KillReverseShell, "rule_kill", cfg.Prevention.AllowRuleKill)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		slog.Info("shutting down")
		s.Close()
	}()

	var nEvents, nAlerts uint64
	go func() {
		for range time.Tick(time.Minute) {
			refreshResolvers()
		}
	}()
	go func() {
		for range time.Tick(5 * time.Minute) {
			slog.Info("stats", "events", nEvents, "alerts", nAlerts)
		}
	}()

	for {
		raw, err := s.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			slog.Warn("ringbuf read", "err", err)
			continue
		}
		e, err := sensor.Decode(raw)
		if err != nil {
			slog.Debug("decode", "err", err)
			continue
		}
		nEvents++
		procs.Observe(e)
		enrich(e)
		out.Event(e)
		if allEvents {
			b, _ := jsonLine(e)
			os.Stdout.Write(b)
		}

		for _, r := range en.Match(e) {
			a := &output.Alert{Time: e.Time, Host: host, Rule: r, Action: "alert", Event: e}
			a.Tree, _ = e.Fields["process_tree"].(string)
			if killed, _ := e.Fields["exec.killed"].(bool); killed {
				a.Action = "killed (in-kernel, before first instruction)"
			} else if e.Type == "net_block" {
				a.Action = "blocked (cgroup/connect)"
			} else if r.Action == "kill" {
				a.Action = respond(cfg, e, self)
			}
			if exe, _ := e.Fields["proc.exe"].(string); exe != "" && e.Type == "exec" {
				a.SHA256 = procs.Hash(e.TGID, exe)
			}
			if out.Alert(a) {
				nAlerts++
			}
		}
	}
}

func respond(cfg *config.Config, e *event.Event, self uint32) string {
	if !cfg.Prevention.AllowRuleKill {
		return "alert (kill suppressed: prevention.allow_rule_kill=false)"
	}
	if e.TGID <= 1 || e.TGID == self {
		return "alert (refusing to kill pid " + strconv.Itoa(int(e.TGID)) + ")"
	}
	if err := syscall.Kill(int(e.TGID), syscall.SIGKILL); err != nil {
		return "kill failed: " + err.Error()
	}
	return "killed (userspace SIGKILL)"
}

func kernelConfig() map[string]string {
	m := map[string]string{}
	f, err := os.Open("/proc/config.gz")
	if err != nil {
		return m
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return m
	}
	sc := bufio.NewScanner(gz)
	for sc.Scan() {
		line := sc.Text()
		if k, v, ok := strings.Cut(line, "="); ok && strings.HasPrefix(k, "CONFIG_") {
			m[k] = v
		} else if strings.HasPrefix(line, "# CONFIG_") && strings.HasSuffix(line, " is not set") {
			m[strings.Fields(line)[1]] = "n"
		}
	}
	return m
}

func caps(cfg *config.Config) error {
	var uts syscall.Utsname
	syscall.Uname(&uts)
	rel := func(a [65]int8) string {
		b := make([]byte, 0, 65)
		for _, c := range a {
			if c == 0 {
				break
			}
			b = append(b, byte(c))
		}
		return string(b)
	}
	kc := kernelConfig()
	lsm, _ := os.ReadFile("/sys/kernel/security/lsm")
	_, btfErr := os.Stat("/sys/kernel/btf/vmlinux")

	fmt.Printf("kernel        %s\n", rel(uts.Release))
	fmt.Printf("BTF           %v\n", btfErr == nil)
	fmt.Printf("active LSMs   %s\n", strings.TrimSpace(string(lsm)))
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "KERNEL CONFIG\tVALUE\tIMPACT")
	for _, c := range []struct{ k, impact string }{
		{"CONFIG_BPF_LSM", "BPF LSM: synchronous deny (-EPERM) of exec/open/connect. Missing => prevention uses SIGKILL at exec + cgroup hooks"},
		{"CONFIG_FUNCTION_ERROR_INJECTION", "bpf_override_return: alternative syscall deny. Missing => same as above"},
		{"CONFIG_FPROBE", "kprobe.multi: attach to many functions cheaply"},
		{"CONFIG_DEBUG_INFO_BTF", "CO-RE + fentry/fexit/tp_btf (required)"},
		{"CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS", "fentry/fexit trampolines (required)"},
		{"CONFIG_CGROUP_BPF", "cgroup connect deny (network prevention)"},
		{"CONFIG_UPROBES", "user-space probes (bash readline)"},
		{"CONFIG_FANOTIFY_ACCESS_PERMISSIONS", "fanotify permission events: an alternative exec/open deny path"},
		{"CONFIG_IMA", "file integrity measurement"},
	} {
		v := kc[c.k]
		if v == "" {
			v = "n"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", strings.TrimPrefix(c.k, "CONFIG_"), v, c.impact)
	}
	tw.Flush()
	fmt.Println()

	if os.Geteuid() != 0 {
		fmt.Println("(run as root to test-attach every probe)")
		return nil
	}
	s, err := sensor.Load(config.Set(cfg.DisableProbes))
	if err != nil {
		return err
	}
	defer s.Close()
	ok, total := printStatus(s)
	fmt.Fprintf(os.Stderr, "\n%d/%d probes attached\n", ok, total)
	return nil
}

func jsonLine(e *event.Event) ([]byte, error) {
	b, err := json.Marshal(e)
	return append(b, '\n'), err
}

// lookEngine builds the Look In detection engine, discovering the
// integration through reflection.
func lookEngine(cfg *config.Config, opt look.Options) (*look.Engine, error) {
	if cfg.Look.Enabled == "false" {
		return nil, errors.New("disabled in config")
	}
	base, err := look.ParseRules(config.DefaultLookRules)
	if err != nil {
		return nil, fmt.Errorf("built-in look rules: %w", err)
	}
	sets := [][]*look.Rule{base}
	for _, f := range cfg.Look.RulesFiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		rs, err := look.ParseRules(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		sets = append(sets, rs)
	}
	off := config.Set(cfg.Look.DisableRules)
	for _, set := range sets {
		for _, r := range set {
			if off[r.ID] {
				r.Disabled = true
			}
		}
	}
	duck := cfg.Look.DuckDB
	if duck == "" {
		if duck, err = exec.LookPath("duckdb"); err != nil {
			return nil, errors.New("duckdb CLI not found")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	endpoint, bucket, err := look.Discover(ctx)
	if err != nil {
		return nil, err
	}
	opt.Endpoint, opt.Bucket, opt.DuckDB = endpoint, bucket, duck
	opt.StateDir = cfg.Look.StateDir
	if opt.Lookback == 0 {
		opt.Lookback = cfg.Look.Lookback
	}
	return look.New(opt, sets...), nil
}

func lookAlert(f look.Finding, host string) *output.Alert {
	e := &event.Event{Time: time.Now().UTC(), Type: "look", Fields: map[string]any{"look.key": f.Key}}
	for k, v := range f.Row {
		e.Set("look."+k, v)
	}
	r := f.Rule
	return &output.Alert{
		Time: e.Time, Host: host, Action: "alert", Event: e,
		Rule: &rules.Rule{ID: r.ID, Title: r.Title, Description: r.Description, Severity: r.Severity, MITRE: r.MITRE},
	}
}

func lookLoop(le *look.Engine, every time.Duration, out *output.Writer, host string) {
	for {
		ctx, cancel := context.WithTimeout(context.Background(), every+5*time.Minute)
		fs, err := le.Poll(ctx)
		cancel()
		if err != nil {
			slog.Warn("look poll", "err", err)
		}
		for _, f := range fs {
			out.Alert(lookAlert(f, host))
		}
		time.Sleep(every)
	}
}

func lookOnce(cfg *config.Config, since time.Duration) error {
	if cfg.Look.Enabled == "false" {
		cfg.Look.Enabled = "true"
	}
	le, err := lookEngine(cfg, look.Options{Ephemeral: true, Lookback: since})
	if err != nil {
		return err
	}
	out, err := output.New(output.Options{Format: cfg.Output.Format, MinSeverity: "info"})
	if err != nil {
		return err
	}
	host, _ := os.Hostname()
	fs, err := le.Poll(context.Background())
	if err != nil {
		return err
	}
	for _, f := range fs {
		out.Alert(lookAlert(f, host))
	}
	slog.Info("look done", "findings", len(fs), "window", since)
	return nil
}
