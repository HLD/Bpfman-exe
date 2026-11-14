package sensor

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// Probe describes one kernel hook and how to attach it.
type Probe struct {
	Prog     string // program name in the object
	Category string // telemetry | prevention
	Hook     string
	Covers   string
	attach   func(*ebpf.Program) (link.Link, error)
}

// Status is the outcome of trying to load+attach one probe.
type Status struct {
	Probe
	OK  bool
	Err string
}

func tracing(p *ebpf.Program) (link.Link, error) {
	return link.AttachTracing(link.TracingOptions{Program: p})
}

func cgroup(attach ebpf.AttachType) func(*ebpf.Program) (link.Link, error) {
	return func(p *ebpf.Program) (link.Link, error) {
		return link.AttachCgroup(link.CgroupOptions{Path: "/sys/fs/cgroup", Attach: attach, Program: p})
	}
}

func uretprobe(bin, sym string) func(*ebpf.Program) (link.Link, error) {
	return func(p *ebpf.Program) (link.Link, error) {
		ex, err := link.OpenExecutable(bin)
		if err != nil {
			return nil, err
		}
		return ex.Uretprobe(sym, p, nil)
	}
}

var Probes = []Probe{
	{"on_exec", "telemetry", "tp_btf/sched_process_exec", "process exec, argv, socket-stdio, memfd/deleted/tmp exec; in-kernel kill policy", tracing},
	{"on_exit", "telemetry", "tp_btf/sched_process_exit", "process exit", tracing},
	{"on_file_open", "telemetry", "fentry/security_file_open", "watched file reads/writes (in-kernel path filter)", tracing},
	{"on_tcp_connect", "telemetry", "fentry/tcp_connect", "outbound TCP (v4/v6)", tracing},
	{"on_accept", "telemetry", "fexit/inet_csk_accept", "inbound TCP", tracing},
	{"on_listen", "telemetry", "fentry/inet_listen", "new listening sockets (bind shells)", tracing},
	{"on_udp_sendmsg", "telemetry", "fentry/udp_sendmsg", "DNS queries (raw packet, any libc/runtime)", tracing},
	{"on_udpv6_sendmsg", "telemetry", "fentry/udpv6_sendmsg", "DNS queries over IPv6", tracing},
	{"on_commit_creds", "telemetry", "fentry/commit_creds", "uid/euid/capability transitions (privesc)", tracing},
	{"on_ptrace", "telemetry", "fentry/security_ptrace_access_check", "ptrace / process injection", tracing},
	{"on_module_load", "telemetry", "tp_btf/module_load", "kernel module loads", tracing},
	{"on_bpf", "telemetry", "fentry/security_bpf", "BPF program loads by others (rootkit / tamper)", tracing},
	{"on_memfd_create", "telemetry", "tracepoint/syscalls/sys_enter_memfd_create", "fileless staging", func(p *ebpf.Program) (link.Link, error) {
		return link.Tracepoint("syscalls", "sys_enter_memfd_create", p, nil)
	}},
	{"on_mprotect", "telemetry", "fentry/security_file_mprotect", "anonymous W+X memory (shellcode)", tracing},
	{"on_mmap", "telemetry", "fentry/security_mmap_file", "anonymous RWX mappings", tracing},
	{"on_task_kill", "telemetry", "fentry/security_task_kill", "signals aimed at the agent (tamper)", tracing},
	{"on_readline", "telemetry", "uretprobe:/usr/bin/bash:readline", "interactive bash command lines", uretprobe("/usr/bin/bash", "readline")},
	{"block_connect4", "prevention", "cgroup/connect4 (root cgroup)", "deny IPv4 connects to blocked CIDRs/ports", cgroup(ebpf.AttachCGroupInet4Connect)},
	{"block_connect6", "prevention", "cgroup/connect6 (root cgroup)", "deny IPv6 connects to blocked CIDRs/ports", cgroup(ebpf.AttachCGroupInet6Connect)},
}

// Sensor owns the loaded maps, programs and links.
type Sensor struct {
	Status []Status
	maps   map[string]*ebpf.Map
	progs  []*ebpf.Program
	links  []link.Link
	rd     *ringbuf.Reader
}

// Load creates maps, then loads and attaches each probe independently so a
// missing hook on some kernel costs one sensor, not the whole agent.
func Load(disabled map[string]bool) (*Sensor, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock: %w", err)
	}
	spec, err := loadWarden()
	if err != nil {
		return nil, err
	}

	mapSpec := spec.Copy()
	mapSpec.Programs = map[string]*ebpf.ProgramSpec{}
	mc, err := ebpf.NewCollection(mapSpec)
	if err != nil {
		return nil, fmt.Errorf("creating maps: %w", err)
	}
	s := &Sensor{maps: mc.Maps}
	// Register our tgid before loading any program so our own BPF loads
	// and file opens are filtered from the first event.
	if err := s.maps["policy_map"].Put(uint32(0), wardenPolicy{SelfTgid: uint32(os.Getpid())}); err != nil {
		s.Close()
		return nil, fmt.Errorf("policy: %w", err)
	}

	for _, pr := range Probes {
		st := Status{Probe: pr}
		if disabled[pr.Prog] {
			st.Err = "disabled by config"
			s.Status = append(s.Status, st)
			continue
		}
		one := spec.Copy()
		one.Programs = map[string]*ebpf.ProgramSpec{pr.Prog: spec.Programs[pr.Prog]}
		c, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{MapReplacements: mc.Maps})
		if err != nil {
			st.Err = shortErr(err)
			s.Status = append(s.Status, st)
			continue
		}
		p := c.Programs[pr.Prog]
		l, err := pr.attach(p)
		if err != nil {
			p.Close()
			st.Err = shortErr(err)
			s.Status = append(s.Status, st)
			continue
		}
		s.progs = append(s.progs, p)
		s.links = append(s.links, l)
		st.OK = true
		s.Status = append(s.Status, st)
	}

	s.rd, err = ringbuf.NewReader(s.maps["events"])
	if err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func shortErr(err error) string {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		return "verifier: " + ve.Cause.Error()
	}
	msg := err.Error()
	if i := strings.IndexByte(msg, '\n'); i > 0 {
		msg = msg[:i]
	}
	return msg
}

// Read blocks for the next raw record.
func (s *Sensor) Read() ([]byte, error) {
	rec, err := s.rd.Read()
	if err != nil {
		return nil, err
	}
	return rec.RawSample, nil
}

func (s *Sensor) Close() {
	if s.rd != nil {
		s.rd.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	for _, p := range s.progs {
		p.Close()
	}
	for _, m := range s.maps {
		m.Close()
	}
}

// Policy is the in-kernel configuration pushed into BPF maps.
type Policy struct {
	KillMemfdExec    bool
	KillRevShell     bool
	KillTmpExec      bool
	KillDeletedExec  bool
	KillBlocklisted  bool
	WatchRead        []string
	WatchWrite       []string
	WatchNamesRead   []string
	WatchNamesWrite  []string
	Shells           []string
	BlockedExecPaths []string
	BlockedCIDRs     []string
	BlockedPorts     []uint16
}

const (
	wfRead  = 1
	wfWrite = 2
)

func fnv(s string) uint64 {
	h := uint64(0xcbf29ce484222325)
	for i := 0; i < len(s); i++ {
		h = (h ^ uint64(s[i])) * 0x100000001b3
	}
	return h
}

func b2u(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

// Apply writes p into the kernel maps.
func (s *Sensor) Apply(p Policy) error {
	pol := wardenPolicy{
		SelfTgid:        uint32(os.Getpid()),
		KillMemfdExec:   b2u(p.KillMemfdExec),
		KillRevshell:    b2u(p.KillRevShell),
		KillTmpExec:     b2u(p.KillTmpExec),
		KillDeletedExec: b2u(p.KillDeletedExec),
		KillBlocklisted: b2u(p.KillBlocklisted),
	}
	if err := s.maps["policy_map"].Put(uint32(0), pol); err != nil {
		return fmt.Errorf("policy: %w", err)
	}

	watch := func(m *ebpf.Map, paths []string, flag uint32) error {
		for _, path := range paths {
			if path != "/" {
				path = strings.TrimRight(path, "/")
			}
			k := fnv(path)
			var cur uint32
			_ = m.Lookup(k, &cur)
			if err := m.Put(k, cur|flag); err != nil {
				return fmt.Errorf("watch %q: %w", path, err)
			}
		}
		return nil
	}
	for _, w := range []struct {
		m     string
		paths []string
		flag  uint32
	}{
		{"watch_prefix", p.WatchRead, wfRead | wfWrite},
		{"watch_prefix", p.WatchWrite, wfWrite},
		{"watch_name", p.WatchNamesRead, wfRead | wfWrite},
		{"watch_name", p.WatchNamesWrite, wfWrite},
	} {
		if err := watch(s.maps[w.m], w.paths, w.flag); err != nil {
			return err
		}
	}

	for _, sh := range p.Shells {
		if err := s.maps["shell_names"].Put(fnv(sh), uint8(1)); err != nil {
			return err
		}
	}
	for _, path := range p.BlockedExecPaths {
		if err := s.maps["exec_block"].Put(fnv(path), uint8(1)); err != nil {
			return err
		}
	}
	for _, port := range p.BlockedPorts {
		if err := s.maps["block_port"].Put(port, uint8(1)); err != nil {
			return err
		}
	}
	for _, c := range p.BlockedCIDRs {
		pfx, err := netip.ParsePrefix(c)
		if err != nil {
			addr, err2 := netip.ParseAddr(c)
			if err2 != nil {
				return fmt.Errorf("blocked cidr %q: %w", c, err)
			}
			pfx = netip.PrefixFrom(addr, addr.BitLen())
		}
		pfx = pfx.Masked()
		if pfx.Addr().Is4() {
			k := wardenLpmV4{Prefixlen: uint32(pfx.Bits())}
			a := pfx.Addr().As4()
			copy((*[4]byte)(unsafeBytes(&k.Addr))[:], a[:])
			if err := s.maps["block_v4"].Put(k, uint8(1)); err != nil {
				return err
			}
			// IPv4-mapped form, for dual-stack sockets connecting via connect6.
			mk := wardenLpmV6{Prefixlen: uint32(96 + pfx.Bits())}
			m := netip.AddrFrom16(pfx.Addr().As16()).As16()
			copy(mk.Addr[:], m[:])
			if err := s.maps["block_v6"].Put(mk, uint8(1)); err != nil {
				return err
			}
		} else {
			k := wardenLpmV6{Prefixlen: uint32(pfx.Bits())}
			a := pfx.Addr().As16()
			copy(k.Addr[:], a[:])
			if err := s.maps["block_v6"].Put(k, uint8(1)); err != nil {
				return err
			}
		}
	}
	slog.Debug("policy applied", "watch_prefixes", len(p.WatchRead)+len(p.WatchWrite), "blocked_cidrs", len(p.BlockedCIDRs))
	return nil
}
