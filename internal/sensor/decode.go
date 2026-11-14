package sensor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/exedev/warden/internal/event"
)

const (
	evExec = iota + 1
	evExit
	evFile
	evConnect
	evAccept
	evListen
	evCreds
	evPtrace
	evModule
	evBPF
	evMemfd
	evWXMem
	evKill
	evDNS
	evShellCmd
	evNetBlock
)

const (
	xfStdinSock = 1 << iota
	xfStdoutSock
	xfMemfd
	xfDeleted
	xfTmpfs
	xfKilled
	xfBlocklisted
	xfTmpPath
)

var typeNames = map[uint32]string{
	evExec: "exec", evExit: "exit", evFile: "file", evConnect: "connect",
	evAccept: "accept", evListen: "listen", evCreds: "creds", evPtrace: "ptrace",
	evModule: "module", evBPF: "bpf", evMemfd: "memfd", evWXMem: "wx_mem",
	evKill: "tamper_kill", evDNS: "dns", evShellCmd: "shell_cmd", evNetBlock: "net_block",
}

var bpfProgTypes = map[uint32]string{
	1: "socket_filter", 2: "kprobe", 3: "sched_cls", 4: "sched_act", 5: "tracepoint",
	6: "xdp", 7: "perf_event", 8: "cgroup_skb", 9: "cgroup_sock", 10: "lwt_in",
	11: "lwt_out", 12: "lwt_xmit", 13: "sock_ops", 14: "sk_skb", 15: "cgroup_device",
	16: "sk_msg", 17: "raw_tracepoint", 18: "cgroup_sock_addr", 19: "lwt_seg6local",
	20: "lirc_mode2", 21: "sk_reuseport", 22: "flow_dissector", 23: "cgroup_sysctl",
	24: "raw_tracepoint_writable", 25: "cgroup_sockopt", 26: "tracing", 27: "struct_ops",
	28: "ext", 29: "lsm", 30: "sk_lookup", 31: "syscall", 32: "netfilter",
}

var sigNames = map[uint32]string{9: "SIGKILL", 15: "SIGTERM", 19: "SIGSTOP"}

// bootOffset converts CLOCK_BOOTTIME nanoseconds to wall-clock time.
var bootOffset = func() time.Duration {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return time.Duration(time.Now().UnixNano() - ts.Nano())
}()

func cstr(b []int8) string {
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&b[0])), len(b))
	if i := bytes.IndexByte(buf, 0); i >= 0 {
		buf = buf[:i]
	}
	return string(buf)
}

func ipString(family uint16, a [16]byte) string {
	if family == unix.AF_INET {
		return netip.AddrFrom4([4]byte(a[:4])).String()
	}
	ip := netip.AddrFrom16(a)
	return ip.Unmap().String()
}

func isPrivate(s string) bool {
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

func read[T any](raw []byte) (*T, error) {
	var v T
	if len(raw) < int(unsafe.Sizeof(v)) {
		return nil, fmt.Errorf("short record: %d < %d", len(raw), unsafe.Sizeof(v))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func header(h *wardenHdr) *event.Event {
	return &event.Event{
		Time:   time.Unix(0, int64(h.Ts)).Add(bootOffset),
		Type:   typeNames[h.Type],
		PID:    h.Pid,
		TGID:   h.Tgid,
		PPID:   h.Ppid,
		UID:    h.Uid,
		Comm:   cstr(h.Comm[:]),
		Fields: map[string]any{"gid": h.Gid, "cgroup_id": h.Cgroup, "mntns": h.Mntns},
	}
}

// Decode turns one ring-buffer record into an Event.
func Decode(raw []byte) (*event.Event, error) {
	if len(raw) < 8+4 {
		return nil, fmt.Errorf("short record")
	}
	typ := binary.LittleEndian.Uint32(raw[8:12])
	switch typ {
	case evExec:
		r, err := read[wardenEvExec](raw)
		if err != nil {
			return nil, err
		}
		e := header(&r.H)
		f := r.H.Flags
		e.Set("exec.filename", cstr(r.Filename[:]))
		args := splitArgs(r.Args[:r.ArgsLen])
		e.Set("exec.argv", args)
		e.Set("exec.args", strings.Join(args, " "))
		e.Set("exec.inode", r.Ino)
		e.Set("exec.stdin_socket", f&xfStdinSock != 0)
		e.Set("exec.stdout_socket", f&xfStdoutSock != 0)
		e.Set("exec.memfd", f&xfMemfd != 0)
		e.Set("exec.deleted", f&xfDeleted != 0)
		e.Set("exec.tmpfs", f&xfTmpfs != 0)
		e.Set("exec.tmp_path", f&xfTmpPath != 0)
		e.Set("exec.killed", f&xfKilled != 0)
		e.Set("exec.blocklisted", f&xfBlocklisted != 0)
		return e, nil
	case evExit:
		r, err := read[wardenEvExit](raw)
		if err != nil {
			return nil, err
		}
		e := header(&r.H)
		e.Set("exit.code", r.Code>>8&0xff)
		e.Set("exit.signal", r.Code&0x7f)
		return e, nil
	case evFile:
		r, err := read[wardenEvFile](raw)
		if err != nil {
			return nil, err
		}
		e := header(&r.H)
		p := cstr(r.Path[:])
		e.Set("file.path", p)
		e.Set("file.name", p[strings.LastIndexByte(p, '/')+1:])
		e.Set("file.write", r.Fmode&0x2 != 0)
		return e, nil
	case evConnect, evAccept, evListen, evNetBlock:
		r, err := read[wardenEvNet](raw)
		if err != nil {
			return nil, err
		}
		e := header(&r.H)
		daddr := ipString(r.Family, r.Daddr)
		e.Set("net.family", map[uint16]string{unix.AF_INET: "ipv4", unix.AF_INET6: "ipv6"}[r.Family])
		e.Set("net.saddr", ipString(r.Family, r.Saddr))
		e.Set("net.daddr", daddr)
		e.Set("net.sport", int(r.Sport))
		e.Set("net.dport", int(r.Dport))
		e.Set("net.daddr_private", isPrivate(daddr))
		if typ == evListen {
			e.Set("net.laddr", e.Fields["net.saddr"])
			e.Set("net.lport", int(r.Sport))
			delete(e.Fields, "net.daddr")
			delete(e.Fields, "net.dport")
			delete(e.Fields, "net.daddr_private")
		}
		return e, nil
	case evCreds:
		r, err := read[wardenEvCreds](raw)
		if err != nil {
			return nil, err
		}
		e := header(&r.H)
		e.Set("creds.old_uid", r.OldUid)
		e.Set("creds.old_euid", r.OldEuid)
		e.Set("creds.new_uid", r.NewUid)
		e.Set("creds.new_euid", r.NewEuid)
		e.Set("creds.old_caps", fmt.Sprintf("%#x", r.OldCaps))
		e.Set("creds.new_caps", fmt.Sprintf("%#x", r.NewCaps))
		e.Set("creds.gained_root", r.OldEuid != 0 && r.NewEuid == 0)
		return e, nil
	case evPtrace, evModule, evBPF, evMemfd, evWXMem, evKill:
		r, err := read[wardenEvTarget](raw)
		if err != nil {
			return nil, err
		}
		e := header(&r.H)
		name := cstr(r.Name[:])
		switch typ {
		case evPtrace:
			e.Set("target.pid", r.TargetPid)
			e.Set("target.comm", cstr(r.TargetComm[:]))
			e.Set("ptrace.mode", r.Arg)
		case evModule:
			e.Set("module.name", name)
		case evBPF:
			e.Set("bpf.prog_type", bpfProgTypes[r.Arg2])
			e.Set("bpf.prog_name", name)
		case evMemfd:
			e.Set("memfd.name", name)
			e.Set("memfd.flags", r.Arg)
		case evWXMem:
			e.Set("wx.prot", r.Arg)
		case evKill:
			e.Set("target.pid", r.TargetPid)
			e.Set("signal", sigNames[r.Arg])
		}
		return e, nil
	case evDNS:
		r, err := read[wardenEvDns](raw)
		if err != nil {
			return nil, err
		}
		e := header(&r.H)
		q, qt := parseDNSQuery(r.Payload[:r.Len])
		e.Set("dns.query", q)
		e.Set("dns.qtype", qt)
		e.Set("dns.server", ipString(r.Family, r.Daddr))
		return e, nil
	case evShellCmd:
		r, err := read[wardenEvShellcmd](raw)
		if err != nil {
			return nil, err
		}
		e := header(&r.H)
		e.Set("shell.line", cstr(r.Line[:]))
		return e, nil
	}
	return nil, fmt.Errorf("unknown event type %d", typ)
}

func splitArgs(b []int8) []string {
	if len(b) == 0 {
		return nil
	}
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&b[0])), len(b))
	s := string(bytes.TrimRight(buf, "\x00"))
	if s == "" {
		return nil
	}
	return strings.Split(s, "\x00")
}

var qtypes = map[uint16]string{1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}

// parseDNSQuery extracts the first question from a raw DNS query payload.
func parseDNSQuery(b []byte) (string, string) {
	if len(b) < 13 {
		return "", ""
	}
	var labels []string
	i := 12
	for i < len(b) {
		n := int(b[i])
		if n == 0 {
			i++
			break
		}
		if n&0xc0 != 0 || i+1+n > len(b) {
			return strings.Join(labels, "."), ""
		}
		labels = append(labels, string(b[i+1:i+1+n]))
		i += 1 + n
	}
	qt := ""
	if i+2 <= len(b) {
		t := binary.BigEndian.Uint16(b[i:])
		if qt = qtypes[t]; qt == "" {
			qt = fmt.Sprint(t)
		}
	}
	return strings.ToLower(strings.Join(labels, ".")), qt
}
