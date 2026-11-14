// SPDX-License-Identifier: GPL-2.0
// warden: eBPF host sensor. Built for kernels without CONFIG_BPF_LSM
// (e.g. exe.dev VMs): visibility comes from tp_btf/fentry/fexit, and
// prevention from bpf_send_signal + cgroup sock_addr hooks.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define COMM_LEN 16
#define PATH_LEN 256
#define ARGS_LEN 512
#define DNS_LEN 256

#define S_IFMT 0170000
#define S_IFSOCK 0140000
#define TMPFS_MAGIC 0x01021994
#define FMODE_WRITE 0x2
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4
#define VM_WRITE 0x2
#define PTRACE_MODE_ATTACH 0x02
#define AF_INET 2
#define AF_INET6 10
#define SIGKILL 9
#define SIGTERM 15
#define SIGSTOP 19

enum ev_type {
	EV_EXEC = 1,
	EV_EXIT,
	EV_FILE,
	EV_CONNECT,
	EV_ACCEPT,
	EV_LISTEN,
	EV_CREDS,
	EV_PTRACE,
	EV_MODULE,
	EV_BPF,
	EV_MEMFD,
	EV_WX_MEM,
	EV_KILL,
	EV_DNS,
	EV_SHELLCMD,
	EV_NETBLOCK,
};

// exec flags
#define XF_STDIN_SOCK (1 << 0)
#define XF_STDOUT_SOCK (1 << 1)
#define XF_MEMFD (1 << 2)
#define XF_DELETED (1 << 3)
#define XF_TMPFS (1 << 4)
#define XF_KILLED (1 << 5)
#define XF_BLOCKLISTED (1 << 6)
#define XF_TMPPATH (1 << 7)

// watch flags
#define WF_READ (1 << 0)
#define WF_WRITE (1 << 1)

struct hdr {
	u64 ts;
	u32 type;
	u32 pid;
	u32 tgid;
	u32 ppid;
	u32 uid;
	u32 gid;
	u64 cgroup;
	u32 mntns;
	u32 flags;
	char comm[COMM_LEN];
};

struct ev_exec {
	struct hdr h;
	u32 args_len;
	u32 nlink;
	u64 ino;
	char filename[PATH_LEN];
	char args[ARGS_LEN];
};

struct ev_exit {
	struct hdr h;
	u32 code;
	u32 _pad;
};

struct ev_file {
	struct hdr h;
	u32 fmode;
	u32 watch;
	char path[PATH_LEN];
};

struct ev_net {
	struct hdr h;
	u16 family;
	u16 sport;
	u16 dport;
	u16 proto;
	u8 saddr[16];
	u8 daddr[16];
};

struct ev_creds {
	struct hdr h;
	u32 old_uid;
	u32 old_euid;
	u32 new_uid;
	u32 new_euid;
	u64 old_caps;
	u64 new_caps;
};

struct ev_target {
	struct hdr h;
	u32 target_pid;
	u32 arg; // ptrace mode / signal / bpf cmd / prot
	u32 arg2; // bpf prog type
	u32 _pad;
	char target_comm[COMM_LEN];
	char name[64]; // module / bpf prog / memfd name
};

struct ev_dns {
	struct hdr h;
	u16 family;
	u16 dport;
	u32 len;
	u8 daddr[16];
	u8 payload[DNS_LEN];
};

struct ev_shellcmd {
	struct hdr h;
	char line[PATH_LEN];
};

struct policy {
	u32 self_tgid;
	u8 kill_memfd_exec;
	u8 kill_revshell;
	u8 kill_tmp_exec;
	u8 kill_deleted_exec;
	u8 kill_blocklisted;
	u8 _pad[3];
};

struct lpm_v4 {
	u32 prefixlen;
	u32 addr;
};

struct lpm_v6 {
	u32 prefixlen;
	u8 addr[16];
};

// Force BTF emission of event structs so bpf2go can generate Go types.
const struct ev_exec *_e1 __attribute__((unused));
const struct ev_exit *_e2 __attribute__((unused));
const struct ev_file *_e3 __attribute__((unused));
const struct ev_net *_e4 __attribute__((unused));
const struct ev_creds *_e5 __attribute__((unused));
const struct ev_target *_e6 __attribute__((unused));
const struct ev_dns *_e7 __attribute__((unused));
const struct ev_shellcmd *_e8 __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 << 20);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct policy);
} policy_map SEC(".maps");

// FNV-1a hash of path prefixes ending at a '/' boundary or end of string.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u32);
} watch_prefix SEC(".maps");

// FNV-1a hash of a single path component (any depth), e.g. ".ssh".
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u64);
	__type(value, u32);
} watch_name SEC(".maps");

// Basenames treated as interactive shells/interpreters for reverse-shell kill.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, u64);
	__type(value, u8);
} shell_names SEC(".maps");

// Exec paths (FNV-1a of filename as passed to execve) to kill on sight.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, u64);
	__type(value, u8);
} exec_block SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v4);
	__type(value, u8);
} block_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, struct lpm_v6);
	__type(value, u8);
} block_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u16);
	__type(value, u8);
} block_port SEC(".maps");

// One W^X alert per process.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, u32);
	__type(value, u8);
} wx_seen SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct ev_file);
} file_scratch SEC(".maps");

#define FNV_OFF 0xcbf29ce484222325ULL
#define FNV_PRIME 0x100000001b3ULL

static __always_inline struct policy *get_policy(void)
{
	u32 k = 0;
	return bpf_map_lookup_elem(&policy_map, &k);
}

static __always_inline bool is_self(void)
{
	struct policy *p = get_policy();
	return p && p->self_tgid == (u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline void fill_hdr(struct hdr *h, u32 type)
{
	struct task_struct *t = bpf_get_current_task_btf();
	u64 pt = bpf_get_current_pid_tgid();
	u64 ug = bpf_get_current_uid_gid();

	h->ts = bpf_ktime_get_boot_ns();
	h->type = type;
	h->pid = (u32)pt;
	h->tgid = pt >> 32;
	h->ppid = BPF_CORE_READ(t, real_parent, tgid);
	h->uid = (u32)ug;
	h->gid = ug >> 32;
	h->cgroup = bpf_get_current_cgroup_id();
	h->mntns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns.inum);
	h->flags = 0;
	bpf_get_current_comm(h->comm, sizeof(h->comm));
}

// Variant for program types without task BTF access (cgroup hooks).
static __always_inline void fill_hdr_basic(struct hdr *h, u32 type)
{
	u64 pt = bpf_get_current_pid_tgid();
	u64 ug = bpf_get_current_uid_gid();

	h->ts = bpf_ktime_get_boot_ns();
	h->type = type;
	h->pid = (u32)pt;
	h->tgid = pt >> 32;
	h->ppid = 0;
	h->uid = (u32)ug;
	h->gid = ug >> 32;
	h->cgroup = bpf_get_current_cgroup_id();
	h->mntns = 0;
	h->flags = 0;
	bpf_get_current_comm(h->comm, sizeof(h->comm));
}

// True only for IPv4/IPv6 sockets: AF_UNIX socketpairs are how libuv
// (Node, Claude Code, VS Code server) wires child stdio, not a network peer.
static __always_inline bool fd_is_inet_socket(struct task_struct *t, int fd)
{
	struct file **fds = BPF_CORE_READ(t, files, fdt, fd);
	struct file *f = NULL;
	struct socket *sock;
	u16 family;

	if (!fds || bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]) || !f)
		return false;
	if ((BPF_CORE_READ(f, f_inode, i_mode) & S_IFMT) != S_IFSOCK)
		return false;
	sock = BPF_CORE_READ(f, private_data);
	family = BPF_CORE_READ(sock, sk, __sk_common.skc_family);
	return family == AF_INET || family == AF_INET6;
}

static __always_inline bool has_prefix(const char *s, const char *p, int n)
{
	for (int i = 0; i < n; i++)
		if (s[i] != p[i])
			return false;
	return true;
}

/* ---------------------------------------------------------------- process */

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	struct policy *pol = get_policy();
	struct ev_exec *e;
	struct file *f;
	u64 h = FNV_OFF, bh = FNV_OFF;
	bool kill = false;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_hdr(&e->h, EV_EXEC);

	bpf_probe_read_kernel_str(e->filename, sizeof(e->filename), BPF_CORE_READ(bprm, filename));

	f = BPF_CORE_READ(bprm, file);
	e->nlink = BPF_CORE_READ(f, f_inode, __i_nlink);
	e->ino = BPF_CORE_READ(f, f_inode, i_ino);
	if (e->nlink == 0)
		e->h.flags |= XF_DELETED;
	if (BPF_CORE_READ(f, f_inode, i_sb, s_magic) == TMPFS_MAGIC)
		e->h.flags |= XF_TMPFS;

	char dname[8] = {};
	bpf_probe_read_kernel_str(dname, sizeof(dname), BPF_CORE_READ(f, f_path.dentry, d_name.name));
	if (has_prefix(dname, "memfd:", 6))
		e->h.flags |= XF_MEMFD;

	if (has_prefix(e->filename, "/tmp/", 5) || has_prefix(e->filename, "/var/tmp/", 9) ||
	    has_prefix(e->filename, "/dev/shm/", 9))
		e->h.flags |= XF_TMPPATH;

	if (fd_is_inet_socket(p, 0))
		e->h.flags |= XF_STDIN_SOCK;
	if (fd_is_inet_socket(p, 1))
		e->h.flags |= XF_STDOUT_SOCK;

	unsigned long as = BPF_CORE_READ(p, mm, arg_start);
	unsigned long ae = BPF_CORE_READ(p, mm, arg_end);
	u32 len = ae > as ? ae - as : 0;
	if (len > ARGS_LEN)
		len = ARGS_LEN;
	if (bpf_probe_read_user(e->args, len, (void *)as) == 0)
		e->args_len = len;

	// Path hash and basename hash for policy lookups.
	for (int i = 0; i < PATH_LEN; i++) {
		char c = e->filename[i];
		if (!c)
			break;
		h = (h ^ (u8)c) * FNV_PRIME;
		bh = c == '/' ? FNV_OFF : (bh ^ (u8)c) * FNV_PRIME;
	}

	if (pol && e->h.tgid != pol->self_tgid) {
		if (bpf_map_lookup_elem(&exec_block, &h)) {
			e->h.flags |= XF_BLOCKLISTED;
			kill |= pol->kill_blocklisted;
		}
		if (pol->kill_memfd_exec && (e->h.flags & XF_MEMFD))
			kill = true;
		if (pol->kill_deleted_exec && (e->h.flags & XF_DELETED))
			kill = true;
		if (pol->kill_tmp_exec && (e->h.flags & (XF_TMPPATH | XF_TMPFS)) && !(e->h.flags & XF_MEMFD))
			kill = true;
		if (pol->kill_revshell && (e->h.flags & XF_STDIN_SOCK) && (e->h.flags & XF_STDOUT_SOCK) &&
		    bpf_map_lookup_elem(&shell_names, &bh))
			kill = true;
	}

	// The new image hasn't run a single user instruction yet: SIGKILL here
	// is effectively exec prevention.
	if (kill) {
		bpf_send_signal(SIGKILL);
		e->h.flags |= XF_KILLED;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(on_exit, struct task_struct *p)
{
	struct ev_exit *e;

	if (p->pid != p->tgid)
		return 0;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_hdr(&e->h, EV_EXIT);
	e->code = p->exit_code;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ------------------------------------------------------------------- file */

SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	u32 k = 0, watch = 0, *v;
	u64 h = FNV_OFF, ch = FNV_OFF;
	struct ev_file *e;

	if (is_self())
		return 0;
	e = bpf_map_lookup_elem(&file_scratch, &k);
	if (!e)
		return 0;
	if (bpf_d_path(&file->f_path, e->path, sizeof(e->path)) < 0)
		return 0;

	for (int i = 0; i < PATH_LEN; i++) {
		char c = e->path[i];
		if (c == '/' || c == 0) {
			if (i > 0) {
				v = bpf_map_lookup_elem(&watch_prefix, &h);
				if (v)
					watch |= *v;
				v = bpf_map_lookup_elem(&watch_name, &ch);
				if (v)
					watch |= *v;
			}
			if (c == 0)
				break;
			ch = FNV_OFF;
		} else {
			ch = (ch ^ (u8)c) * FNV_PRIME;
		}
		h = (h ^ (u8)c) * FNV_PRIME;
	}
	if (!watch)
		return 0;

	e->fmode = file->f_mode;
	if (!(watch & WF_READ) && !(e->fmode & FMODE_WRITE))
		return 0;
	e->watch = watch;
	fill_hdr(&e->h, EV_FILE);
	bpf_ringbuf_output(&events, e, sizeof(*e), 0);
	return 0;
}

/* ---------------------------------------------------------------- network */

static __always_inline void fill_sock(struct ev_net *e, struct sock *sk)
{
	e->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
	e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
	e->proto = BPF_CORE_READ(sk, sk_protocol);
	// Explicit sizes: BPF_CORE_READ_INTO would size by *dst (one byte).
	if (e->family == AF_INET) {
		bpf_core_read(e->saddr, 4, &sk->__sk_common.skc_rcv_saddr);
		bpf_core_read(e->daddr, 4, &sk->__sk_common.skc_daddr);
	} else {
		bpf_core_read(e->saddr, 16, &sk->__sk_common.skc_v6_rcv_saddr);
		bpf_core_read(e->daddr, 16, &sk->__sk_common.skc_v6_daddr);
	}
}

static __always_inline int emit_sock(struct sock *sk, u32 type)
{
	struct ev_net *e;

	if (!sk || is_self())
		return 0;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e->saddr, 0, sizeof(e->saddr) * 2);
	fill_hdr(&e->h, type);
	fill_sock(e, sk);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/tcp_connect")
int BPF_PROG(on_tcp_connect, struct sock *sk)
{
	return emit_sock(sk, EV_CONNECT);
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(on_accept, struct sock *sk, struct proto_accept_arg *arg, struct sock *ret)
{
	return emit_sock(ret, EV_ACCEPT);
}

SEC("fentry/inet_listen")
int BPF_PROG(on_listen, struct socket *sock, int backlog)
{
	return emit_sock(BPF_CORE_READ(sock, sk), EV_LISTEN);
}

// DNS: capture the raw query payload of any UDP datagram to port 53. Works
// for glibc, musl, Go and containers alike, unlike a getaddrinfo uprobe.
static __always_inline int on_udp(struct sock *sk, struct msghdr *msg)
{
	struct ev_dns *e;
	u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
	u16 dport = 0;
	void *name = BPF_CORE_READ(msg, msg_name);
	u8 daddr[16] = {};

	if (name) {
		struct sockaddr_in6 sa = {};
		bpf_probe_read_kernel(&sa, sizeof(sa), name);
		dport = bpf_ntohs(sa.sin6_port);
		if (sa.sin6_family == AF_INET)
			__builtin_memcpy(daddr, &((struct sockaddr_in *)&sa)->sin_addr, 4);
		else
			__builtin_memcpy(daddr, &sa.sin6_addr, 16);
	} else {
		dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
		if (family == AF_INET)
			bpf_core_read(daddr, 4, &sk->__sk_common.skc_daddr);
		else
			bpf_core_read(daddr, 16, &sk->__sk_common.skc_v6_daddr);
	}
	if (dport != 53 || is_self())
		return 0;

	void *base = NULL;
	u8 itype = BPF_CORE_READ(msg, msg_iter.iter_type);
	if (itype == bpf_core_enum_value(enum iter_type, ITER_UBUF))
		base = BPF_CORE_READ(msg, msg_iter.ubuf);
	else if (itype == bpf_core_enum_value(enum iter_type, ITER_IOVEC))
		base = BPF_CORE_READ(msg, msg_iter.__iov, iov_base);
	if (!base)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_hdr(&e->h, EV_DNS);
	e->family = family;
	e->dport = dport;
	__builtin_memcpy(e->daddr, daddr, 16);
	u64 cnt = BPF_CORE_READ(msg, msg_iter.count);
	if (cnt > DNS_LEN)
		cnt = DNS_LEN;
	e->len = 0;
	if (bpf_probe_read_user(e->payload, cnt, base) == 0)
		e->len = cnt;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/udp_sendmsg")
int BPF_PROG(on_udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	return on_udp(sk, msg);
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(on_udpv6_sendmsg, struct sock *sk, struct msghdr *msg, size_t len)
{
	return on_udp(sk, msg);
}

/* ------------------------------------------------- privilege / integrity */

SEC("fentry/commit_creds")
int BPF_PROG(on_commit_creds, struct cred *new)
{
	struct task_struct *t = bpf_get_current_task_btf();
	const struct cred *old = t->real_cred;
	struct ev_creds *e;
	u32 ou = old->uid.val, oe = old->euid.val;
	u32 nu = new->uid.val, ne = new->euid.val;

	if (ou == nu && oe == ne)
		return 0;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_hdr(&e->h, EV_CREDS);
	e->old_uid = ou;
	e->old_euid = oe;
	e->new_uid = nu;
	e->new_euid = ne;
	e->old_caps = BPF_CORE_READ(old, cap_effective.val);
	e->new_caps = BPF_CORE_READ(new, cap_effective.val);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline struct ev_target *target_ev(u32 type, struct task_struct *target)
{
	struct ev_target *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return NULL;
	fill_hdr(&e->h, type);
	e->arg = 0;
	e->arg2 = 0;
	e->target_pid = 0;
	e->name[0] = 0;
	e->target_comm[0] = 0;
	if (target) {
		e->target_pid = BPF_CORE_READ(target, tgid);
		BPF_CORE_READ_STR_INTO(&e->target_comm, target, comm);
	}
	return e;
}

SEC("fentry/security_ptrace_access_check")
int BPF_PROG(on_ptrace, struct task_struct *child, unsigned int mode)
{
	struct ev_target *e;

	if (!(mode & PTRACE_MODE_ATTACH) || is_self())
		return 0;
	e = target_ev(EV_PTRACE, child);
	if (!e)
		return 0;
	e->arg = mode;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/module_load")
int BPF_PROG(on_module_load, struct module *mod)
{
	struct ev_target *e = target_ev(EV_MODULE, NULL);

	if (!e)
		return 0;
	BPF_CORE_READ_STR_INTO(&e->name, mod, name);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/security_bpf")
int BPF_PROG(on_bpf, int cmd, union bpf_attr *attr)
{
	struct ev_target *e;

	if (cmd != BPF_PROG_LOAD || is_self())
		return 0;
	e = target_ev(EV_BPF, NULL);
	if (!e)
		return 0;
	e->arg = cmd;
	e->arg2 = BPF_CORE_READ(attr, prog_type);
	bpf_probe_read_kernel_str(e->name, 16, &attr->prog_name);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int on_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
	struct ev_target *e;

	if (is_self())
		return 0;
	e = target_ev(EV_MEMFD, NULL);
	if (!e)
		return 0;
	e->arg = ctx->args[1];
	bpf_probe_read_user_str(e->name, sizeof(e->name), (void *)ctx->args[0]);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

static __always_inline int emit_wx(unsigned long prot)
{
	u32 tgid = bpf_get_current_pid_tgid() >> 32;
	u8 one = 1;
	struct ev_target *e;

	if (bpf_map_lookup_elem(&wx_seen, &tgid) || is_self())
		return 0;
	bpf_map_update_elem(&wx_seen, &tgid, &one, BPF_ANY);
	e = target_ev(EV_WX_MEM, NULL);
	if (!e)
		return 0;
	e->arg = prot;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Anonymous memory becoming writable+executable: shellcode / reflective loaders
// (also JITs, so userspace rules allowlist known runtimes).
SEC("fentry/security_file_mprotect")
int BPF_PROG(on_mprotect, struct vm_area_struct *vma, unsigned long reqprot, unsigned long prot)
{
	if (!(prot & PROT_EXEC) || vma->vm_file)
		return 0;
	if (!(prot & PROT_WRITE) && !(vma->vm_flags & VM_WRITE))
		return 0;
	return emit_wx(prot);
}

SEC("fentry/security_mmap_file")
int BPF_PROG(on_mmap, struct file *file, unsigned long prot, unsigned long flags)
{
	if (file || (prot & (PROT_WRITE | PROT_EXEC)) != (PROT_WRITE | PROT_EXEC))
		return 0;
	return emit_wx(prot);
}

// Tamper: signals aimed at the agent itself.
SEC("fentry/security_task_kill")
int BPF_PROG(on_task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig)
{
	struct policy *pol = get_policy();
	struct ev_target *e;

	if (!pol || p->tgid != pol->self_tgid || is_self())
		return 0;
	if (sig != SIGKILL && sig != SIGTERM && sig != SIGSTOP)
		return 0;
	e = target_ev(EV_KILL, p);
	if (!e)
		return 0;
	e->arg = sig;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

// Interactive bash command lines.
SEC("uretprobe")
int BPF_KRETPROBE(on_readline, const char *ret)
{
	struct ev_shellcmd *e;

	if (!ret)
		return 0;
	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	fill_hdr(&e->h, EV_SHELLCMD);
	bpf_probe_read_user_str(e->line, sizeof(e->line), ret);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ------------------------------------------------------- network enforce */

static __always_inline void emit_block(u16 family, u16 port, void *addr, int alen)
{
	struct ev_net *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return;
	__builtin_memset(e->saddr, 0, sizeof(e->saddr) * 2);
	fill_hdr_basic(&e->h, EV_NETBLOCK);
	e->family = family;
	e->dport = port;
	e->sport = 0;
	e->proto = 0;
	if (alen == 4)
		bpf_probe_read_kernel(e->daddr, 4, addr);
	else
		bpf_probe_read_kernel(e->daddr, 16, addr);
	bpf_ringbuf_submit(e, 0);
}

SEC("cgroup/connect4")
int block_connect4(struct bpf_sock_addr *ctx)
{
	struct lpm_v4 k = { .prefixlen = 32, .addr = ctx->user_ip4 };
	u16 port = bpf_ntohs(ctx->user_port);

	if (bpf_map_lookup_elem(&block_v4, &k) || bpf_map_lookup_elem(&block_port, &port)) {
		emit_block(AF_INET, port, &k.addr, 4);
		return 0;
	}
	return 1;
}

SEC("cgroup/connect6")
int block_connect6(struct bpf_sock_addr *ctx)
{
	struct lpm_v6 k = { .prefixlen = 128 };
	u16 port = bpf_ntohs(ctx->user_port);

	k.addr[0] = 0;
	*(u32 *)&k.addr[0] = ctx->user_ip6[0];
	*(u32 *)&k.addr[4] = ctx->user_ip6[1];
	*(u32 *)&k.addr[8] = ctx->user_ip6[2];
	*(u32 *)&k.addr[12] = ctx->user_ip6[3];
	if (bpf_map_lookup_elem(&block_v6, &k) || bpf_map_lookup_elem(&block_port, &port)) {
		emit_block(AF_INET6, port, k.addr, 16);
		return 0;
	}
	return 1;
}
