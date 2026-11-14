# warden

An eBPF host detection & response agent built for exe.dev VMs: a single
static Go binary (cilium/ebpf, CO-RE), 19 kernel probes, 40 detection rules
mapped to MITRE ATT&CK, and in-kernel prevention. It also runs 19 SQL
detections over exe.dev's Look In tables (proxy requests, VM metrics, SSH
logins), so platform-side and in-guest alerts land in one stream.

```
make build                 # needs clang, libbpf-dev, go
sudo ./bin/warden caps     # what this kernel supports + test-attach every probe
sudo ./bin/warden run      # run in the foreground with built-in config
make sim                   # end-to-end: 31 benign attack simulations -> 31/31 detected
make install               # systemd service, config in /etc/warden/warden.yaml
sudo ./bin/warden look -since 24h   # run the Look In detections once
```

## What exe.dev kernels give us (6.12, probed 2026-11-14)

The assumption was that EDR-grade visibility isn't possible here. It mostly is.
The thing that's missing is **synchronous deny**, not visibility.

| Capability | exe.dev | Consequence |
|---|---|---|
| BTF (`/sys/kernel/btf/vmlinux`) | yes | CO-RE, one binary works across kernel updates |
| fentry/fexit/tp_btf (`DYNAMIC_FTRACE_WITH_DIRECT_CALLS`) | yes | low-overhead hooks on LSM functions (`security_*`) for visibility |
| kprobes / uprobes / syscall tracepoints | yes | |
| `bpf_d_path`, ringbuf, `bpf_send_signal` | yes | full file paths, fast event transport, in-kernel kill |
| cgroup sock_addr (`CGROUP_BPF`) | yes | **real network deny** (connect returns EPERM) |
| **BPF LSM** (`CONFIG_BPF_LSM`) | **no** | no `-EPERM` on exec/open. Active LSMs: `capability,landlock,selinux` |
| **error injection** (`bpf_override_return`) | **no** | no alternative syscall-deny route |
| `FPROBE` (kprobe.multi) | no | minor: attach probes one by one |
| `/proc/kcore`, `/dev/mem` | not built | that attack surface is absent |
| fanotify permission events | yes | possible future route to real exec/open deny |

So CrowdStrike/Falcon-style **telemetry** is fully achievable. **Prevention** is done like this:

* **Exec prevention**: `bpf_send_signal(SIGKILL)` inside `sched_process_exec`. The
  new image is killed before it runs one instruction (the simulated reverse shell exits 137 and
  never prints). Policies: reverse shell, memfd exec, deleted-binary exec, /tmp exec, path blocklist.
* **Network prevention**: `cgroup/connect4`+`connect6` on the root cgroup, so it covers every
  process and Docker container. Blocks CIDRs and ports.
* **Rule-driven response**: rules with `action: kill` SIGKILL from userspace (after the fact).
  Off unless `prevention.allow_rule_kill: true`.

**Ask for exe.dev:** set `CONFIG_BPF_LSM=y`. `CONFIG_LSM` already lists `bpf`, so nothing else
changes. That would turn this from detect+kill into true deny (`-EPERM` on `file_open`,
`bprm_check_security`, `socket_connect`, `bpf`, `kernel_module_request`).

## Sensors

| Probe | Hook | Covers |
|---|---|---|
| on_exec | tp_btf/sched_process_exec | exec, argv, socket-stdio, memfd/deleted/tmp flags; kill policy |
| on_exit | tp_btf/sched_process_exit | process lifecycle |
| on_file_open | fentry/security_file_open | watched paths; filtered **in kernel** by FNV-hashed path prefixes + component names |
| on_tcp_connect / on_accept / on_listen | fentry/fexit | outbound, inbound, new listeners |
| on_udp_sendmsg / on_udpv6_sendmsg | fentry | DNS queries: raw packet, works for glibc, musl, Go and containers |
| on_commit_creds | fentry | uid/euid/capability transitions |
| on_ptrace | fentry/security_ptrace_access_check | injection / debugging attach |
| on_module_load | tp_btf/module_load | kernel modules |
| on_bpf | fentry/security_bpf | BPF loads by anyone else (eBPF rootkits) |
| on_memfd_create | syscall tracepoint | fileless staging |
| on_mprotect / on_mmap | fentry | anonymous W+X memory (one event per process) |
| on_task_kill | fentry/security_task_kill | SIGKILL/TERM/STOP aimed at warden |
| on_readline | uretprobe /usr/bin/bash | interactive bash command lines |
| block_connect4/6 | cgroup/connect4/6 | network deny |

Each probe loads and attaches independently. If a future kernel lacks one hook, the agent loses
that sensor and keeps running, and `warden caps` shows which one.

Userspace enrichment: process tree (12 levels), exe path, cmdline, container ID (resolved from
the kernel cgroup ID, so it works for processes that have already exited), sha256 of the binary on
exec alerts, and `/proc/N` self-vs-foreign detection.

## Detections

`warden rules` lists them. Summary: reverse shells (socket stdio, `/dev/tcp`, interpreter one-liners,
nc/socat `-e`), bind shells, fileless/memfd and deleted-binary exec, /tmp exec, `curl|sh`,
base64→shell, miners (process, args, pool ports, pool DNS), shadow/SSH-key/cloud-credential access,
`/proc/*/environ` scraping, persistence (authorized_keys, cron, systemd, ld.so.preload, shell rc,
sudoers, PAM/sshd, passwd, modules-load, system binary dirs), unexpected root transitions, ptrace,
kernel modules, tracing-class BPF loads, W^X memory, agent tamper, tunneling/OAST/paste DNS, long-label
DNS exfil, and anti-forensics/reverse-shell syntax typed in bash.

Allowlists are tuned for exe.dev (`exe-init`, `/exe.dev/bin/sshd-session`, `shelley`, `claude`,
dockerd). With the default config, a dev session of apt installs, docker pull/run, git clone,
go build, curl and vim produced no false positives.

### Writing rules

```yaml
- id: LOCAL-001
  title: Web server spawned a shell
  severity: high
  mitre: T1505.003
  event: exec
  action: kill               # needs prevention.allow_rule_kill: true
  match:
    all:
      - {field: proc.name, in: [sh, bash, dash]}
      - {field: ancestors.name, in: [nginx, php-fpm, node, gunicorn]}
      - not: {field: exec.args, contains: "healthcheck"}
```

Ops: `eq in prefix suffix contains glob regex cidr gt lt exists`, composed with `all`/`any`/`not`.
List-valued fields (`ancestors.name`) match if any element does. Add files under `rules_files:`.
A rule with an existing ID overrides the built-in one. Run `warden run -events` to see every field
on live events.

## Look In detections (platform side)

When a `look` integration is attached to the VM, `warden run` finds it through
`reflection.int.exe.xyz` and polls the Look In Iceberg tables every 5 minutes
with the `duckdb` CLI, which keeps warden static and cgo-free. Findings go
through the same outputs as kernel alerts, and each is reported once: the
dedupe state lives in `/var/lib/warden/look-state.json` and survives restarts.

| ID | Table | Detects |
|---|---|---|
| LK-001 | http_requests | VM served 2xx to anonymous visitors (exposed) |
| LK-002 | http_requests | Secrets/admin/traversal probe got past the login gate |
| LK-003 | http_requests | Internet scanner reached a VM |
| LK-004 | http_requests | 50+ unauthenticated requests from one IP to a private VM |
| LK-010 | http_requests | Known exe.dev user from an IP not seen in 30 days |
| LK-011 | ssh_access | SSH key's first login in 90 days |
| LK-012 | ssh_access | exe.dev support session |
| LK-013 | ssh_access | Root SSH login |
| LK-014 | ssh_access | API remote exec with an app token (no key attribution) |
| LK-020 | vm_metrics | Egress over 200 MB/h and 10x the VM's own p90 baseline |
| LK-021 | vm_metrics | 15+ minutes of CPU saturation (miner) |
| LK-022 | vm_metrics | VM restarted, moved host, or stopped reporting |
| LK-030 | http_requests | Host newly exposed to anonymous visitors (VM with history went public) |
| LK-031 | http_requests | Anonymous POST/PUT/PATCH/DELETE got a 2xx |
| LK-032 | http_requests | One source IP swept 3+ VMs in an hour (platform enumeration) |
| LK-033 | http_requests | Content discovery: 30+ distinct 404 paths from one IP on one host |
| LK-034 | http_requests | Same recon path from 5+ IPs in a day (campaign) |
| LK-035 | http_requests | 5+ anonymous HTTP 500s from one IP in an hour (possible exploitation) |
| LK-036 | vm_metrics + http_requests | Egress surge on a VM that served anonymous traffic (overlaps LK-020 by design) |

Rules that need a table that doesn't exist yet (it appears with its first row)
are skipped until it does. `go test ./internal/look` runs every rule against
synthetic tables with one seeded example each. Add rules with `look.rules_files`;
each rule's SQL must filter on `timestamp >= {since}` and name its `key` columns.

Look In records are 1-minute metrics and request logs, which is too coarse for
attacks inside the guest; that's what the kernel sensors are for. Gaps we've
asked exe.dev about (SSH source IPs, failed logins, a control-plane audit
table, request IDs passed into the VM, an append-only table agents can write to)
are listed in the asks doc.

## Send alerts to Edgewatch

Edgewatch's web UI is the fusion point for warden (eBPF), agentless SSH and Look In. To relay kernel alerts to it, connect warden in Edgewatch (**Data sources → Connect warden**) and set:

```yaml
output:
  webhook: "http://127.0.0.1:8000/api/ingest/warden"
  webhook_token: "<token shown once by Edgewatch>"
```

With `pull_tasks: true`, warden also polls Edgewatch every 15 seconds for **follow-up hunts**: when Look In flags something on this VM, Edgewatch can ask warden to watch live events for 10 minutes in one of three fixed, passive modes and post a short summary.

| Mode | Watches |
|---|---|
| `net` | outbound destinations, listeners, accepted connections, DNS names |
| `exec` | executables and arguments started, with temp/memfd/deleted/socket-stdio flags |
| `access` | privilege changes, writes to sensitive files, shell commands, ptrace, modules, BPF loads |

Warden pulls and never listens. A task carries only an ID, one of those modes and a duration (clamped to 60 to 900 s); unknown modes are ignored, at most three hunts run at once, and memory and report size are bounded. A hunt only sees events after it starts. Code: `internal/hunt`.

Edgewatch accepts alerts from its own VM only and ignores `LK-*` alerts, since it polls Look In itself. See Edgewatch's `DATA_SOURCES.md`.

## Output

* stdout: human-readable, or `-json`
* `alerts_file` (JSONL), plus optional `events_file` with all telemetry
* `webhook`: POSTs each alert as JSON, with retries. Point it at your SIEM or collector so a tamper
  alert leaves the box even if the agent is then killed.
* Throttling per rule+binary+object (default 60s), with a count of suppressed repeats.

## Overhead (2 vCPU exe.dev VM)

`open()` on an unwatched path: about 0.9 → 1.1 µs. Fork+exec of `/bin/true`: about 15–30% slower in a
tight loop (noisy measurement). Idle CPU is negligible, since every filter runs in kernel before
the ringbuf.

## Known gaps / next steps

* **Tamper resistance**: root can kill the agent, which detaches its links. Mitigations in place:
  systemd `Restart=always`, the tamper alert fires before the signal lands, and the webhook gets it off-box.
  Next: pin links in `/sys/fs/bpf` so probes outlive the process, and add a heartbeat to the collector.
* **File-open prevention**: not implemented. Options are SIGKILL in `security_file_open` (the process
  dies before it can read) or fanotify `FAN_OPEN_PERM` for real deny.
* Not captured yet: unlink/rename (`bpf_d_path` isn't allowed on those hooks), DNS over TCP/DoH,
  bash readline inside containers (different inode), AF_UNIX connects (e.g. docker.sock).
* File paths for container processes are relative to the container's root.
* No fleet console: one agent per VM with JSONL/webhook output.
