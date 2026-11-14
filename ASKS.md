# Asks for exe.dev

Gaps in the platform telemetry and kernel that limit what Warden and Edgewatch can detect on exe.dev VMs. Ordered by how much they would change detection quality. Each entry says what we saw, what we would build with it, and the privacy line we would hold.

Status: **drafted for the exe.dev team; not yet submitted.** Nothing here has been sent anywhere.

---

## 1. Look In: record data transiting integrations, and classify egress

**Priority: highest.** This is the largest remaining blind spot for network threat detection.

### What we hit

On 2026-11-14, Look In reported `newsecreads` sending 1.4 GB in 75 minutes (five consecutive 15-minute buckets, 10:00 to 11:15 UTC). Everything Look In could tell us:

| Question | What Look In could answer |
|---|---|
| Bytes moved | 1.4 GB sent, 5.4 GB received (`vm_metrics`) |
| Served through the proxy? | No: zero `http_requests` rows for the VM in the window |
| VM to VM? | Indirectly: no other visible VM had matching received bytes |
| Over an integration? | **Unanswerable.** Integration calls are outbound from the VM and appear in no table |
| Where did it go? | **Unanswerable.** `vm_metrics` has cumulative byte counters only |
| Which integrations does the VM have? | **Unanswerable** from here. The reflection integration is documented as self-discovery for the calling VM, and no Look In table records attachments |

The owner later explained that a Tigris integration pushes PDF captures of ingested news sites to a bucket, which fits every number (heavy inbound fetches, about 40% CPU for rendering, no disk growth, a bounded window). We could not verify that from the data. Meanwhile Edgewatch raised five `high` findings, and a classifier model scored the VM 0.81 likely data exfiltration until we added context by hand. A sanctioned, intended transfer and a genuine exfiltration are **indistinguishable in Look In today**.

We worked around it by building owner-declared "expected activity" profiles in Edgewatch (an envelope of window and cap that a human asserts). That is a judgement we cannot verify; the platform could verify it.

### Proposal, smallest useful step first

1. **Split the byte counters by class.** Add to `vm_metrics`, per minute:
   `net_tx_bytes_integration`, `net_rx_bytes_integration`, `net_tx_bytes_vm_to_vm`, `net_rx_bytes_vm_to_vm` (the existing `net_*_bytes` stay as totals). Internet traffic is the remainder. No destinations, no identities; just *which class of path*. This alone answers "is it over an integration, VM to VM, or out to the Internet?" for any VM.
2. **A `vm_integrations` table** (or columns on an existing one): `vm_name`, `integration_name`, `integration_type`, `attached_at`. With attach and detach events in the control-plane audit table (see 3). Detections can then know what a VM is *allowed* to use, and flag a VM that suddenly calls an integration it never used.
3. **An `integration_requests` table**, one row per proxied request or one aggregate row per VM, integration and minute: `timestamp`, `team_id`, `vm_name`, `integration_name`, `integration_type`, `target_host` (the configured target only, for example the Tigris endpoint), `method`, `status`, `duration_ms`, `request_bytes`, `response_bytes`.

### Privacy line

Match what `http_requests` already does. Record the integration name, the configured target host, byte counts and status. **Never** record request or response bodies, headers (including the injected credentials), query strings, bucket or object names, or end-user identities beyond what `http_requests` already holds. Data stays team-scoped, as Look In is today.

### What we would build

- Egress findings that subtract sanctioned integration traffic and name the path: "412 MB to the `tigris` integration" versus "412 MB direct to the Internet".
- Alerts on an integration used from a VM that never used it, volume far above that VM's own baseline for an integration, or a spike in `4xx`/`5xx` from an integration (credential misuse or a runaway loop).
- Removal of a whole class of false positives, and a sharper exfiltration signal, because direct-to-Internet egress would stand alone.

Example queries this would enable:

```sql
-- bytes that left the VM by path, last hour
SELECT vm_name,
       sum(net_tx_bytes_integration)  AS via_integration,
       sum(net_tx_bytes_vm_to_vm)     AS to_other_vms,
       sum(net_tx_bytes) - sum(net_tx_bytes_integration) - sum(net_tx_bytes_vm_to_vm) AS to_internet
FROM vm_metrics_increase WHERE timestamp >= now() - INTERVAL 1 HOUR GROUP BY vm_name;

-- a VM using an integration it has not used in the last 30 days
SELECT vm_name, integration_name, min(timestamp)
FROM integration_requests GROUP BY ALL
HAVING min(timestamp) >= now() - INTERVAL 1 HOUR;
```

---

## 2. SSH source IPs and failed logins in `ssh_access`

`ssh_access` records successful logins with the key fingerprint but not the source IP, and does not record failures. Brute-force, credential stuffing and logins from unexpected networks are invisible. Ask: add `source_ip` and a `result` column (`success` or `failure` with a reason). The table also did not exist on the day of the incident above, which hid SSH activity from the investigation, so please keep it queryable even when empty.

## 3. A control-plane audit table

Who attached or detached an integration, changed a VM's sharing or proxy settings, created or deleted a VM, or rotated a credential. Today those changes are not visible to Look In consumers, so Edgewatch cannot flag "a VM went public" at the moment it happened, only later from the first anonymous request. Ask: `control_plane_events(timestamp, team_id, login_user_id, vm_name, action, detail)` with no secrets in `detail`.

## 4. Request IDs passed into the VM

Pass the proxy's request ID to the VM (for example an `X-Exedev-Request-Id` header) and record it in `http_requests`. That would let an in-guest sensor join a request seen at the proxy to what the VM did with it, which turns two independent views into one trace.

## 5. An append-only table that agents can write to

A small, per-team, append-only table that a VM's own agents (Warden, Edgewatch) can write findings to through an integration, readable from Look In. Alerts would then land somewhere a compromised guest cannot rewrite, instead of relying on a webhook to the same VM.

## 6. Guest kernel: `CONFIG_BPF_LSM=y`

`CONFIG_LSM` already lists `bpf` but the option is off, so Warden can detect and kill but cannot deny. Enabling it allows synchronous `-EPERM` on exec, open, connect, `bpf()` and module loads. Everything else about the kernel (BTF, fentry, cgroup sock_addr, ring buffers) is already what we need.
