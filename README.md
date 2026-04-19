# agent-vault — Zero-Knowledge Credential Injector

An AI coding agent sends HTTP requests using a **dummy token** (`FAKE_TOKEN_12345`).

For a structured developer guide, start with [`docs/README.md`](docs/README.md).

**On Linux:** An eBPF TC egress classifier intercepts outbound TCP packets, checks whether they belong to the agent's test cgroup, locates the dummy token in the payload, and overwrites it with the **real credential** before the packet leaves the host.

**On macOS/Windows:** A local HTTP proxy (`localhost:8888`) intercepts requests, rewrites the token in HTTP headers and request bodies, and forwards to the upstream server.

Both modes ensure the agent process — and any logs it emits — **only ever sees the fake token**.

```
┌─ Linux (eBPF, kernel-space) ─────────────────────────────┐
│  Agent  →  [FAKE]  →  eBPF hook  →  [REAL]  →  Server   │
└──────────────────────────────────────────────────────────┘

┌─ macOS/Windows (HTTP proxy, user-space) ────────────────┐
│  Agent  →  proxy  →  [FAKE→REAL]  →  Server             │
└──────────────────────────────────────────────────────────┘
```

---

## Prerequisites

### Linux (eBPF mode)

| Requirement | Minimum | Verify |
|---|---|---|
| Linux kernel | **5.8+** | `uname -r` |
| cgroup v2 (unified hierarchy) | required | `stat -f --format="%T" /sys/fs/cgroup` → must print `cgroup2fs` |
| TC / clsact support | required | provided by modern Linux kernels |
| Docker | 20.10+ | `docker version` |
| Docker daemon access | required | use `sudo docker ...` or add your user to the `docker` group |
| Rust stable | 1.78+ | `rustup show` |
| Rust nightly | any | `rustup toolchain install nightly` |

### macOS / Windows (HTTP proxy mode)

| Requirement | Version |
|---|---|
| Rust stable | 1.78+ |
| Any OS with networking | ✓ |

> **macOS users:** You can run agent-vault locally without Docker. Just use proxy mode.

---

## Project layout

```
orouboros/
├── Cargo.toml                      # Cargo workspace
├── Dockerfile                      # Two-stage build: eBPF → daemon
├── docker-compose.yml              # Container orchestration (Linux/eBPF mode)
├── README.md                       # This file
├── agent-vault-common/             # no_std shared structs (kernel ↔ user boundary)
│   ├── Cargo.toml
│   └── src/lib.rs                  # TokenPair struct (C ABI)
├── agent-vault-ebpf/               # Kernel-space eBPF interceptor (Linux only)
│   ├── Cargo.toml
│   └── src/main.rs                 # TC egress classifier (nightly, BPF target)
└── agent-vault/                    # User-space daemon (dispatcher + proxy/eBPF modes)
    ├── Cargo.toml
    └── src/
        ├── main.rs                 # CLI dispatcher (clap, mode selection)
        ├── ebpf.rs                 # eBPF mode initialization (Linux only)
        └── proxy.rs                # HTTP/1.1 proxy (cross-platform)
└── xtask/                          # Build automation (cargo xtask)
    ├── Cargo.toml
    └── src/main.rs                 # eBPF + daemon build coordinator
```

---

## Build helpers (xtask)

This project includes **xtask** — a Rust-based build automation tool that coordinates eBPF (nightly) and daemon (stable) compilation:

```bash
# Build eBPF only (nightly toolchain, custom BPF target)
cargo xtask build-ebpf --release

# Build daemon only (stable toolchain)
cargo xtask build --release

# Build both in order (recommended)
cargo xtask build-all --release

# Get help
cargo xtask --help
```

> **Note:** xtask automatically selects the right toolchain and target— no need to memorize cargo flags!

### **macOS / Windows: HTTP proxy mode (simplest)**

No Docker needed — runs locally on `localhost:8888`:

```bash
# Build the daemon
cargo build --package agent-vault --release

# Start the proxy
./target/release/agent-vault --mode proxy

# In another terminal, configure your agent to use the proxy:
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888
export NO_PROXY=localhost,127.0.0.1

# Now run your AI agent — all requests will have tokens rewritten
# [FAKE_TOKEN_12345]  →  [REAL_SECRET_9999]
```

### **Linux: eBPF mode (zero-knowledge, Docker)**

```bash
# 1. Verify cgroup v2 on the host
stat -f --format="%T" /sys/fs/cgroup
# Expected: cgroup2fs

# 2. Build the container image (compiles both eBPF and daemon inside the image).
# Use sudo unless your user can access /var/run/docker.sock.
sudo docker compose build --no-cache --pull

# 3. Start the daemon (auto-detects eBPF mode)
sudo docker compose up

# Optional: override interface auto-detection if needed
sudo env AGENT_VAULT_IFACE=eth0 docker compose up

# 4. In another terminal, test from within the test cgroup:
echo $$ | sudo tee /sys/fs/cgroup/agent-vault-test/cgroup.procs >/dev/null
cat /proc/$$/cgroup

env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
  curl -4 -sS --http1.1 --noproxy '*' \
  -H "Authorization: Bearer FAKE_TOKEN_12345" \
  http://httpbin.org/headers
```

### **Linux: Manual build without Docker**

```bash
# Step 1: compile the eBPF kernel-side program
cargo +nightly build \
  --package agent-vault-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release

# Step 2: compile the user-space daemon (embeds the eBPF object via include_bytes!)
cargo build --package agent-vault --release

# Step 3: run with explicit eBPF mode
# Optional: set AGENT_VAULT_IFACE=eth0 if default route detection picks the wrong interface.
sudo ./target/release/agent-vault --mode ebpf
```

---

## CLI usage

```bash
# Auto-detect mode based on platform (eBPF on Linux, proxy on macOS/Windows)
./agent-vault

# Explicitly select mode
./agent-vault --mode ebpf    # Linux only
./agent-vault --mode proxy   # Any platform

# Help
./agent-vault --help
```

---

## Testing the intercept

### **macOS / Windows (proxy mode)**

```bash
# Terminal 1: start the proxy
./target/release/agent-vault --mode proxy

# Terminal 2: configure environment and make a request
export HTTP_PROXY=http://localhost:8888
curl -v -H "Authorization: Bearer FAKE_TOKEN_12345" http://httpbin.org/headers
```

**Expected response** (httpbin echoes back the rewritten token):
```json
{
  "headers": {
    "Authorization": "Bearer REAL_SECRET_9999",
    ...
  }
}
```

### **Linux (eBPF mode)**

In a **second terminal**, after the daemon is running:

```bash
# Move your shell into the test cgroup
echo $$ | sudo tee /sys/fs/cgroup/agent-vault-test/cgroup.procs >/dev/null
cat /proc/$$/cgroup

# Make a plain HTTP/1.1 request with the dummy token.
env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
  curl -4 -sS --http1.1 --noproxy '*' \
  -H "Authorization: Bearer FAKE_TOKEN_12345" \
  http://httpbin.org/headers
```

The cgroup check should print:

```text
0::/agent-vault-test
```

**Expected response** (httpbin echoes back what it received):
```json
{
  "headers": {
    "Authorization": "Bearer REAL_SECRET_9999",
    ...
  }
}
```

The agent sent `FAKE_TOKEN_12345`; the server saw `REAL_SECRET_9999`.
The daemon logs should also eventually include counters like:

```text
eBPF stats: packets=..., map_hits=..., tcp_payloads=1, token_found=1, rewrite_ok=1; ...
```

`token_found=1` and `rewrite_ok=1` confirm that the kernel program found the
dummy token and rewrote the packet payload.

---

## Architecture

### **eBPF mode (Linux — kernel-space interception)**

```
┌─────────────────────────────────────────────────────────┐
│  Docker Container (privileged, pid: host, net: host)    │
│                                                         │
│  ┌──────────────────────┐   eBPF HashMap (cgroup_id →  │
│  │  agent-vault daemon  │──── TokenPair)                │
│  │  (Tokio, user-space) │                   │           │
│  │  • loads eBPF prog   │                   ▼           │
│  │  • creates cgroup    │  ┌────────────────────────┐   │
│  │  • populates map     │  │ Kernel: TC egress      │   │
│  │  • attaches to iface │  │ classifier             │   │
│  └──────────────────────┘  │ 1. get skb cgroup ID   │   │
│                             │ 2. map lookup          │   │
│                             │ 3. find dummy token    │   │
│                             │ 4. overwrite w/ real   │   │
│                             │ 5. recompute checksum   │   │
│                             └────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### **Proxy mode (macOS/Windows/Linux — user-space HTTP proxy)**

```
┌─────────────────────────────────────────────────────────┐
│  macOS / Windows / Linux                                │
│                                                         │
│  Agent Process              proxy daemon                │
│      ↓                          ↓                       │
│   [FAKE_TOKEN]    →    localhost:8888                   │
│      ↓                          ↓                       │
│   HTTP request  →    Rewrite in headers/body            │
│      ↓                          ↓                       │
│                          [REAL_SECRET]                  │
│                              ↓                          │
│                         Server (httpbin, etc.)          │
└─────────────────────────────────────────────────────────┘
```

---

## Debugging

### **Proxy mode logs**

Set `RUST_LOG=info` or `RUST_LOG=debug` to see request interception:

```bash
RUST_LOG=info ./agent-vault --mode proxy
```

Expected output:
```
Intercepted POST request to api.example.com (token rewritten: FAKE_TOKEN_12345 → REAL_SECRET_9999)
```

### **eBPF mode logs**

The daemon logs runtime counters from eBPF maps every few seconds when traffic
changes:

```text
eBPF stats: packets=223, cgroup_zero=12, map_hits=7, tcp_payloads=1, token_found=1, rewrite_ok=1; last_cgroup_id=12202, last_packet_len=749, last_payload_offset=66, last_scan_len=122
```

Useful readings:

- `packets=0`: the TC program is not seeing traffic on the attached interface.
- `packets>0, map_hits=0`: traffic is visible, but no packet matched the test cgroup.
- `tcp_payloads>0, token_found=0`: HTTP payload was parsed, but the dummy token was not inside the scan window.
- `token_found=1, rewrite_ok=1`: the dummy token was found and rewritten successfully.

### Common failure modes

| Symptom | Cause (eBPF) | Fix |
|---|---|---|
| `Permission denied` on BPF load | Missing `CAP_BPF`/`CAP_NET_ADMIN` | Ensure container uses `privileged: true` |
| `permission denied` on Docker socket | User cannot access Docker daemon | Use `sudo docker compose ...` or add the user to the `docker` group |
| `bpf-linker` fails with `edition2024` | Builder image uses old Cargo | Rebuild with the current `rust:1-slim-bookworm` Dockerfile |
| cgroup ID is always 0 | PID namespace isolation | Use `pid: host` in docker-compose |
| Token not replaced | Process not in the test cgroup, wrong egress interface, or daemon not in host network namespace | Run `echo $$ \| sudo tee …/cgroup.procs` first; set `AGENT_VAULT_IFACE=eth0` if needed; Docker mode must use `network_mode: host` |
| TCP checksum rejected by server | Checksum was not recomputed after payload rewrite | Verify `BPF_F_RECOMPUTE_CSUM` is used |
| eBPF program rejected by verifier | Unbounded loop / missing bounds check | Check `ctx.len()` guard in `try_intercept` |
| `cgroup2fs` not found | Host uses cgroup v1 | Reboot with `systemd.unified_cgroup_hierarchy=1` |

---

## Mode comparison

| Feature | eBPF (Linux) | Proxy (macOS/Windows/Linux) |
|---|---|---|
| **Platform support** | Linux 5.8+ only | Any OS |
| **Zero-knowledge** | ✅ Yes (kernel-space) | ❌ No (agent sees proxy) |
| **Protocol support** | Plain IPv4/TCP payloads | HTTP/1.1 only |
| **Performance** | ⚡ Very fast | Good (one hop) |
| **Setup complexity** | Medium (Docker, cgroup v2) | Simple (run locally) |
| **HTTPS/TLS** | Payload inspection blocked | Not implemented; plain HTTP only |
| **Configuration** | Cgroup membership | `HTTP_PROXY` env var |

> Choose **eBPF mode** for Linux hosts where plain TCP payload rewriting is acceptable.
> Choose **proxy mode** for development on macOS/Windows (easier setup, HTTP/1.1 only).

---

## Out of scope (Phase 1)

### eBPF mode
- **HTTPS / TLS** — eBPF cannot inspect encrypted payloads without uprobes on the TLS library.
- **Token rotation** — the HashMap is populated once at startup; live updates not supported.
- **Multi-agent isolation** — one `TokenPair` per `cgroup_id`; separate cgroups needed for multiple agents.
- **Production hardening** — privilege scoping, seccomp profiles, read-only rootfs, BPF map pinning.

### Proxy mode
- **HTTP/2, gRPC, raw TCP** — proxy only handles HTTP/1.1 requests.
- **TLS client certificates** — no mutual TLS authentication support yet.
- **Token in TLS SNI / hostname** — only rewrites tokens in headers and bodies.

---

## Continuous Integration

### GitHub Actions

A workflow (`.github/workflows/build.yml`) automatically runs on every `push` and `pull_request` to `main` and `develop` branches:

1. **Sets up toolchains:** Installs stable + nightly Rust, system eBPF dependencies
2. **Builds eBPF:** `cargo xtask build-ebpf --release` (nightly, custom BPF target)
3. **Builds daemon:** Embedded eBPF bytecode, produces optimized binary
4. **Uploads artifacts:**
   - `agent-vault-ebpf-bytecode` — compiled eBPF object file
   - `agent-vault-binary` — agent-vault daemon executable

**For git tags** (releases), the workflow also creates a tarball with SHA256 checksum.

**Download artifacts:**
- Go to the workflow run → Artifacts section
- Extract binaries and run directly (no rebuild needed)

Example:
```bash
# From GitHub Actions Artifacts
./agent-vault --mode proxy   # on macOS
./agent-vault --mode ebpf    # on Linux (privileged)
```
