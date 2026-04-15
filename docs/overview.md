# Project Overview

## What This Repo Builds

This repo builds `agent-vault`, a Rust daemon that lets a local AI agent use a
placeholder credential while a separate interception layer substitutes the real
credential on the way out.

The core idea is:

```text
agent process sends fake token
agent-vault interception layer rewrites fake token to real token
upstream service receives real token
agent logs and memory contain only the fake token
```

The hard-coded demo tokens used by both modes are:

```text
dummy token: FAKE_TOKEN_12345
real token:  REAL_SECRET_9999
```

Both tokens are exactly 16 bytes. That matters because the eBPF map value uses
fixed `[u8; 16]` arrays and the packet rewrite is an equal-length replacement.

## Main Use Cases

- Demonstrate kernel-space credential injection with eBPF on Linux.
- Provide a simpler local proxy fallback for macOS, Windows, or Linux
  development.
- Keep real credentials out of agent-visible prompts, command history, logs,
  and process memory.

## Workspace Layout

```text
.
|-- Cargo.toml
|-- README.md
|-- agent-vault/
|   |-- Cargo.toml
|   `-- src/
|       |-- main.rs
|       |-- ebpf.rs
|       `-- proxy.rs
|-- agent-vault-common/
|   |-- Cargo.toml
|   `-- src/lib.rs
|-- agent-vault-ebpf/
|   |-- Cargo.toml
|   `-- src/main.rs
|-- xtask/
|   |-- Cargo.toml
|   `-- src/main.rs
|-- Dockerfile
|-- docker-compose.yml
`-- .github/workflows/build.yml
```

## Crates at a Glance

| Crate | Purpose | Target |
|---|---|---|
| `agent-vault` | User-space daemon and CLI | Host OS |
| `agent-vault-common` | Shared ABI structs | Host OS and BPF |
| `agent-vault-ebpf` | Kernel eBPF program | `bpfel-unknown-none` |
| `xtask` | Build helper commands | Host OS |

## Execution Modes

### eBPF Mode

On Linux, the daemon loads the compiled eBPF object, creates a cgroup at
`/sys/fs/cgroup/agent-vault-test`, attaches the eBPF program to egress traffic
from that cgroup, and inserts a `TokenPair` into a BPF hash map keyed by cgroup
ID.

Only processes moved into that cgroup are intended to be rewritten.

### Proxy Mode

On non-Linux platforms, and optionally on Linux, the daemon listens on
`127.0.0.1:8888`. A client must send HTTP traffic through this proxy, usually
by setting:

```bash
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888
export NO_PROXY=localhost,127.0.0.1
```

The current proxy implementation is a simple HTTP/1.1 forwarder. It does not
implement a full HTTPS `CONNECT` proxy.

