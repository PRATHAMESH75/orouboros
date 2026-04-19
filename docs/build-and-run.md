# Build and Run Guide

## Verified Commands

The current code has been checked locally with:

```bash
cargo xtask build-ebpf --release
cargo check --workspace --exclude agent-vault-ebpf
cargo build --package agent-vault --release
```

## Prerequisites

Common:

- Rust stable, recommended 1.78 or newer.
- `rustup`.

Linux eBPF mode:

- Linux kernel 5.8 or newer.
- cgroup v2 mounted at `/sys/fs/cgroup`.
- Rust nightly with `rust-src`.
- `bpf-linker`.
- eBPF-related system libraries: `llvm`, `clang`, `libelf-dev`.
- Elevated privileges or container capabilities for BPF loading and cgroup
  attachment.
- Docker daemon access. Use `sudo docker ...` unless your user belongs to the
  `docker` group.

Proxy mode:

- Rust stable.
- Any OS that can bind `127.0.0.1:8888`.

## Build with `xtask`

The workspace defines a Cargo alias:

```toml
[alias]
xtask = "run --manifest-path xtask/Cargo.toml --"
```

Recommended Linux build:

```bash
cargo xtask build-all --release
```

This builds:

1. `agent-vault-ebpf` with nightly for `bpfel-unknown-none`.
2. `agent-vault` with stable, embedding the eBPF object.

Build individual pieces:

```bash
cargo xtask build-ebpf --release
cargo xtask build --release
```

## Manual Linux Build

```bash
cargo +nightly build \
  --package agent-vault-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release

cargo build --package agent-vault --release
```

The order matters. On Linux, the daemon source uses `include_bytes!` to embed:

```text
target/bpfel-unknown-none/release/agent-vault-ebpf
```

If that file does not exist, the daemon build can fail.

## Run Proxy Mode

```bash
cargo build --package agent-vault --release
./target/release/agent-vault --mode proxy
```

In another shell:

```bash
export HTTP_PROXY=http://localhost:8888
export HTTPS_PROXY=http://localhost:8888
export NO_PROXY=localhost,127.0.0.1

curl -v -H "Authorization: Bearer FAKE_TOKEN_12345" http://httpbin.org/headers
```

Expected upstream-visible header:

```text
Authorization: Bearer REAL_SECRET_9999
```

## Run eBPF Mode with Docker Compose

```bash
sudo docker compose build --no-cache --pull
sudo docker compose up
```

In another shell on the Linux host:

```bash
echo $$ | sudo tee /sys/fs/cgroup/agent-vault-test/cgroup.procs >/dev/null
cat /proc/$$/cgroup

env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
  curl -4 -sS --http1.1 --noproxy '*' \
  -H "Authorization: Bearer FAKE_TOKEN_12345" \
  http://httpbin.org/headers
```

Expected upstream-visible header:

```text
Authorization: Bearer REAL_SECRET_9999
```

The cgroup check should show:

```text
0::/agent-vault-test
```

The daemon should also log counters similar to:

```text
eBPF stats: packets=..., map_hits=..., tcp_payloads=1, token_found=1, rewrite_ok=1; ...
```

`token_found=1` and `rewrite_ok=1` confirm that the eBPF program performed the
in-flight rewrite.

## Docker Details

`Dockerfile` uses two stages:

- `builder`: installs Rust, nightly, `bpf-linker`, system eBPF dependencies,
  then builds eBPF bytecode and the daemon.
- `runtime`: copies only the `agent-vault` binary into a slim Debian image.

`docker-compose.yml` runs the daemon with:

- `privileged: true`
- `pid: host`
- `network_mode: host`
- build network set to `host`
- `/sys/fs/cgroup:/sys/fs/cgroup`
- `RUST_LOG=info`

These settings are required by the current eBPF mode because the daemon must
create a host-visible cgroup and attach a TC BPF program in the same network
namespace used by the host shell running the test request.

The builder image uses the current stable Rust image (`rust:1-slim-bookworm`) so
that `cargo install bpf-linker` can build crates using Rust 2024 edition
metadata.

## CI

`.github/workflows/build.yml` runs on pushes to `main` and `develop`, and pull
requests to `main`.

The workflow:

1. Installs stable Rust.
2. Installs nightly Rust with `rust-src`.
3. Installs system eBPF dependencies.
4. Installs `bpf-linker`.
5. Runs `cargo xtask build-all --release`.
6. Uploads the eBPF bytecode and daemon binary as artifacts.

For git tags, it also creates a tarball and SHA256 checksum.
