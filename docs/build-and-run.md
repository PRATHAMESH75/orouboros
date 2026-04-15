# Build and Run Guide

## Current Environment Note

This repository expects the Rust toolchain to be available as `cargo`.
In the current checked environment, `cargo` was not found when attempting:

```bash
cargo metadata --no-deps --format-version 1
cargo test --workspace --exclude agent-vault-ebpf
```

Install Rust with `rustup` before building locally.

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
docker compose build
docker compose up
```

In another shell on the Linux host:

```bash
echo $$ | sudo tee /sys/fs/cgroup/agent-vault-test/cgroup.procs
curl -v -H "Authorization: Bearer FAKE_TOKEN_12345" http://httpbin.org/headers
```

Expected upstream-visible header:

```text
Authorization: Bearer REAL_SECRET_9999
```

## Docker Details

`Dockerfile` uses two stages:

- `builder`: installs Rust, nightly, `bpf-linker`, system eBPF dependencies,
  then builds eBPF bytecode and the daemon.
- `runtime`: copies only the `agent-vault` binary into a slim Debian image.

`docker-compose.yml` runs the daemon with:

- `privileged: true`
- `pid: host`
- `/sys/fs/cgroup:/sys/fs/cgroup`
- `RUST_LOG=info`

These settings are required by the current eBPF mode because the daemon must
create a host-visible cgroup and attach a BPF program to it.

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

