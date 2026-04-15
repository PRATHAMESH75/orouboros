# Crate Guide

## Workspace Manifest

The root `Cargo.toml` defines a workspace with four members:

```toml
[workspace]
members = [
    "agent-vault-common",
    "agent-vault-ebpf",
    "agent-vault",
    "xtask",
]
default-members = ["agent-vault-common", "agent-vault"]
resolver = "2"
```

`agent-vault-ebpf` is not a default member because it must be built with the
nightly toolchain and the `bpfel-unknown-none` target.

## `agent-vault-common`

Path: `agent-vault-common/`

Purpose:

- Defines data structures shared between user space and eBPF.
- Avoids `std` by default so it can compile for the BPF target.
- Enables a `userspace` feature for `aya::Pod`.

Important file:

- `agent-vault-common/src/lib.rs`

Important type:

```rust
pub struct TokenPair {
    pub dummy_token: [u8; 16],
    pub real_token: [u8; 16],
}
```

Why it matters:

- The daemon writes `TokenPair` values into `TOKEN_MAP`.
- The kernel eBPF program reads those values during packet processing.

## `agent-vault-ebpf`

Path: `agent-vault-ebpf/`

Purpose:

- Builds the kernel-side `cgroup_skb/egress` program.
- Rewrites matching outbound packet payload bytes.
- Runs as `#![no_std]` and `#![no_main]`.

Important file:

- `agent-vault-ebpf/src/main.rs`

Important items:

- `TOKEN_MAP`: BPF hash map keyed by cgroup ID.
- `cgroup_skb_egress`: eBPF program entry point.
- `try_intercept`: packet rewrite implementation.

Build requirements:

- Rust nightly.
- `rust-src` for nightly.
- `bpf-linker`.
- Target `bpfel-unknown-none`.

## `agent-vault`

Path: `agent-vault/`

Purpose:

- Builds the main daemon binary.
- Selects eBPF mode or proxy mode.
- Owns the hard-coded token pair used by each mode.

Important files:

- `agent-vault/src/main.rs`: CLI and mode dispatch.
- `agent-vault/src/ebpf.rs`: eBPF object loading and cgroup setup.
- `agent-vault/src/proxy.rs`: local HTTP proxy.

Platform-specific dependencies:

- Linux builds enable `agent-vault-common/userspace` and include `aya` and
  `aya-log`.
- Non-Linux builds include `agent-vault-common` without Linux eBPF features.

## `xtask`

Path: `xtask/`

Purpose:

- Provides build automation through the Cargo alias in `.cargo/config.toml`.
- Hides the eBPF-specific build flags behind normal commands.

Commands:

```bash
cargo xtask build-ebpf --release
cargo xtask build --release
cargo xtask build-all --release
```

Implementation:

- `BuildEbpf` runs `rustup run nightly cargo build ... --target bpfel-unknown-none -Z build-std=core`.
- `Build` runs `cargo build --package agent-vault`.
- `BuildAll` runs eBPF first, then the daemon.

