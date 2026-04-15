# Architecture

Agent Vault has a small but important boundary between user space and kernel
space.

## High-Level Design

```text
                    +----------------------+
                    | agent-vault daemon   |
                    |                      |
                    | - parses CLI args    |
                    | - chooses mode       |
                    | - owns token config  |
                    +----------+-----------+
                               |
              +----------------+----------------+
              |                                 |
              v                                 v
    +--------------------+            +--------------------+
    | Linux eBPF mode    |            | HTTP proxy mode    |
    |                    |            |                    |
    | cgroup egress hook |            | localhost:8888     |
    | BPF hash map       |            | user-space rewrite |
    +--------------------+            +--------------------+
```

The binary entry point is `agent-vault/src/main.rs`. It uses `clap` to parse
`--mode` and dispatches to:

- `ebpf::run_ebpf_mode()` on Linux when mode is `ebpf` or omitted.
- `proxy::run_proxy_mode()` when mode is `proxy`.
- `proxy::run_proxy_mode()` on non-Linux platforms.

## User-Space Daemon

The `agent-vault` crate owns runtime orchestration:

- CLI parsing with `clap`.
- Async runtime with `tokio`.
- Logging with `env_logger`.
- Linux eBPF loading with `aya`.
- Proxy networking with `tokio::net::TcpListener`.

On Linux, `agent-vault/src/ebpf.rs` embeds the eBPF object with:

```rust
include_bytes!("../../target/bpfel-unknown-none/release/agent-vault-ebpf")
```

That means the release eBPF object must exist before building the daemon in
eBPF-capable Linux builds.

## Shared ABI

`agent-vault-common/src/lib.rs` defines:

```rust
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenPair {
    pub dummy_token: [u8; 16],
    pub real_token: [u8; 16],
}
```

This type crosses the user/kernel boundary through an eBPF hash map. The
important constraints are:

- `#[repr(C)]` keeps layout predictable.
- Fixed byte arrays avoid heap allocation.
- The eBPF crate can use the type in `no_std`.
- The user-space crate enables the `userspace` feature so `TokenPair` can
  implement `aya::Pod`.

## eBPF Data Path

The eBPF program declares a map:

```rust
#[map(name = "TOKEN_MAP")]
static TOKEN_MAP: HashMap<u64, TokenPair> = HashMap::with_max_entries(64, 0);
```

The key is a cgroup ID. The value is the dummy/real token pair.

At startup, the daemon:

1. Loads the compiled eBPF object.
2. Initializes eBPF logging with `aya-log`.
3. Creates `/sys/fs/cgroup/agent-vault-test`.
4. Opens that cgroup directory.
5. Loads and attaches the `cgroup_skb_egress` program.
6. Reads the cgroup directory inode as the cgroup ID.
7. Inserts `TokenPair` into `TOKEN_MAP` using that cgroup ID.
8. Waits for Ctrl-C.

At packet egress time, the kernel program:

1. Gets the current cgroup ID with `bpf_get_current_cgroup_id()`.
2. Looks up that cgroup ID in `TOKEN_MAP`.
3. Loads up to 128 bytes of payload into a stack buffer.
4. Searches for the dummy token.
5. Replaces the matching bytes with the real token.
6. Recomputes checksums.
7. Allows the modified packet through.

## Proxy Data Path

The proxy path is simpler and runs entirely in user space:

```text
agent -> localhost:8888 -> token rewrite -> upstream host:80
```

For each accepted TCP connection, `agent-vault/src/proxy.rs`:

1. Reads up to 4096 bytes from the client socket.
2. Parses the request line and `Host` header using string operations.
3. Rewrites `FAKE_TOKEN_12345` to `REAL_SECRET_9999` in headers.
4. Rewrites the same token in the request body.
5. Opens a TCP connection to `<host>:80`.
6. Sends the rewritten request upstream.
7. Streams the upstream response back to the client.

This implementation is intentionally small. It is useful for demos and local
HTTP tests, but it is not a complete production proxy.

