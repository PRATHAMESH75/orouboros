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
    | TC egress hook     |            | localhost:8888     |
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
2. Creates `/sys/fs/cgroup/agent-vault-test`.
3. Discovers active non-loopback host interfaces, unless `AGENT_VAULT_IFACE`
   is set.
4. Loads the `token_rewrite_egress` TC classifier.
5. Adds `clsact` and attaches the classifier at TC egress.
6. Reads the cgroup directory inode as the cgroup ID.
7. Inserts `TokenPair` into `TOKEN_MAP` using that cgroup ID.
8. Opens `STATS` and `DEBUG_VALUES` maps for diagnostics.
9. Logs packet counters while waiting for Ctrl-C.

At packet egress time, the kernel program:

1. Gets the skb cgroup ID with `bpf_skb_cgroup_id()`.
2. Looks up that cgroup ID in `TOKEN_MAP`.
3. Parses Ethernet, IPv4, and TCP headers.
4. Searches the first 128 bytes of TCP payload for the dummy token.
5. Replaces the matching bytes with the real token.
6. Stores the replacement with checksum recomputation enabled.
7. Allows the modified packet through.

The diagnostics maps expose counters such as `packets`, `map_hits`,
`tcp_payloads`, `token_found`, and `rewrite_ok`. Seeing `token_found=1` and
`rewrite_ok=1` confirms that the kernel program rewrote at least one packet.

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
