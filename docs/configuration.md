# Configuration and Constants

Most runtime values are currently hard-coded. This makes the MVP easy to follow
but means the project is not yet configurable enough for production use.

## Token Values

eBPF mode:

```rust
const DUMMY_TOKEN: &[u8; 16] = b"FAKE_TOKEN_12345";
const REAL_TOKEN: &[u8; 16] = b"REAL_SECRET_9999";
```

Proxy mode:

```rust
const DUMMY_TOKEN: &str = "FAKE_TOKEN_12345";
const REAL_TOKEN: &str = "REAL_SECRET_9999";
```

Important constraints:

- The eBPF token fields are fixed 16-byte arrays.
- The dummy and real token are equal length.
- Equal-length replacement avoids changing packet length and `Content-Length`.
- Different token lengths would require broader changes.

## Proxy Listen Address

Proxy mode listens on:

```text
127.0.0.1:8888
```

Source:

```rust
const PROXY_LISTEN: &str = "127.0.0.1:8888";
```

This value is not currently exposed as a CLI flag.

## Cgroup Path

eBPF mode creates and attaches to:

```text
/sys/fs/cgroup/agent-vault-test
```

Source:

```rust
const CGROUP_PATH: &str = "/sys/fs/cgroup/agent-vault-test";
```

Traffic is rewritten only for processes that belong to this cgroup and match a
`TOKEN_MAP` entry.

## BPF Map

The eBPF map is:

```rust
#[map(name = "TOKEN_MAP")]
static TOKEN_MAP: HashMap<u64, TokenPair> = HashMap::with_max_entries(64, 0);
```

Key:

```text
cgroup_id: u64
```

Value:

```text
TokenPair { dummy_token, real_token }
```

Maximum entries:

```text
64
```

The current daemon inserts one entry at startup.

## eBPF Packet Constants

The eBPF program uses fixed header sizes:

```rust
const ETH_HDR_LEN: u32 = 14;
const IPV4_HDR_LEN: u32 = 20;
const TCP_HDR_LEN: u32 = 20;
const PAYLOAD_OFFSET: u32 = ETH_HDR_LEN + IPV4_HDR_LEN + TCP_HDR_LEN;
```

It scans:

```rust
const TOKEN_LEN: usize = 16;
const PAYLOAD_BUF: usize = 128;
```

This means the token must appear within the first 128 bytes loaded from the
assumed payload offset.

## Logging

The daemon initializes `env_logger`, so normal Rust logging can be controlled
with `RUST_LOG`:

```bash
RUST_LOG=info ./target/release/agent-vault --mode proxy
RUST_LOG=debug ./target/release/agent-vault --mode proxy
```

In eBPF mode, `aya_log::EbpfLogger::init` forwards `aya_log_ebpf::info!`
messages from the kernel program into the daemon logger.

