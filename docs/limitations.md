# Limitations and Risks

This repo is best read as an MVP/prototype. The main concept is clear, but many
production concerns are intentionally not solved yet.

## eBPF Mode Limitations

### Linux Only

The eBPF path requires Linux, cgroup v2, BPF support, and privileges for program
loading and attachment.

### Plain Payload Visibility

The eBPF program rewrites bytes in packet payloads. It cannot inspect encrypted
TLS payloads at this layer. HTTPS requests will not expose the `Authorization`
header as plain text to this hook.

### Fixed Header Assumptions

The eBPF program assumes:

- Ethernet II header is 14 bytes.
- IPv4 header is 20 bytes.
- TCP header is 20 bytes.
- No IPv4 options.
- No TCP options.

Packets that do not match those assumptions may not be rewritten correctly.

### Limited Payload Scan

Only 128 bytes are loaded into the eBPF stack buffer. If the dummy token appears
later than that window, it will not be found.

### Equal-Length Tokens

The eBPF mode performs an in-place replacement of exactly 16 bytes. Supporting
variable-length credentials would require packet resizing or a different
injection strategy.

### One Startup Registration

The daemon inserts one `TokenPair` into `TOKEN_MAP` at startup. There is no API
for live token rotation, deletion, or per-agent dynamic registration.

### Privileged Runtime

The Docker Compose setup uses `privileged: true`, host PID namespace, and a
read-write bind mount of `/sys/fs/cgroup`. That is acceptable for a local demo,
but too broad for production.

## Proxy Mode Limitations

### HTTP/1.1 Only

The proxy manually parses simple HTTP/1.1 request text. It does not implement a
complete proxy protocol stack.

### No HTTPS CONNECT Handling

The startup instructions include `HTTPS_PROXY`, but the code does not implement
the `CONNECT` method required for normal HTTPS proxying. As implemented, proxy
mode should be treated as plain HTTP only.

### Upstream Port Is Always 80

The proxy forwards to:

```text
<host>:80
```

It does not preserve explicit ports from the original request target.

### Partial Request Reads

The proxy reads up to 4096 bytes from the client initially. Large headers,
chunked bodies, streaming bodies, and multi-read request bodies are not handled
robustly.

### Body Reconstruction Is Approximate

The current code rewrites a body string derived from the tail of the initial
buffer, not from a full HTTP parser. It works for small demos but can corrupt
or duplicate content in more complex requests.

## Build and Tooling Risks

### eBPF Object Must Exist Before Linux Daemon Build

The daemon embeds a release eBPF object by path. On Linux, build the eBPF crate
first or use:

```bash
cargo xtask build-all --release
```

### `cargo` Is Required

The current environment used to write these docs did not have `cargo` on
`PATH`, so builds/tests could not be executed here.

## Security Risks

### Real Secret Is Hard-Coded

`REAL_SECRET_9999` is compiled into the binary. A real system should fetch
secrets from an external secret manager or a locked-down local vault.

### Proxy Mode Is Not Zero-Knowledge in the Same Way

The agent knows it is configured to use a proxy, and the proxy runs in user
space. The Linux eBPF path is closer to the stated zero-knowledge goal because
the rewrite happens below the agent process.

### Logs Can Reveal Demo Values

The code and docs print the demo replacement pair. Production code should avoid
logging real credentials.

