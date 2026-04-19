# Runtime Flows

## CLI Mode Selection

`agent-vault/src/main.rs` defines:

```rust
enum Mode {
    Ebpf,
    Proxy,
}
```

`Ebpf` only exists on Linux builds because it is guarded with
`#[cfg(target_os = "linux")]`.

Mode behavior:

| Platform | No `--mode` | `--mode ebpf` | `--mode proxy` |
|---|---|---|---|
| Linux | eBPF mode | eBPF mode | proxy mode |
| macOS/Windows | proxy mode | unavailable | proxy mode |

## Linux eBPF Startup Flow

Function: `run_ebpf_mode` in `agent-vault/src/ebpf.rs`

```text
start daemon
load embedded eBPF bytes
create /sys/fs/cgroup/agent-vault-test
discover active non-loopback host interfaces, or read AGENT_VAULT_IFACE
find token_rewrite_egress program in eBPF object
load program into kernel
add clsact qdisc and attach program to TC egress on host interfaces
read cgroup inode as cgroup ID
open TOKEN_MAP
insert TokenPair for cgroup ID
open STATS and DEBUG_VALUES maps
print test instructions
log eBPF counters while waiting for Ctrl-C
remove cgroup on shutdown
```

The test cgroup path is:

```text
/sys/fs/cgroup/agent-vault-test
```

To send traffic through the eBPF path, a process must be moved into that
cgroup:

```bash
echo $$ | sudo tee /sys/fs/cgroup/agent-vault-test/cgroup.procs
```

## eBPF Packet Flow

Function: `try_intercept` in `agent-vault-ebpf/src/main.rs`

```text
packet exits a hooked host interface
get skb cgroup ID
look up TokenPair in TOKEN_MAP
if no map entry, allow packet unchanged
parse Ethernet, IPv4, and TCP headers
scan up to the first 128 bytes of TCP payload for dummy token
if no match, allow packet unchanged
overwrite bytes with real token
ask the kernel to recompute the skb checksum
allow modified packet
update STATS and DEBUG_VALUES counters
```

The payload offset is calculated from packet headers:

```text
Ethernet header: fixed 14 bytes
IPv4 header:     derived from IHL
TCP header:      derived from TCP data offset
```

The implementation handles IPv4 and TCP header options, but passes non-IPv4 and
non-TCP traffic through unchanged.

The daemon logs eBPF counters when traffic changes:

```text
eBPF stats: packets=..., cgroup_zero=..., map_hits=..., tcp_payloads=..., token_found=..., rewrite_ok=...; last_cgroup_id=..., last_packet_len=..., last_payload_offset=..., last_scan_len=...
```

## Proxy Startup Flow

Function: `run_proxy_mode` in `agent-vault/src/proxy.rs`

```text
start daemon
bind 127.0.0.1:8888
print proxy instructions
accept TCP connections forever
spawn one task per connection
```

## Proxy Request Flow

Function: `handle_http_connection` in `agent-vault/src/proxy.rs`

```text
read up to 4096 bytes from client
parse request line
extract Host header
rewrite dummy token in headers
rewrite dummy token in body
connect to host:80
send rewritten request
copy upstream response to client
```

Because the proxy connects to port 80, it is suitable for plain HTTP tests. It
does not implement HTTPS tunneling.
