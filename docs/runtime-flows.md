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
initialize eBPF logger
create /sys/fs/cgroup/agent-vault-test
open cgroup directory
find cgroup_skb_egress program in eBPF object
load program into kernel
attach program to cgroup egress
read cgroup inode as cgroup ID
open TOKEN_MAP
insert TokenPair for cgroup ID
print test instructions
wait for Ctrl-C
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
packet leaves cgroup
get current cgroup ID
look up TokenPair in TOKEN_MAP
if no map entry, allow packet unchanged
load payload bytes from fixed offset
scan for dummy token
if no match, allow packet unchanged
overwrite bytes with real token
recompute IP/TCP checksums
allow modified packet
```

The current payload offset is calculated as:

```text
Ethernet header: 14 bytes
IPv4 header:     20 bytes
TCP header:      20 bytes
payload offset:  54 bytes
```

The implementation assumes no IP options and no TCP options.

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

