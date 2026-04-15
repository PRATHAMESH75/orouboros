# Development Notes

## What to Change First for Real Use

The next practical improvements are:

1. Move token values out of constants and into a secure configuration path.
2. Add CLI flags or config for proxy address, cgroup path, dummy token, and
   secret source.
3. Replace the proxy's manual HTTP parsing with a real HTTP proxy
   implementation.
4. Add tests for proxy request rewriting.
5. Add Linux integration tests or a reproducible local script for eBPF mode.
6. Scope Docker privileges down from `privileged: true`.

## Suggested Test Strategy

Unit-level tests:

- Token replacement helper in proxy mode.
- Request parsing and host extraction once refactored behind testable helpers.
- `TokenPair` size and layout assertions.

Integration tests:

- Start proxy mode on a random local port.
- Run a local HTTP server.
- Send a request containing `FAKE_TOKEN_12345`.
- Assert the upstream server receives `REAL_SECRET_9999`.

Linux/eBPF smoke tests:

- Verify cgroup v2.
- Build eBPF bytecode.
- Run daemon with privileges.
- Move a test process into `/sys/fs/cgroup/agent-vault-test`.
- Send a plain HTTP request.
- Assert the upstream server receives the real token.

## Code Quality Observations

The repository is small and readable. The strongest separation is the
workspace-level split between:

- shared ABI data (`agent-vault-common`);
- kernel packet logic (`agent-vault-ebpf`);
- user-space runtime (`agent-vault`);
- build orchestration (`xtask`).

The highest-risk implementation area is `agent-vault/src/proxy.rs`, because it
manually parses and reconstructs HTTP traffic. The eBPF path is also narrow by
design: fixed offsets, fixed token sizes, and a short payload scan window.

## Common Debug Checklist

For eBPF mode:

```bash
stat -f --format="%T" /sys/fs/cgroup
```

Expected:

```text
cgroup2fs
```

Check that the eBPF object exists:

```bash
ls -lh target/bpfel-unknown-none/release/agent-vault-ebpf
```

Check that the daemon binary exists:

```bash
ls -lh target/release/agent-vault
```

Check that the test process is in the cgroup:

```bash
cat /sys/fs/cgroup/agent-vault-test/cgroup.procs
```

For proxy mode:

```bash
lsof -iTCP:8888 -sTCP:LISTEN
```

Send a plain HTTP request:

```bash
curl -v \
  -x http://localhost:8888 \
  -H "Authorization: Bearer FAKE_TOKEN_12345" \
  http://httpbin.org/headers
```

