# Agent Vault Documentation

This folder explains the repository from the perspective of a developer who
wants to understand, build, run, or extend it.

Agent Vault is a Rust workspace for credential injection. An agent sends a
dummy token such as `FAKE_TOKEN_12345`; Agent Vault replaces it with
`REAL_SECRET_9999` before the request reaches the upstream service.

The repository has two interception modes:

- Linux eBPF mode: a kernel TC egress classifier rewrites outbound TCP packet
  payloads for processes inside a configured cgroup.
- Proxy mode: a local user-space HTTP proxy on `127.0.0.1:8888` rewrites
  HTTP/1.1 headers and bodies before forwarding traffic.

## Reading Order

1. [Project Overview](overview.md)
2. [Architecture](architecture.md)
3. [Crate Guide](crates.md)
4. [Runtime Flows](runtime-flows.md)
5. [Build and Run Guide](build-and-run.md)
6. [Configuration and Constants](configuration.md)
7. [Limitations and Risks](limitations.md)
8. [Development Notes](development-notes.md)

## Source Files Worth Reading First

- `Cargo.toml`: workspace membership and default build members.
- `agent-vault/src/main.rs`: CLI dispatcher and mode selection.
- `agent-vault/src/ebpf.rs`: Linux eBPF loader, cgroup setup, map population.
- `agent-vault/src/proxy.rs`: local HTTP proxy implementation.
- `agent-vault-ebpf/src/main.rs`: kernel-side payload rewrite logic.
- `agent-vault-common/src/lib.rs`: shared `TokenPair` ABI type.
- `xtask/src/main.rs`: build automation for the eBPF program and daemon.
