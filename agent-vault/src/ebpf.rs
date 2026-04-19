//! eBPF mode for agent-vault (Linux only).
//!
//! Loads the compiled eBPF TC egress interceptor, creates a test cgroup,
//! attaches the program to the default network interface, and populates the
//! kernel HashMap with the token pair.

use agent_vault_common::TokenPair;
use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap},
    programs::{tc, SchedClassifier, TcAttachType},
    Ebpf,
};
use std::{env, fs, os::unix::fs::MetadataExt};
use tokio::{signal, time};

// ---------------------------------------------------------------------------
// Configuration constants
// ---------------------------------------------------------------------------

const CGROUP_PATH: &str = "/sys/fs/cgroup/agent-vault-test";
const DUMMY_TOKEN: &[u8; 16] = b"FAKE_TOKEN_12345";
const REAL_TOKEN: &[u8; 16] = b"REAL_SECRET_9999";
const IFACE_ENV: &str = "AGENT_VAULT_IFACE";

const STAT_NAMES: [&str; 6] = [
    "packets",
    "cgroup_zero",
    "map_hits",
    "tcp_payloads",
    "token_found",
    "rewrite_ok",
];

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub async fn run_ebpf_mode() -> Result<()> {
    // 1. Load the eBPF object file compiled for bpfel-unknown-none.
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/agent-vault-ebpf"
    ))
    .context("Failed to load eBPF object. Did you run the eBPF build step first?")?;

    // 2. Kernel-side logging is intentionally disabled to keep the verifier
    // state space small for the packet-rewrite program.

    // 3. Create the test cgroup under the host-mounted cgroupfs (cgroup v2).
    fs::create_dir_all(CGROUP_PATH).with_context(|| {
        format!("Failed to create cgroup at {CGROUP_PATH}. Is cgroup v2 mounted?")
    })?;
    log::info!("Created cgroup at {}", CGROUP_PATH);

    // 4. Load a TC egress classifier and attach it to host outbound interfaces.
    let ifaces = egress_interfaces().context("Failed to determine egress network interfaces")?;
    let program: &mut SchedClassifier = bpf
        .program_mut("token_rewrite_egress")
        .context("eBPF program 'token_rewrite_egress' not found in object file")?
        .try_into()
        .context("Program is not of type SchedClassifier")?;

    program
        .load()
        .context("Failed to load eBPF program into the kernel")?;

    let mut attached_ifaces = Vec::new();
    for iface in ifaces {
        match tc::qdisc_add_clsact(&iface) {
            Ok(()) => log::info!("Added clsact qdisc to {}", iface),
            Err(e) if e.raw_os_error() == Some(17) => {
                log::info!("clsact qdisc already exists on {}", iface);
            }
            Err(e) => {
                log::warn!("Skipping {}: failed to add clsact qdisc: {}", iface, e);
                continue;
            }
        }

        match program.attach(&iface, TcAttachType::Egress) {
            Ok(_) => {
                log::info!("eBPF TC egress program attached to {}", iface);
                attached_ifaces.push(iface);
            }
            Err(e) => {
                log::warn!(
                    "Skipping {}: failed to attach TC egress program: {}",
                    iface,
                    e
                );
            }
        }
    }

    if attached_ifaces.is_empty() {
        anyhow::bail!("Failed to attach TC egress program to any interface");
    }

    // 5. Derive the cgroup ID from the inode number of the cgroup directory.
    let cgroup_id: u64 = fs::metadata(CGROUP_PATH)
        .context("Cannot stat cgroup path")?
        .ino();
    log::info!("cgroup_id = {}", cgroup_id);

    // 6. Insert the TokenPair into the shared eBPF HashMap.
    {
        let mut token_map: HashMap<_, u64, TokenPair> =
            HashMap::try_from(bpf.map_mut("TOKEN_MAP").context("TOKEN_MAP not found")?)
                .context("Failed to open TOKEN_MAP as HashMap")?;

        let pair = TokenPair {
            dummy_token: *DUMMY_TOKEN,
            real_token: *REAL_TOKEN,
        };
        token_map
            .insert(cgroup_id, pair, 0)
            .context("Failed to insert TokenPair into TOKEN_MAP")?;
    }
    log::info!("TokenPair registered for cgroup_id={}", cgroup_id);

    // 7. Print the welcome banner.
    print_banner(cgroup_id, &attached_ifaces.join(", "));

    let stats: Array<_, u64> = Array::try_from(bpf.map("STATS").context("STATS not found")?)
        .context("Failed to open STATS as Array")?;
    let debug_values: Array<_, u64> =
        Array::try_from(bpf.map("DEBUG_VALUES").context("DEBUG_VALUES not found")?)
            .context("Failed to open DEBUG_VALUES as Array")?;

    // 8. Block until SIGINT / Ctrl-C, logging packet counters while running.
    let mut ticker = time::interval(time::Duration::from_secs(5));
    let mut last_stats = [0u64; 6];
    loop {
        tokio::select! {
            result = signal::ctrl_c() => {
                result.context("Error waiting for Ctrl-C signal")?;
                break;
            }
            _ = ticker.tick() => {
                log_debug_counters(&stats, &debug_values, &mut last_stats);
            }
        }
    }

    // 9. Best-effort cleanup: remove the test cgroup.
    if let Err(e) = fs::remove_dir(CGROUP_PATH) {
        log::warn!("Could not remove cgroup {}: {}", CGROUP_PATH, e);
    } else {
        log::info!("Cgroup {} removed.", CGROUP_PATH);
    }

    println!("Shutting down. The snake rests.");
    Ok(())
}

// ---------------------------------------------------------------------------
// Banner
// ---------------------------------------------------------------------------

fn print_banner(cgroup_id: u64, iface: &str) {
    let cyan = "\x1b[36m";
    let green = "\x1b[32m";
    let yellow = "\x1b[33m";
    let bold = "\x1b[1m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    println!();
    println!("{cyan}{bold}");
    println!(r"          ≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋");
    println!(r"         ≋                                      ≋");
    println!(r"        ≋    ╔══════════════════════════════╗    ≋");
    println!(r"        ≋    ║  ⊙  o u r o u b o r o s  ⊙  ║    ≋");
    println!(r"        ≋    ║    a g e n t - v a u l t    ║    ≋");
    println!(r"        ≋    ║    zero-knowledge injector   ║    ≋");
    println!(r"        ≋    ║    [FAKE] ─────────► [REAL]  ║    ≋");
    println!(r"        ≋    ╚══════════════════════════════╝    ≋");
    println!(r"         ≋                                      ≋");
    println!(r"          ≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋≋");
    println!(r"   >≋─────────── TAIL · BODY · HEAD ────────────≋◄(@)");
    println!(r"         ╰──── mouth closes the ring (ouroboros) ─╯");
    println!("{reset}");

    println!(
        "{bold}  agent-vault{reset}  {dim}v{}  ·  eBPF mode{reset}",
        env!("CARGO_PKG_VERSION")
    );
    println!("{dim}  Zero-Knowledge eBPF Credential Injector{reset}");
    println!();

    println!("{green}  ✔{reset}  eBPF TC egress program loaded & attached");
    println!(
        "{green}  ✔{reset}  interface       {yellow}{bold}{}{reset}",
        iface
    );
    println!("{green}  ✔{reset}  cgroup created  {dim}{CGROUP_PATH}{reset}");
    println!("{green}  ✔{reset}  cgroup_id       {yellow}{bold}{cgroup_id}{reset}");
    println!(
        "{green}  ✔{reset}  dummy token     {dim}FAKE_TOKEN_12345{reset}  →  real token injected in-flight"
    );
    println!();

    println!("{bold}  How to test:{reset}");
    println!("  {dim}# 1. Move your shell into the intercepted cgroup:{reset}");
    println!("  echo $$ | sudo tee {CGROUP_PATH}/cgroup.procs");
    println!();
    println!("  {dim}# 2. Send a request with the dummy token:{reset}");
    println!("  curl -s -H \"Authorization: Bearer FAKE_TOKEN_12345\" http://httpbin.org/headers");
    println!();
    println!("  {dim}# expected: httpbin echoes back 'Bearer REAL_SECRET_9999'{reset}");
    println!();
    println!("  {yellow}Press Ctrl-C to stop.{reset}");
    println!();
}

fn log_debug_counters(
    stats: &Array<&aya::maps::MapData, u64>,
    debug_values: &Array<&aya::maps::MapData, u64>,
    last_stats: &mut [u64; 6],
) {
    let mut current = [0u64; 6];
    for (index, value) in current.iter_mut().enumerate() {
        *value = stats.get(&(index as u32), 0).unwrap_or(0);
    }

    if current == *last_stats {
        return;
    }

    *last_stats = current;

    let last_cgroup_id = debug_values.get(&0, 0).unwrap_or(0);
    let last_packet_len = debug_values.get(&1, 0).unwrap_or(0);
    let last_payload_offset = debug_values.get(&2, 0).unwrap_or(0);
    let last_scan_len = debug_values.get(&3, 0).unwrap_or(0);

    let mut counters = String::new();
    for (index, name) in STAT_NAMES.iter().enumerate() {
        if index > 0 {
            counters.push_str(", ");
        }
        counters.push_str(name);
        counters.push('=');
        counters.push_str(&current[index].to_string());
    }

    log::info!(
        "eBPF stats: {}; last_cgroup_id={}, last_packet_len={}, last_payload_offset={}, last_scan_len={}",
        counters,
        last_cgroup_id,
        last_packet_len,
        last_payload_offset,
        last_scan_len
    );
}

fn egress_interfaces() -> Result<Vec<String>> {
    if let Ok(iface) = env::var(IFACE_ENV) {
        let ifaces: Vec<String> = iface
            .split(',')
            .map(str::trim)
            .filter(|iface| !iface.is_empty())
            .map(ToOwned::to_owned)
            .collect();
        if !ifaces.is_empty() {
            return Ok(ifaces);
        }
    }

    active_non_loopback_interfaces()
        .with_context(|| format!("Set {IFACE_ENV}=<interface>, for example {IFACE_ENV}=eth0"))
}

fn active_non_loopback_interfaces() -> Result<Vec<String>> {
    let mut active = Vec::new();
    let mut fallback = Vec::new();

    for entry in fs::read_dir("/sys/class/net").context("Failed to list /sys/class/net")? {
        let entry = entry.context("Failed to read /sys/class/net entry")?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "lo" {
            continue;
        }

        fallback.push(name.clone());

        let operstate_path = entry.path().join("operstate");
        let operstate = fs::read_to_string(operstate_path).unwrap_or_default();
        let operstate = operstate.trim();
        if operstate == "up" || operstate == "unknown" {
            active.push(name);
        }
    }

    active.sort();
    active.dedup();
    if !active.is_empty() {
        return Ok(active);
    }

    fallback.sort();
    fallback.dedup();
    if !fallback.is_empty() {
        return Ok(fallback);
    }

    anyhow::bail!("no non-loopback network interfaces found")
}
