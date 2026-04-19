//! eBPF TC egress interceptor.
//!
//! Loaded by the user-space daemon; attaches to the host egress interface and
//! rewrites TCP payloads from registered cgroups that contain the dummy token,
//! replacing it with the real credential in-flight. The originating process
//! never sees the real token.
//!
//! # Build
//! ```
//! cargo +nightly build \
//!   --package agent-vault-ebpf \
//!   --target bpfel-unknown-none \
//!   -Z build-std=core \
//!   --release
//! ```
#![no_std]
#![no_main]

use agent_vault_common::TokenPair;
use aya_ebpf::bindings::TC_ACT_OK;
use aya_ebpf::{
    macros::{classifier, map},
    maps::{Array, HashMap},
    programs::TcContext,
    EbpfContext,
};

// ---------------------------------------------------------------------------
// eBPF map: cgroup_id (u64) → TokenPair
// ---------------------------------------------------------------------------
#[map(name = "TOKEN_MAP")]
static TOKEN_MAP: HashMap<u64, TokenPair> = HashMap::with_max_entries(64, 0);

#[map(name = "STATS")]
static STATS: Array<u64> = Array::with_max_entries(8, 0);

#[map(name = "DEBUG_VALUES")]
static DEBUG_VALUES: Array<u64> = Array::with_max_entries(8, 0);

// ---------------------------------------------------------------------------
// Packet offsets for TC egress.
//
// TC classifiers see packets from the Ethernet header (L2), so byte 0 is the
// first byte of the destination MAC address.
// ---------------------------------------------------------------------------
const ETH_HDR_LEN: u32 = 14;
const ETH_TYPE_OFFSET: u32 = 12;
const ETH_P_IPV4: u16 = 0x0800;
const IPV4_MIN_HDR_LEN: u32 = 20;
const TCP_MIN_HDR_LEN: u32 = 20;
const IPV4_PROTOCOL_OFFSET: u32 = 9;
const TCP_DATA_OFFSET_BYTE: u32 = 12;
const IPPROTO_TCP: u8 = 6;

const TOKEN_LEN: usize = 16;
const PAYLOAD_BUF: usize = 128;

// Ask bpf_skb_store_bytes to update the skb checksum after the payload rewrite.
const BPF_F_RECOMPUTE_CSUM: u64 = 1;

const STAT_PACKETS: u32 = 0;
const STAT_CGROUP_ZERO: u32 = 1;
const STAT_MAP_HITS: u32 = 2;
const STAT_TCP_PAYLOADS: u32 = 3;
const STAT_TOKEN_FOUND: u32 = 4;
const STAT_REWRITE_OK: u32 = 5;

const DEBUG_LAST_CGROUP_ID: u32 = 0;
const DEBUG_LAST_PACKET_LEN: u32 = 1;
const DEBUG_LAST_PAYLOAD_OFFSET: u32 = 2;
const DEBUG_LAST_SCAN_LEN: u32 = 3;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
#[classifier]
pub fn token_rewrite_egress(ctx: TcContext) -> i32 {
    match try_intercept(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, // on any error, let the original packet through
    }
}

// ---------------------------------------------------------------------------
// Core logic
// ---------------------------------------------------------------------------
fn try_intercept(ctx: &TcContext) -> Result<i32, i64> {
    // Step 1 — identify the cgroup that owns this skb.
    bump_stat(STAT_PACKETS);
    set_debug(DEBUG_LAST_PACKET_LEN, ctx.len() as u64);

    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_skb_cgroup_id(ctx.as_ptr() as *mut _) };
    set_debug(DEBUG_LAST_CGROUP_ID, cgroup_id);
    if cgroup_id == 0 {
        bump_stat(STAT_CGROUP_ZERO);
    }

    // Step 2 — is this cgroup registered in our map?
    let pair_ptr = match unsafe { TOKEN_MAP.get(&cgroup_id) } {
        Some(ptr) => ptr,
        None => return Ok(TC_ACT_OK), // not our cgroup; pass through
    };
    bump_stat(STAT_MAP_HITS);

    // Copy the TokenPair off the map pointer onto the BPF stack.
    // This is safe: TokenPair is repr(C) + Copy and the pointer is valid for the
    // lifetime of the BPF program invocation.
    // Copying to the stack also makes subsequent field accesses verifier-friendly.
    let pair: TokenPair = unsafe { *pair_ptr };

    // Step 3 — parse IPv4/TCP header lengths and compute the payload offset.
    let packet_len = ctx.len();
    if packet_len < ETH_HDR_LEN + IPV4_MIN_HDR_LEN + TCP_MIN_HDR_LEN + TOKEN_LEN as u32 {
        return Ok(TC_ACT_OK);
    }

    if load_be_u16(ctx, ETH_TYPE_OFFSET)? != ETH_P_IPV4 {
        return Ok(TC_ACT_OK);
    }

    let ip_offset = ETH_HDR_LEN;
    let version_ihl = load_byte(ctx, ip_offset)?;
    if version_ihl >> 4 != 4 {
        return Ok(TC_ACT_OK);
    }

    let ip_header_len = ((version_ihl & 0x0f) as u32) * 4;
    if ip_header_len < IPV4_MIN_HDR_LEN {
        return Ok(TC_ACT_OK);
    }

    if load_byte(ctx, ip_offset + IPV4_PROTOCOL_OFFSET)? != IPPROTO_TCP {
        return Ok(TC_ACT_OK);
    }

    if packet_len < ip_offset + ip_header_len + TCP_MIN_HDR_LEN + TOKEN_LEN as u32 {
        return Ok(TC_ACT_OK);
    }

    let tcp_offset = ip_offset + ip_header_len;
    let tcp_header_len = ((load_byte(ctx, tcp_offset + TCP_DATA_OFFSET_BYTE)? >> 4) as u32) * 4;
    if tcp_header_len < TCP_MIN_HDR_LEN {
        return Ok(TC_ACT_OK);
    }

    let payload_offset = tcp_offset + tcp_header_len;
    if packet_len < payload_offset + TOKEN_LEN as u32 {
        return Ok(TC_ACT_OK);
    }
    set_debug(DEBUG_LAST_PAYLOAD_OFFSET, payload_offset as u64);

    let payload_len = packet_len - payload_offset;
    let scan_len = if payload_len > PAYLOAD_BUF as u32 {
        PAYLOAD_BUF as u32
    } else {
        payload_len
    };
    set_debug(DEBUG_LAST_SCAN_LEN, scan_len as u64);
    bump_stat(STAT_TCP_PAYLOADS);

    // Step 5 — scan payload for exactly TOKEN_LEN bytes matching dummy_token.
    // The scan window is capped, but the packet may contain less than PAYLOAD_BUF
    // bytes. Load one fixed-size token candidate at a time so short HTTP
    // requests are still inspected without reading past the end of the skb.
    let mut found_offset: Option<u32> = None;

    'outer: for i in 0..(PAYLOAD_BUF - TOKEN_LEN + 1) {
        if i as u32 + TOKEN_LEN as u32 > scan_len {
            break;
        }

        let mut candidate = [0u8; TOKEN_LEN];
        let candidate_offset = payload_offset + i as u32;
        let ret = unsafe {
            aya_ebpf::helpers::bpf_skb_load_bytes(
                ctx.as_ptr() as *const _,
                candidate_offset,
                candidate.as_mut_ptr() as *mut _,
                TOKEN_LEN as u32,
            )
        };
        if ret < 0 {
            return Ok(TC_ACT_OK);
        }

        for j in 0..TOKEN_LEN {
            if candidate[j] != pair.dummy_token[j] {
                continue 'outer;
            }
        }
        found_offset = Some(candidate_offset);
        bump_stat(STAT_TOKEN_FOUND);
        break;
    }

    let write_offset = match found_offset {
        Some(o) => o,
        None => return Ok(TC_ACT_OK), // dummy token not in this packet; pass through
    };

    // Step 6 — overwrite dummy_token bytes with real_token in the packet.
    let ret = unsafe {
        aya_ebpf::helpers::bpf_skb_store_bytes(
            ctx.as_ptr() as *mut _,
            write_offset,
            pair.real_token.as_ptr() as *const _,
            TOKEN_LEN as u32,
            BPF_F_RECOMPUTE_CSUM,
        )
    };
    if ret < 0 {
        return Err(ret);
    }
    bump_stat(STAT_REWRITE_OK);

    Ok(TC_ACT_OK) // allow the *modified* packet
}

#[inline(always)]
fn bump_stat(index: u32) {
    if let Some(value) = STATS.get_ptr_mut(index) {
        unsafe {
            *value += 1;
        }
    }
}

#[inline(always)]
fn set_debug(index: u32, value: u64) {
    if let Some(slot) = DEBUG_VALUES.get_ptr_mut(index) {
        unsafe {
            *slot = value;
        }
    }
}

#[inline(always)]
fn load_byte(ctx: &TcContext, offset: u32) -> Result<u8, i64> {
    let mut byte = [0u8; 1];
    let ret = unsafe {
        aya_ebpf::helpers::bpf_skb_load_bytes(
            ctx.as_ptr() as *const _,
            offset,
            byte.as_mut_ptr() as *mut _,
            1,
        )
    };
    if ret < 0 {
        return Err(ret);
    }
    Ok(byte[0])
}

#[inline(always)]
fn load_be_u16(ctx: &TcContext, offset: u32) -> Result<u16, i64> {
    let high = load_byte(ctx, offset)? as u16;
    let low = load_byte(ctx, offset + 1)? as u16;
    Ok((high << 8) | low)
}

// Required for no_std + BPF target — the verifier never actually executes this.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
