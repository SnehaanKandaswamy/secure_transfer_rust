//! Block-pipelined reliable UDP transport.
//!
//! Replaces the old packet-level sliding-window skeleton (which was never
//! actually enforced -- `can_send()` always returned `true`) with something
//! that operates purely at the *block* granularity, per the design:
//!
//! - The file is split into fixed-size blocks of `PACKETS_PER_BLOCK` packets.
//! - At most `PIPELINE_DEPTH` blocks are "open" (packets sent, not yet
//!   confirmed complete) at any time. This is the only form of flow control
//!   in the whole transport -- no cwnd, no per-packet timers, no inflight
//!   packet maps.
//! - Retransmission is scoped to individual packets within one block, never
//!   a whole block or the whole file.
//!
//! Memory bound: with `PIPELINE_DEPTH` blocks of `PACKETS_PER_BLOCK` packets
//! each cached at a time, worst-case cache size is
//! `PIPELINE_DEPTH * PACKETS_PER_BLOCK` packets -- a small, constant number
//! regardless of file size (e.g. 4 * 256 = 1024 packets, ~1.4 MB at
//! CHUNK_SIZE=1400).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::config::PACKETS_PER_BLOCK;

/// Per-block cache of packets the sender has transmitted, kept only long
/// enough to serve retransmission requests. Freed as soon as the block is
/// confirmed complete by the receiver.
pub struct BlockCacheEntry {
    /// Encoded, ready-to-resend UDP datagrams, indexed by packet_in_block.
    packets: Vec<Option<Vec<u8>>>,
}

impl BlockCacheEntry {
    fn new(total: usize) -> Self {
        Self {
            packets: vec![None; total],
        }
    }
}

/// Shared between the block-sender loop (producer, one insert per packet
/// sent) and the control-ack listener thread (consumer: one lookup per
/// retransmit request, one removal per completed block).
///
/// A plain `Mutex` is sufficient: none of these operations sit on a
/// per-packet hot path once the network itself is the bottleneck, and
/// contention between "insert newly sent packet" and "look up packets to
/// retransmit" is inherently rare (retransmits only happen for a handful of
/// packets per block, not the steady stream of new sends).
#[derive(Clone)]
pub struct SharedBlockCache {
    inner: Arc<Mutex<HashMap<u32, BlockCacheEntry>>>,
}

impl SharedBlockCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Records a freshly sent packet, creating the block's cache entry on
    /// first use. `total` is the number of packets in this block (handles
    /// the final, possibly-shorter block of the file).
    pub fn record_sent(&self, block_id: u32, packet_in_block: u16, total: usize, datagram: Vec<u8>) {
        let mut guard = self.inner.lock().unwrap();
        let entry = guard
            .entry(block_id)
            .or_insert_with(|| BlockCacheEntry::new(total));
        entry.packets[packet_in_block as usize] = Some(datagram);
    }

    /// Returns the cached datagrams for the requested packet ids, silently
    /// skipping any that aren't cached (defensive only -- under correct
    /// operation every requested id should have been sent and cached).
    pub fn fetch_for_retransmit(&self, block_id: u32, ids: &[u16]) -> Vec<Vec<u8>> {
        let guard = self.inner.lock().unwrap();
        let Some(entry) = guard.get(&block_id) else {
            return Vec::new();
        };
        ids.iter()
            .filter_map(|&id| entry.packets.get(id as usize).and_then(|p| p.clone()))
            .collect()
    }

    /// Frees a block's cache once the receiver has confirmed it complete.
    pub fn complete(&self, block_id: u32) {
        self.inner.lock().unwrap().remove(&block_id);
    }

    /// Number of blocks currently cached (sent but not yet confirmed
    /// complete). Exposed for logging/diagnostics; the pipeline depth is
    /// actually enforced via a semaphore-style permit channel (see
    /// sender.rs), not by polling this count.
    pub fn open_block_count(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

impl Default for SharedBlockCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Computes `(block_id, packet_in_block)` for a global chunk id.
#[inline]
pub fn block_of(chunk_id: u32) -> (u32, u16) {
    let per_block = PACKETS_PER_BLOCK as u32;
    (chunk_id / per_block, (chunk_id % per_block) as u16)
}

/// Global chunk id for a given `(block_id, packet_in_block)` pair -- the
/// inverse of `block_of`. This is what gets fed to the (unchanged) AES-CTR
/// encrypt/decrypt functions, so block framing never touches the crypto.
#[inline]
pub fn chunk_id_of(block_id: u32, packet_in_block: u16) -> u32 {
    block_id * PACKETS_PER_BLOCK as u32 + packet_in_block as u32
}

/// Number of packets belonging to `block_id`, accounting for the final
/// block of the file possibly being shorter than `PACKETS_PER_BLOCK`.
pub fn packets_in_block(block_id: u32, total_chunks: u32) -> usize {
    let start = block_id as u64 * PACKETS_PER_BLOCK as u64;
    let remaining = (total_chunks as u64).saturating_sub(start);
    remaining.min(PACKETS_PER_BLOCK as u64) as usize
}

/// Total number of blocks a file of `total_chunks` packets splits into.
pub fn total_blocks(total_chunks: u32) -> u32 {
    (total_chunks as u64).div_ceil(PACKETS_PER_BLOCK as u64) as u32
}
