//! Block-pipelined reliable UDP transport.
//!
//! Replaces the old packet-level sliding-window skeleton (which was never
//! actually enforced -- `can_send()` always returned `true`) with something
//! that operates purely at the *block* granularity, per the design:
//!
//! - The file is split into fixed-size blocks of `PACKETS_PER_BLOCK` packets.
//! - At most `PIPELINE_DEPTH` blocks are "open" at any time on the sender
//!   side, and correspondingly at most that many blocks are ever actively
//!   tracked on the receiver side. No cwnd, no per-packet timers, no
//!   inflight packet maps.
//! - Retransmission is scoped to individual packets within one block, never
//!   a whole block or the whole file.
//!
//! This module holds both halves of that bookkeeping:
//! `SharedBlockCache` (sender: cached datagrams for retransmit) and
//! `SharedReceiverState` (receiver: per-block received bitmap + timers).
//!
//! PROGRESS: `SharedBlockCache` previously had a real race -- see the
//! comment on `fetch_for_retransmit` below and the matching one in
//! `sender.rs::block_sender_loop`. Fixed by reordering the sender loop to
//! cache a packet before sending it; nothing in this file changed to fix
//! it (this file's cache/lookup logic was always correct), only debug
//! `println!`s that had been added while chasing the bug were removed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::PACKETS_PER_BLOCK;

// =======================================================================
// Sender side
// =======================================================================

/// Per-block cache of packets the sender has transmitted, kept only long
/// enough to serve retransmission requests. Freed as soon as the block is
/// confirmed complete by the receiver.
pub struct BlockCacheEntry {
    packets: Vec<Option<Vec<u8>>>,
}

impl BlockCacheEntry {
    fn new(total: usize) -> Self {
        Self {
            packets: vec![None; total],
        }
    }
}

/// Shared between the block-sender loop (producer) and the control-ack
/// listener thread (consumer). A plain `Mutex` is sufficient: none of these
/// operations sit on a per-packet hot path once the network itself is the
/// bottleneck.
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

    pub fn record_sent(&self, block_id: u32, packet_in_block: u16, total: usize, datagram: Vec<u8>) {
        let mut guard = self.inner.lock().unwrap();
        let entry = guard
            .entry(block_id)
            .or_insert_with(|| BlockCacheEntry::new(total));
        entry.packets[packet_in_block as usize] = Some(datagram);
    }

    /// Serves a retransmission request for specific packet ids within a
    /// block. Because the sender loop now calls `record_sent` for a
    /// packet and waits for it to return *before* that packet is ever
    /// handed to the socket, any id the receiver could possibly have
    /// learned about as "missing" is guaranteed to already be present here
    /// -- there is no longer a window where a just-sent packet hasn't been
    /// cached yet.
    pub fn fetch_for_retransmit(&self, block_id: u32, ids: &[u16]) -> Vec<Vec<u8>> {
        let guard = self.inner.lock().unwrap();

        let Some(entry) = guard.get(&block_id) else {
            return Vec::new();
        };

        ids.iter()
            .filter_map(|&id| entry.packets.get(id as usize).and_then(|p| p.clone()))
            .collect()
    }

    pub fn complete(&self, block_id: u32) {
        self.inner.lock().unwrap().remove(&block_id);
    }

    pub fn open_block_count(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

impl Default for SharedBlockCache {
    fn default() -> Self {
        Self::new()
    }
}

// =======================================================================
// Shared helpers (block <-> chunk id arithmetic)
// =======================================================================

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

// =======================================================================
// Receiver side
// =======================================================================

/// Per-block receive-side bookkeeping.
///
/// IMPORTANT correctness note: `received` bits are set only once a packet
/// has been *decrypted and checksum-verified* (by a decryption worker), not
/// merely once its datagram has arrived off the wire. If we marked bits at
/// raw-arrival time instead, a corrupted-but-delivered packet could make a
/// block look complete before decryption ever runs, causing the ack manager
/// to send BlockComplete -- at which point the sender frees that packet's
/// cache entry, permanently losing the data. `last_activity` (used purely
/// for grace-period/idle-timeout *timing*, not correctness) is updated at
/// raw-arrival time instead, since that's the signal that reflects real
/// network activity.
pub struct BlockRxEntry {
    pub total: usize,
    received: Vec<bool>,
    received_count: usize,
    last_activity: Instant,
    end_seen: bool,
    rounds: u32,
}

impl BlockRxEntry {
    fn new(total: usize) -> Self {
        Self {
            total,
            received: vec![false; total],
            received_count: 0,
            last_activity: Instant::now(),
            end_seen: false,
            rounds: 0,
        }
    }

    pub fn is_complete(&self) -> bool {
        self.received_count == self.total
    }

    pub fn missing_ids(&self) -> Vec<u16> {
        self.received
            .iter()
            .enumerate()
            .filter(|(_, ok)| !**ok)
            .map(|(i, _)| i as u16)
            .collect()
    }
}

/// Shared receive-side block tracker. One entry per currently-active block;
/// removed as soon as that block is confirmed complete (or given up on) and
/// handed off, so memory stays bounded to roughly `PIPELINE_DEPTH` blocks
/// regardless of file size -- mirrors `SharedBlockCache` on the sender side.
#[derive(Clone)]
pub struct SharedReceiverState {
    inner: Arc<Mutex<HashMap<u32, BlockRxEntry>>>,
    // Block ids that have already been confirmed complete (or force-
    // completed) and removed from `inner`. Needed because the sender may
    // have queued more than one retransmit for the same still-missing
    // packet before the receiver's first "Missing" report actually reached
    // it - those extra copies are still in flight when the block finishes,
    // and arrive afterward. Without this guard, `touch_activity` (which
    // runs unconditionally on every raw packet arrival) would silently
    // recreate a brand-new, empty tracking entry for an already-finished
    // block via `entry(block_id).or_insert_with(...)`, restarting an entire
    // repair cycle for a block that was already done and double-counting
    // its completion.
    completed_blocks: Arc<Mutex<std::collections::HashSet<u32>>>,
}

impl SharedReceiverState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            completed_blocks: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
    }
   

    fn is_completed(&self, block_id: u32) -> bool {
        self.completed_blocks.lock().unwrap().contains(&block_id)
    }

    /// Called by the raw UDP receiver thread on every data packet, purely to
    /// keep the "is this block still active" timer fresh. Does NOT affect
    /// the received bitmap -- see the correctness note on `BlockRxEntry`.
    pub fn touch_activity(&self, block_id: u32, total: usize) {
        if self.is_completed(block_id) {
            return;
        }
        let mut guard = self.inner.lock().unwrap();
        let entry = guard
            .entry(block_id)
            .or_insert_with(|| BlockRxEntry::new(total));
        entry.last_activity = Instant::now();
    }

    /// Called by a decryption worker once a packet has been decrypted and
    /// its checksum verified. This is the only thing that can mark a
    /// packet "received" for ack purposes.
    pub fn mark_verified(&self, block_id: u32, packet_in_block: u16, total: usize) {
    if self.is_completed(block_id) {
        return;
    }

    let mut guard = self.inner.lock().unwrap();
    let entry = guard
        .entry(block_id)
        .or_insert_with(|| BlockRxEntry::new(total));

    let idx = packet_in_block as usize;

    if idx < entry.received.len() && !entry.received[idx] {
        entry.received[idx] = true;
        entry.received_count += 1;
    }
}

    /// Records that a BlockEnd datagram arrived for this block.
    pub fn mark_end_seen(&self, block_id: u32, total: usize) {
        if self.is_completed(block_id) {
            return;
        }
        let mut guard = self.inner.lock().unwrap();
        let entry = guard
            .entry(block_id)
            .or_insert_with(|| BlockRxEntry::new(total));
        entry.end_seen = true;
        entry.last_activity = Instant::now();
        
    }

    /// Returns block ids ready to be checked right now: either BlockEnd was
    /// seen and the grace period has elapsed since last activity, or the
    /// block has gone idle without ever seeing a BlockEnd (guards against a
    /// lost BlockEnd -- the block still gets checked eventually).
    ///
    /// The required wait backs off linearly with how many repair rounds
    /// have already been tried (capped at `idle_timeout`), instead of using
    /// a single fixed `grace` value forever. Without backoff, a block that
    /// genuinely needs more than one round trip to repair gets re-checked
    /// at the exact same short interval every time, re-requesting packets
    /// whose previous retransmit hasn't had a chance to land yet.
   pub fn ready_for_check(&self, grace: Duration, idle_timeout: Duration) -> Vec<u32> {
    let guard = self.inner.lock().unwrap();
    let now = Instant::now();


    

    let ready = guard
        .iter()
        .filter(|(_, e)| {
                let elapsed = now.duration_since(e.last_activity);

        // Block is complete.
        if e.is_complete() {
            // If we saw BlockEnd, wait the normal grace period.
            if e.end_seen {
                return elapsed >= grace;
            }

            // If BlockEnd was lost, don't wait forever.
            return elapsed >= idle_timeout;
        }

        // Block is incomplete.
        if e.end_seen {
            let required =
                grace.saturating_mul(e.rounds + 1).min(idle_timeout);
            elapsed >= required
        } else {
            elapsed >= idle_timeout
        }
        })
        .map(|(&id, _)| id)
        .collect::<Vec<_>>();


    ready
}
 /// Snapshots a block's state for building an ack, and bumps its retry
    /// round counter (checked against MAX_BLOCK_RETRY_ROUNDS by the caller).
    /// Returns `(is_complete, missing_ids, rounds_so_far)`.
    pub fn snapshot_and_tick(&self, block_id: u32) -> Option<(bool, Vec<u16>, u32)> {
        let mut guard = self.inner.lock().unwrap();
        let entry = guard.get_mut(&block_id)?;
        entry.rounds += 1;
        entry.last_activity = Instant::now();
        Some((entry.is_complete(), entry.missing_ids(), entry.rounds))
    }

    /// Removes a block's tracking state once it's confirmed complete (or
    /// given up on) so memory doesn't grow with the number of blocks seen
    /// over the life of the transfer. Also remembers the block id as
    /// completed so any late-arriving duplicate packets for it (e.g. an
    /// extra retransmit copy still in flight when the block finished) are
    /// recognized and ignored instead of recreating a fresh entry.
    pub fn remove(&self, block_id: u32) {

    self.inner.lock().unwrap().remove(&block_id);
    self.completed_blocks.lock().unwrap().insert(block_id);
}

}
impl Default for SharedReceiverState {
    fn default() -> Self {
        Self::new()
    }
}

