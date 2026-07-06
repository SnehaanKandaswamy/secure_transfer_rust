//! Sliding-window transport state with AIMD-style congestion control.
//!
//! This replaces the old "blast everything, then repair once at the end"
//! model. The sender keeps a bounded number of unacknowledged packets in
//! flight (`cwnd`) instead of firing the whole file as fast as the socket
//! will accept it. The receiver reports progress continuously - a
//! cumulative "highest contiguous" marker, plus which ids above that floor
//! it already has (selective ack) and which it's still missing - and the
//! sender reacts immediately:
//!
//!   * No losses reported  -> grow the window (we can push harder)
//!   * Losses reported     -> shrink the window and resend just those IDs
//!   * An ACK never shows  -> resend anyway once the packet times out
//!
//! This is the same shape as TCP's congestion control (and what QUIC/UDT/
//! KCP/ENet do over UDP), which is what lets it settle at whatever rate a
//! given network can sustain instead of needing per-network tuning.

use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use crate::config::{INITIAL_WINDOW, MAX_WINDOW, MIN_WINDOW, RTO_MS, WINDOW_GROWTH_STEP};

pub struct InFlightPacket {
    pub sent_at: Instant,
}

pub struct TransportState {
    /// Congestion window: the max number of packets allowed in flight
    /// (sent, not yet acknowledged one way or another) at any given moment.
    pub cwnd: usize,

    /// Lowest chunk id the receiver has confirmed contiguously up to.
    pub send_base: u32,

    /// Next fresh sequence number handed out by `mark_sent`.
    pub next_seq: u32,

    /// Packets sent but not yet acknowledged (cumulatively or selectively),
    /// keyed by chunk id.
    pub inflight: BTreeMap<u32, InFlightPacket>,

    /// Packets waiting for window space before their first transmission.
    pub pending: VecDeque<(u32, Vec<u8>, usize)>,
}

impl TransportState {
    pub fn new() -> Self {
        Self {
            cwnd: INITIAL_WINDOW,
            send_base: 0,
            next_seq: 0,
            inflight: BTreeMap::new(),
            pending: VecDeque::new(),
        }
    }

    pub fn queue_packet(&mut self, chunk_id: u32, packet: Vec<u8>, bytes: usize) {
        self.pending.push_back((chunk_id, packet, bytes));
    }

    pub fn next_pending(&mut self) -> Option<(u32, Vec<u8>, usize)> {
        self.pending.pop_front()
    }

    /// True while there's still room in the window for another fresh send.
    /// This is the actual flow-control gate: on a fast clean link `cwnd`
    /// climbs and this stays true almost always; on a congested link it
    /// stays false until acks free up room, which is what makes the sender
    /// naturally back off instead of overflowing queues downstream.
    pub fn can_send(&self) -> bool {
        self.inflight.len() < self.cwnd
    }

    pub fn mark_sent(&mut self, chunk_id: u32) {
        self.inflight.insert(chunk_id, InFlightPacket { sent_at: Instant::now() });
        self.next_seq = self.next_seq.max(chunk_id + 1);
    }

    /// Reset the in-flight timer for a chunk we just resent. Without this,
    /// a chunk reported `missing` by an ACK (and resent in that branch)
    /// keeps its original `sent_at`, so `timed_out()` can immediately
    /// consider it expired again and resend it a second time on the very
    /// next loop iteration, even though we just sent it moments ago.
    pub fn mark_retransmitted(&mut self, chunk_id: u32) {
        if let Some(p) = self.inflight.get_mut(&chunk_id) {
            p.sent_at = Instant::now();
        }
    }

    /// Apply one progress report from the receiver:
    ///   - everything below `highest_contiguous` is fully delivered
    ///   - `acked` lists ids *above* that floor the receiver already has
    ///     (selective ack) - a later chunk can arrive fine even while an
    ///     earlier one is still missing, and without this list those later
    ///     chunks could never be evicted from `inflight` just because the
    ///     cumulative floor hasn't caught up to them yet
    ///   - `missing` lists ids the receiver is still waiting on
    ///
    /// Returns the chunk ids to retransmit right now (empty if the round
    /// was clean, in which case the window also grows).
    pub fn on_ack(&mut self, highest_contiguous: u32, acked: &[u32], missing: &[u32]) -> Vec<u32> {
        self.send_base = self.send_base.max(highest_contiguous);

        // Cumulative floor: anything below it is done, whether or not we
        // still happen to have a stale inflight entry for it.
        self.inflight.retain(|&id, _| id >= highest_contiguous);

        // Selective ack: evict specific later ids the receiver confirms it
        // has, even though the contiguous floor hasn't reached them yet.
        // This is the fix for the freeze - previously only the cumulative
        // floor could evict anything, so one stuck low chunk id pinned
        // every chunk sent after it in `inflight` forever, `can_send()`
        // never went true again, and the window stuck at MIN_WINDOW with
        // nothing moving.
        for &id in acked {
            self.inflight.remove(&id);
        }

        if missing.is_empty() {
            self.grow();
        } else {
            self.shrink();
        }

        missing.to_vec()
    }

    /// Packets that have been in flight longer than the retransmit timeout
    /// without being acknowledged (cumulatively or selectively) or reported
    /// missing yet. Covers the case where the ACK itself got dropped, or a
    /// chunk was sent further ahead than the receiver's current report
    /// window covers.
    pub fn timed_out(&mut self) -> Vec<u32> {
        let now = Instant::now();
        let rto = Duration::from_millis(RTO_MS);

        let expired: Vec<u32> = self
            .inflight
            .iter()
            .filter(|(_, p)| now.duration_since(p.sent_at) > rto)
            .map(|(&id, _)| id)
            .collect();

        if expired.is_empty() {
            return expired;
        }

        for id in &expired {
            if let Some(p) = self.inflight.get_mut(id) {
                p.sent_at = now;
            }
        }

        self.shrink();
        expired
    }

    fn grow(&mut self) {
        self.cwnd = (self.cwnd + WINDOW_GROWTH_STEP).min(MAX_WINDOW);
    }

    fn shrink(&mut self) {
        self.cwnd = (self.cwnd / 2).max(MIN_WINDOW);
    }
}