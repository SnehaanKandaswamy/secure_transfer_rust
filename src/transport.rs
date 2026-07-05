//BEST
use std::{
    collections::{BTreeMap, VecDeque},
    time::Instant,
};
use crate::config::WINDOW_SIZE;

pub struct InFlightPacket {
    pub bytes: usize,
    pub sent_at: Instant,
}
pub struct TransportState {

    // First packet not yet acknowledged
    pub send_base: u32,

    // Next sequence number to transmit
    pub next_seq: u32,

    // Largest cumulative ACK received
    pub highest_ack: u32,

    // Packets currently outstanding
    pub inflight: BTreeMap<u32, InFlightPacket>,

    // Packets waiting to be transmitted
    pub pending: VecDeque<(u32, Vec<u8>, usize)>,
}

impl TransportState {

    pub fn new() -> Self {

        Self {

            send_base: 0,

            next_seq: 0,

            highest_ack: 0,

            inflight: BTreeMap::new(),

            pending: VecDeque::new(),
        }
    }
    pub fn queue_packet(
    &mut self,
    chunk_id: u32,
    packet: Vec<u8>,
    bytes: usize,
) {
    self.pending.push_back((chunk_id, packet, bytes));
}
pub fn next_pending(
    &mut self,
) -> Option<(u32, Vec<u8>, usize)> {

    self.pending.pop_front()
}
pub fn can_send(&self) -> bool {
    true
}
pub fn mark_sent(
    &mut self,
    chunk_id: u32,
    bytes: usize,
) {
    self.inflight.insert(
        chunk_id,
        InFlightPacket {
            bytes,
            sent_at: Instant::now(),
        },
    );

    self.next_seq += 1;
}
pub fn acknowledge(&mut self, highest_contiguous: u32) {
    self.inflight.retain(|chunk_id, _| {
        *chunk_id >= highest_contiguous
    });
}
}