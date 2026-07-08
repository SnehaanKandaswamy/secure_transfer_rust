//DEBUG VERSION WHICH WORKS
//BEST
//
// ======================================================================
// PROGRESS LOG -- concurrent state-machine audit + redesign
// ======================================================================
// ✔ ACK deadlock (ready_for_check ignoring completed blocks) -- fixed.
// ✔ Shared retransmission cache -- working.
// ✔ Send-before-cache race (BlockEnd sent-before-cached ordering) -- fixed
//   by writing to the cache before the socket send.
//
// ✘ ROOT CAUSE of the "BlockEnd for block 2 twice" panic: this was never
//   actually a double *emission*. It was two independent, unsynchronized
//   authorities disagreeing about the lifecycle of the same block:
//
//     1. block_sender_loop's local counter -- "I've sent every packet in
//        this block" (send-side truth).
//     2. control_ack_loop's receipt of a TCP `BlockAck::Complete` --
//        "the receiver confirms it has everything" (receive-side truth).
//        Critically, this same message is *also* sent when a block blows
//        through MAX_BLOCK_RETRY_ROUNDS and the receiver simply gives up
//        -- i.e. it is not even always a true confirmation.
//
//   Both authorities were allowed to mutate the *same* `SharedBlockCache`
//   HashMap independently: block_sender_loop wrote packets into a block's
//   entry via `record_sent`, while control_ack_loop could call
//   `cache.complete(block_id)` -- which *removes* that entry -- the
//   instant any Complete ack landed, including a force-completion that
//   raced ahead of the sender actually finishing that block. A Mutex only
//   guarantees the HashMap itself doesn't corrupt under concurrent
//   access; it guarantees nothing about the *protocol* two threads are
//   running against it. Sequence that produces exactly the observed log:
//
//     - control_ack_loop force-completes block 2 early (or a legitimate
//       Complete lands unusually fast) -> cache.complete(2) wipes the
//       entry.
//     - block_sender_loop is still mid-block, still calling
//       cache.record_sent(2, ..) for remaining packets -> `entry(2)
//       .or_insert_with(..)` silently recreates a *new*, partially-filled
//       entry for block 2.
//     - when the local `sent_count` for block 2 (which never itself
//       double-fires -- block ids are monotonic and never re-inserted)
//       finally reaches `block_total`, the assert reads this
//       just-recreated entry and finds it incomplete -> panic.
//     - the ack thread, meanwhile, already believes block 2 is done and
//       is blocked reading the next `BlockAck` for a block whose sender
//       side just died -- hence "ack thread alive" forever.
//
//   A second, independent defect was found while auditing point (6) of
//   the requested audit ("can encryption workers finish out of order"):
//   yes -- `NUM_WORKERS` workers pull off a shared queue and race to push
//   onto `send_tx`, so packets can arrive at the sender loop out of order
//   *across block boundaries*, not just within one block (within-block
//   reordering was already handled correctly: index writes + a plain
//   counter). If a packet from block N+1 is dequeued before the last
//   packet of block N, and PIPELINE_DEPTH blocks are already open,
//   `permits_rx.recv()` blocks the *only* thread that could ever consume
//   block N's still-pending last packet -- a second, independent
//   deadlock, unrelated to the panic above but from the same root cause:
//   no single owner of block lifecycle, and implicit ordering
//   assumptions nothing in the code enforced.
//
// REDESIGN: single-owner block manager (see `block_manager_loop` below).
//   `SharedBlockCache` (transport.rs) is no longer used by the sender --
//   block packet storage, counts, and the pipeline-depth budget are now
//   plain (non-`Arc`, non-`Mutex`) local state owned by exactly one
//   thread. Both encrypted chunks and incoming `BlockAck`s are funneled
//   into that one thread as *events*, via two dumb relay threads that
//   each own nothing but a socket/channel and forward what they read into
//   one shared channel, so "did we finish sending this block" and "did
//   the receiver confirm
//   it" are evaluated in one consistent, serialized timeline instead of
//   on two threads racing over a shared HashMap. A chunk that would open
//   a new block beyond the pipeline budget is buffered locally rather
//   than blocking the thread, which is what closes the encryption-worker
//   reordering deadlock too: the same thread that would otherwise block
//   on a permit is always still available to drain BlockAcks that free
//   one up.
// ======================================================================
use anyhow::Result;
use std::time::{Duration, Instant};
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs8::DecodePublicKey,
    Oaep,
    RsaPublicKey,
};
use sha2::Sha256;
use std::collections::HashMap;

use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
};

use crate::{
    checksum,
    config::{CHUNK_SIZE, DATA_PORT, RECEIVER_IP, KEY_PORT, PACKETS_PER_BLOCK, PIPELINE_DEPTH},
    crypto,
};

use crossbeam_channel::{bounded, Receiver, Sender as ChannelSender};

use crate::pipeline::{
    ReadChunk,
    EncryptedChunk,
    NUM_WORKERS,
};

use crate::protocol::{DataPacket, BlockEndPacket, BlockAck};
use crate::transport::{block_of, packets_in_block, total_blocks};

// ---------------------------------------------------------------------
// Per-block state, owned exclusively by `Sender::block_manager_loop`.
// Lives at module scope because `struct`/`enum`/`impl` items cannot be
// declared inside an `impl` block in Rust.
//
// State machine per block:
//
//   Sending { .. }  -- packets arriving, cache filling up
//        │  (sent_count reaches total)
//        ▼
//   AwaitingAck { .. }  -- BlockEnd emitted exactly once (end_emitted),
//        │                cache kept around only to serve retransmits
//        │  (BlockAck::Complete, real or force-completed)
//        ▼
//   removed from the map, pipeline slot released
// ---------------------------------------------------------------------
struct BlockState {
    total: usize,
    packets: Vec<Option<Vec<u8>>>,
    sent: usize,
    end_emitted: bool,
}

impl BlockState {
    fn new(total: usize) -> Self {
        Self {
            total,
            packets: vec![None; total],
            sent: 0,
            end_emitted: false,
        }
    }

    fn all_cached(&self) -> bool {
        self.packets.iter().take(self.total).all(|p| p.is_some())
    }
}

// ---------------------------------------------------------------------
// Scheduler fix #2: see PROGRESS LOG entry at the top of this file.
//
// The previous fix (separate `blocks: HashMap<u32, BlockState>`,
// `pending: HashMap<u32, Vec<EncryptedChunk>>`, and
// `resolved: HashSet<u32>`) closed the reopening bug in practice, but left
// a block's state spread across up to three different collections with
// nothing at the type level stopping a given id from ending up in more
// than one of them at once, and left `block_manager_loop` only draining
// `pending` reactively (inside the `Complete` arm) rather than before
// every wait on `events.recv()`.
//
// `BlockSlot` collapses all of that into one enum, and `block_states:
// HashMap<u32, BlockSlot>` is now the *only* place block lifecycle lives.
// A given block id has exactly one entry with exactly one variant at any
// time -- "existing in two scheduler states at once" is no longer
// something the code has to avoid by convention, it's something the type
// system doesn't allow. Entries are never removed once resolved (only
// bounded by `total_blocks`, which is known and finite), which is what
// makes "cannot be reopened or buffered twice" permanent rather than
// contingent on remembering to consult a side-set.
// ---------------------------------------------------------------------
enum BlockSlot {
    /// Chunks have arrived for this block, but the pipeline had no room
    /// to open it at the time. Never coexists with an `Open` or
    /// `Resolved` entry for the same id -- it's a different variant of
    /// the same map slot, not a separate collection.
    Pending(Vec<EncryptedChunk>),
    /// Actively open: accepting chunks, cache serving retransmits.
    Open(BlockState),
    /// Permanently resolved -- confirmed complete, or force-completed by
    /// the receiver after `MAX_BLOCK_RETRY_ROUNDS`. Terminal: nothing
    /// ever transitions a `Resolved` entry back to `Pending` or `Open`.
    /// This is what makes reopening structurally impossible -- there is
    /// no code path that ever calls `.entry(id).or_insert_with(..)` on an
    /// id without first checking whether it's already `Resolved`.
    Resolved,
}

/// Admits a chunk into an already-`Open` block. Caller guarantees
/// `block_states[block_id]` is `BlockSlot::Open(..)`.
fn place_chunk(
    block_id: u32,
    packet_in_block: u16,
    chunk: EncryptedChunk,
    block_states: &mut HashMap<u32, BlockSlot>,
    udp: &UdpSocket,
    bytes_sent: &mut u64,
    packets_sent: &mut u64,
    next_print: &mut u64,
) {
    let Some(BlockSlot::Open(entry)) = block_states.get_mut(&block_id) else {
        unreachable!(
            "place_chunk called for block {block_id}, packet {packet_in_block}, \
             but that block is not in the Open state"
        );
    };

    // Cache-before-send ordering, unchanged from the earlier fix.
    entry.packets[packet_in_block as usize] = Some(chunk.packet.clone());

    if let Err(e) = udp.send(&chunk.packet) {
        eprintln!("udp send failed (non-fatal, will retry): {e}");
    }

    *packets_sent += 1;
    *bytes_sent += chunk.bytes as u64;
    if *bytes_sent >= *next_print {
    println!(
        "[PROGRESS] Sent {:.1} MB",
        *bytes_sent as f64 / (1024.0 * 1024.0)
    );

    *next_print += 100 * 1024 * 1024; // Print every 100 MB
}
    entry.sent += 1;

    if entry.sent == entry.total && !entry.end_emitted {
        assert!(
            entry.all_cached(),
            "invariant violated: about to emit BlockEnd for block {block_id} \
             but the cache is missing at least one of its {} packets",
            entry.total
        );
        let end = BlockEndPacket::encode(block_id, entry.total as u32);

        if let Err(e) = udp.send(&end) {
            eprintln!("udp send failed (non-fatal, will retry): {e}");
        }
        entry.end_emitted = true;
    }

}

/// Admits one freshly-arrived chunk, or buffers it, depending on the
/// current state of its block. This -- together with `place_chunk` and
/// `drain_pending` below -- is the *only* code path that ever writes to
/// `block_states`, so a block's state transitions are always evaluated
/// against exactly one map, never two.
///
/// Reads the current slot first (a plain, short-lived immutable borrow
/// that yields owned/`Copy` data -- lengths, unit variants -- and is
/// fully released before any mutation), then acts on that snapshot. This
/// sidesteps the classic `match map.get_mut(k) { Some(v) => .., None =>
/// map.insert(..) }` borrow conflict entirely, rather than fighting it.
fn admit_or_buffer(
    chunk: EncryptedChunk,
    block_states: &mut HashMap<u32, BlockSlot>,
    open_slots: &mut usize,
    udp: &UdpSocket,
    total_chunks: u32,
    pipeline_depth: usize,
    bytes_sent: &mut u64,
    packets_sent: &mut u64,
    next_print: &mut u64,
) {
    let (block_id, packet_in_block) = block_of(chunk.chunk_id);

    enum Action {
        Drop,
        PlaceIntoOpen,
        AppendToPending,
        OpenAndPlace,
        BufferNew,
    }

    let action = match block_states.get(&block_id) {
        Some(BlockSlot::Resolved) => Action::Drop,
        Some(BlockSlot::Open(_)) => Action::PlaceIntoOpen,
        Some(BlockSlot::Pending(_)) => Action::AppendToPending,
        None if *open_slots < pipeline_depth => Action::OpenAndPlace,
        None => Action::BufferNew,
    };

    match action {
        Action::Drop => {
            // Stale leftover for a block the receiver has already
            // disposed of one way or another (real completion or a
            // force-complete give-up). Dropped here -- never buffered,
            // never used to reopen -- because its slot is `Resolved`.
        }
        Action::PlaceIntoOpen => {
            place_chunk(
                block_id, packet_in_block, chunk, block_states, udp, bytes_sent, packets_sent, next_print,
            );
        }
        Action::AppendToPending => {
            // Same block id already has a `Pending` bucket -- append to
            // the *existing* one. A block id can never end up with two
            // separate pending buckets, because there is only ever one
            // map entry per id.
            if let Some(BlockSlot::Pending(bucket)) = block_states.get_mut(&block_id) {
                bucket.push(chunk);
            }
        }
        Action::OpenAndPlace => {
            let total = packets_in_block(block_id, total_chunks);
            block_states.insert(block_id, BlockSlot::Open(BlockState::new(total)));
            *open_slots += 1;
            place_chunk(
                block_id, packet_in_block, chunk, block_states, udp, bytes_sent, packets_sent, next_print,
            );
        }
        Action::BufferNew => {
            block_states.insert(block_id, BlockSlot::Pending(vec![chunk]));
        }
    }
}

/// Opens as many `Pending` blocks as the pipeline currently has room for,
/// in ascending block-id order, admitting every chunk already buffered
/// for each one it opens. Unlike the old `pop_front`/`push_front`/`break`
/// loop -- which stopped forever the moment the single item at the front
/// of one flat FIFO wasn't admittable, silently starving every admittable
/// chunk queued behind it -- this looks up pending work *by block id*, so
/// a block that's ready to open is never blocked by some unrelated,
/// still-not-ready block that happened to arrive first.
///
/// Called both reactively (right after a `Complete` ack potentially frees
/// a slot) and, in `block_manager_loop` below, proactively at the top of
/// every loop iteration *before* it ever waits on `events.recv()` -- so
/// admittable pending work is never left sitting untried while the
/// manager blocks for a new event that isn't needed to make progress.
fn drain_pending(
    block_states: &mut HashMap<u32, BlockSlot>,
    open_slots: &mut usize,
    pipeline_depth: usize,
    udp: &UdpSocket,
    total_chunks: u32,
    bytes_sent: &mut u64,
    packets_sent: &mut u64,
    next_print: &mut u64,
) {
    while *open_slots < pipeline_depth {
        let next_id = block_states
            .iter()
            .filter_map(|(&id, slot)| matches!(slot, BlockSlot::Pending(_)).then_some(id))
            .min();

        let Some(next_id) = next_id else {
            break;
        };

        let bucket = match block_states.remove(&next_id) {
            Some(BlockSlot::Pending(v)) => v,
            _ => unreachable!("just found block {next_id} as Pending"),
        };

        let total = packets_in_block(next_id, total_chunks);
        block_states.insert(next_id, BlockSlot::Open(BlockState::new(total)));
        *open_slots += 1;

        for buffered in bucket {
            let (bid, pib) = block_of(buffered.chunk_id);
            debug_assert_eq!(bid, next_id, "pending bucket contained a chunk for the wrong block");
            place_chunk(bid, pib, buffered, block_states, udp, bytes_sent, packets_sent, next_print);
        }
    }
}

/// Events funneled into the single-owner block manager thread by the two
/// dumb relay threads (`Sender::chunk_relay`, `Sender::ack_relay`).
enum SenderEvent {
    Chunk(EncryptedChunk),
    Ack(BlockAck),
}

pub struct Sender {
    tcp: TcpStream,
    udp: UdpSocket,

    session_key: [u8; 32],
    nonce: [u8; 16],

    filename: String,
}

impl Sender {
    pub fn new(filename: &str) -> Result<Self> {
        let tcp = TcpStream::connect(
            format!("{}:{}", RECEIVER_IP, KEY_PORT),
        )?;
        tcp.set_nodelay(true)?;

        let udp = UdpSocket::bind("0.0.0.0:0")?;
        udp.connect(format!("{}:{}", RECEIVER_IP, DATA_PORT))?;
        use socket2::SockRef;

        SockRef::from(&udp)
            .set_send_buffer_size(64 * 1024 * 1024)?;
        println!("Sender UDP: {}", udp.local_addr()?);
        udp.set_nonblocking(false)?;

        let mut session_key = [0u8; 32];
        let mut nonce = [0u8; 16];

        OsRng.fill_bytes(&mut session_key);
        OsRng.fill_bytes(&mut nonce);

        Ok(Self {
            tcp,
            udp,
            session_key,
            nonce,
            filename: filename.to_string(),
        })
    }

    // ------------------------------------------------------------------
    // Reader thread -- UNCHANGED. Reads the file sequentially into
    // CHUNK_SIZE pieces and hands them to the encryption workers. Block
    // framing happens downstream in worker_thread, so this doesn't need to
    // know anything about blocks.
    // ------------------------------------------------------------------
    fn reader_thread(
        filename: String,
        tx: ChannelSender<ReadChunk>,
    ) -> Result<()> {
        use std::fs::File;
        use std::io::Read;

        let mut file = File::open(filename)?;
        let mut chunk_id = 0u32;

        loop {
            let mut buffer = vec![0u8; CHUNK_SIZE];

            let bytes = file.read(&mut buffer)?;

            if bytes == 0 {
                break;
            }

            buffer.truncate(bytes);
                println!(
                "[READER] chunk={} ",
                chunk_id,
            
            );
            tx.send(
                ReadChunk {
                    chunk_id,
                    data: buffer,
                }
            )?;

            chunk_id += 1;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Encryption workers -- crypto and checksum logic UNCHANGED. The only
    // difference from the old version is the wire header built around the
    // encrypted payload: it now carries (block_id, packet_in_block)
    // instead of a flat chunk_id, via DataPacket::encode. The global
    // chunk_id used for the AES-CTR counter is untouched.
    // ------------------------------------------------------------------
    fn worker_thread(
        rx: Receiver<ReadChunk>,
        tx: ChannelSender<EncryptedChunk>,
        key: [u8; 32],
        nonce: [u8; 16],
    ) -> Result<()> {
        while let Ok(chunk) = rx.recv() {
            let encrypted = crypto::encrypt_chunk(
                &chunk.data,
                &key,
                &nonce,
                chunk.chunk_id,
            );

            let hash =
                checksum::chunk_hash(&chunk.data);

            let (block_id, packet_in_block) = block_of(chunk.chunk_id);

            let packet = DataPacket::encode(
                block_id,
                packet_in_block,
                hash,
                &encrypted,
            );

            tx.send(
                EncryptedChunk {
                    chunk_id: chunk.chunk_id,
                    packet,
                    bytes: chunk.data.len(),
                }
            )?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Single-owner block state manager.
    //
    // Replaces `block_sender_loop` + `control_ack_loop`. Exactly one
    // thread now owns every piece of a block's lifecycle: its cached
    // packets, its sent-count, whether BlockEnd has been emitted, and
    // whether it has been confirmed/force-completed. Both event sources
    // that used to run on separate threads -- encrypted chunks arriving
    // from the workers, and BlockAcks arriving over TCP -- are read by a
    // tiny dedicated relay thread each and forwarded as `SenderEvent`s
    // into one channel this thread selects over. That turns "did we
    // finish sending this block" and "did the receiver confirm it" into
    // a single serialized timeline instead of two threads racing over a
    // shared `Mutex<HashMap<..>>`.
    //
    // State machine per block (`BlockState`):
    //
    //   Sending { .. }  -- packets arriving, cache filling up
    //        │  (sent_count reaches total)
    //        ▼
    //   AwaitingAck { .. }  -- BlockEnd emitted exactly once, cache kept
    //        │                around only to serve retransmits
    //        │  (BlockAck::Complete, real or force-completed)
    //        ▼
    //   removed from the map, pipeline slot released
    //
    // `BlockAck::Missing` is only ever served out of `Sending` or
    // `AwaitingAck` state -- if the block id isn't present at all (e.g. a
    // stray/duplicate ack after completion), it's a no-op instead of a
    // panic, and is logged as an anomaly rather than corrupting shared
    // state, because there is no second thread that could have raced to
    // remove it in the meantime.
    // ------------------------------------------------------------------
    // ------------------------------------------------------------------
    // Pure I/O relay: reads encrypted chunks off the pipeline channel and
    // forwards them as events. Touches no block state whatsoever.
    // ------------------------------------------------------------------
    fn chunk_relay(rx: Receiver<EncryptedChunk>, tx: ChannelSender<SenderEvent>) {
        while let Ok(chunk) = rx.recv() {
            
                println!(
                        "[WORKER] chunk={} block={}",
                        chunk.chunk_id,
                        chunk.chunk_id / PACKETS_PER_BLOCK as u32
                    );
            if tx.send(SenderEvent::Chunk(chunk)).is_err() {
                break;
            }
        }
    }

    // ------------------------------------------------------------------
    // Pure I/O relay: reads BlockAcks off the TCP control stream and
    // forwards them as events. Touches no block state whatsoever. Exits
    // (rather than hanging forever) as soon as the read errors out, which
    // is exactly what happens when `block_manager_loop` below shuts the
    // control socket down after every block is resolved.
    // ------------------------------------------------------------------
    fn ack_relay(mut control: TcpStream, tx: ChannelSender<SenderEvent>) {
        loop {
            let ack = match BlockAck::read_from(&mut control) {
    Ok(ack) => {
        match &ack {
            BlockAck::Complete { block_id } => {
                println!("[ACK RELAY] Complete {}", block_id);
            }
            BlockAck::Missing { block_id, missing } => {
                println!(
                    "[ACK RELAY] Missing {} ({} packets)",
                    block_id,
                    missing.len()
                );
            }
        }
        ack
    }
    Err(_) => break,

};
                if let BlockAck::Complete(id) = ack {
    println!("[ACK RELAY] COMPLETE {}", id);
}
                if tx.send(SenderEvent::Ack(ack)).is_err() {
                break;
            }
        }
    }

    // ------------------------------------------------------------------
    // The single owner of block lifecycle state. Sends data + BlockEnd
    // over UDP, retransmits on request, and frees blocks on confirmation
    // -- all from one thread, so none of it can race with itself.
    //
    // Backpressure: chunks that would open a block beyond `PIPELINE_DEPTH`
    // are buffered in `pending` instead of blocking the thread. This is
    // what closes the encryption-worker-reordering deadlock: this same
    // thread is always free to keep draining `events` (including the
    // BlockAcks that free up a slot), so a late-arriving packet for an
    // already-open block, or a block that only *looks* like it needs a
    // new slot because of out-of-order worker completion, never wedges
    // the pipeline the way blocking on a permit channel could.
    // ------------------------------------------------------------------
    fn block_manager_loop(
        udp: UdpSocket,
        events: Receiver<SenderEvent>,
        total_chunks: u32,
        pipeline_depth: usize,
        total_blocks: u32,
    ) -> Result<u64> {
        let mut bytes_sent = 0u64;
        let mut packets_sent = 0u64;
        let mut retransmitted = 0u64;
        let mut completed = 0u32;
        let mut next_print: u64 = 100 * 1024 * 1024;
        let start = Instant::now();
        // The single source of truth for every block's lifecycle. See the
        // `BlockSlot` doc comment above: an id is `Pending`, `Open`, or
        // `Resolved` -- never more than one of those at once, and never
        // any of them in a second collection.
        let mut block_states: HashMap<u32, BlockSlot> = HashMap::new();
        let mut open_slots: usize = 0;


        loop {
            // Drain BEFORE waiting on the channel, not just reactively
            // after a Complete ack. Nothing other than a freed slot
            // (tracked by `open_slots`) changes what's admittable, so this
            // is a cheap no-op whenever there's genuinely nothing to do --
            // but it guarantees pending work is never left untried while
            // this thread blocks on `events.recv()` for an event that
            // isn't actually needed to make progress.
            drain_pending(
                &mut block_states,
                &mut open_slots,
                pipeline_depth,
                &udp,
                total_chunks,
                &mut bytes_sent,
                &mut packets_sent,
                &mut next_print,
            );
            
            if completed >= total_blocks {
    println!(
        "[EXIT] completed={} total={} open_slots={}",
        completed,
        total_blocks,
        open_slots
    );
    break;
}           
            println!("[BLOCK MANAGER] waiting for event");
            let event = match events.recv() {
                Ok(event) => {
                println!("[BLOCK MANAGER] got event");
                event
                }Err(_) => {
                    // Both relay threads have exited and the channel is
                    // empty (crossbeam only reports Disconnected once
                    // there is nothing left buffered to receive first) --
                    // no further event will ever arrive. Make one last
                    // attempt to drain anything admittable (in case the
                    // very last event processed freed a slot) before
                    // treating this as terminal, per "channel closure only
                    // terminates after ... all pending work has been
                    // processed".
                    drain_pending(
                        &mut block_states,
                        &mut open_slots,
                        pipeline_depth,
                        &udp,
                        total_chunks,
                        &mut bytes_sent,
                        &mut packets_sent,
                        &mut next_print,
                    );
                    for (id, slot) in &block_states {
                        if let BlockSlot::Open(_) = slot {
                            println!("[DEBUG] STILL OPEN BLOCK {}", id);
                        }
                    }

                    if completed >= total_blocks {
                        break;
                    }

                    let stuck_pending: usize = block_states
                        .values()
                        .map(|slot| match slot {
                            BlockSlot::Pending(v) => v.len(),
                            _ => 0,
                        })
                        .sum();
                    let stuck_pending_blocks = block_states
                        .values()
                        .filter(|slot| matches!(slot, BlockSlot::Pending(_)))
                        .count();

                    return Err(anyhow::anyhow!(
                        "event channel closed with {}/{} blocks unresolved: \
                         {open_slots} block(s) still open awaiting an ack that will \
                         never arrive, {stuck_pending} chunk(s) buffered across \
                         {stuck_pending_blocks} block(s) that never got a pipeline \
                         slot -- the connection was lost before the transfer finished",
                        total_blocks - completed,
                        total_blocks,
                    ));
                }
            };

            match event {
                SenderEvent::Chunk(chunk) => {
                    admit_or_buffer(
                        chunk,
                        &mut block_states,
                        &mut open_slots,
                        &udp,
                        total_chunks,
                        pipeline_depth,
                        &mut bytes_sent,
                        &mut packets_sent,
                        &mut next_print,
                    );
                }
                SenderEvent::Ack(BlockAck::Missing { block_id, missing }) => {
                
                    // Read-only snapshot of exactly the cached packets we'd
                    // resend, taken and released before any further access
                    // to `block_states` (and before any I/O), so there's no
                    // borrow spanning the actual `udp.send` calls below.
                    let cached: Option<Vec<Vec<u8>>> = match block_states.get(&block_id) {
                        Some(BlockSlot::Open(entry)) => Some(
                            missing
                                .iter()
                                .filter_map(|&id| entry.packets.get(id as usize).and_then(|p| p.clone()))
                                .collect(),
                        ),
                        // `Resolved`: stray/late repeat ack, ignore.
                        // `Pending`: not open yet, nothing cached to resend.
                        // Missing entirely: unknown to us, ignore.
                        _ => None,
                    };

                    if let Some(packets) = cached {
                       
                        for packet in &packets {
                            if let Err(e) = udp.send(packet) {
                            eprintln!("udp resend failed (non-fatal, will retry): {e}");
                        } else {
                            retransmitted += 1;
                        }
                       
                    }
                }
                }
                SenderEvent::Ack(BlockAck::Complete { block_id }) => {
                    // Snapshot what this id currently is (owned data only,
                    // borrow released immediately) before deciding how to  
                    // resolve it -- avoids the get/insert borrow conflict
                    // entirely instead of fighting it.
                    println!("[BLOCK MANAGER] COMPLETE {}", id);
                    println!("[ACK RX] Complete received for {}", block_id);
                    println!("[SENDER] Completed block {}", block_id);
                
                    
                    #[derive(Debug)]
                    enum Prior {
                        AlreadyResolved,
                        WasOpen,
                        WasPending(usize),
                        Unseen,
                    }
                    println!(
                            "[ACK RX] map size={} open_slots={} completed={}",
                            block_states.len(),
                            open_slots,
                            completed
                        );
                    let prior = match block_states.get(&block_id) {
                        Some(BlockSlot::Resolved) => Prior::AlreadyResolved,
                        Some(BlockSlot::Open(_)) => Prior::WasOpen,
                        Some(BlockSlot::Pending(bucket)) => Prior::WasPending(bucket.len()),
                        None => Prior::Unseen,
                    };

                    match prior {
                        Prior::AlreadyResolved => {
                            // Duplicate Complete (e.g. two force-completes,
                            // or a genuine Complete after an earlier
                            // force-complete for the same id). Must NOT
                            // bump `completed` again, or the loop could
                            // exit having never actually resolved every
                            // block.
                                println!("[ACK RX] {} already resolved", block_id);
                            println!(
                                "[WARN] duplicate Complete ack for already-resolved block {block_id} -- ignoring"
                            );
                        }
                        Prior::WasOpen => {
                                println!("[ACK RX] {} was open -> resolving", block_id);
                            block_states.insert(block_id, BlockSlot::Resolved);
                            open_slots -= 1;
                            completed += 1;
                             println!(
                                    "[ACK RX] completed={}/{} open_slots={}",
                                    completed,
                                    total_blocks,
                                    open_slots
                                );
                           
                    
                        }
                        Prior::WasPending(n) => {
                            // The receiver resolved (very likely
                            // force-completed) this block before the
                            // sender ever got a pipeline slot to open it.
                            // Whatever's buffered for it is now moot --
                            // discard it. Never admitted, never reopened.
                             println!("[ACK RX] {} was pending ({})", block_id, n);
                            println!(
                                "[WARN] Complete ack for block {block_id} while {n} chunk(s) were \
                                 still buffered (never opened) -- discarding and marking resolved \
                                 so it can never be opened later"
                            );
                            block_states.insert(block_id, BlockSlot::Resolved);
                            completed += 1;
   
                          
                        }
                        Prior::Unseen => {
                            // Force-completed before the sender ever saw a
                            // single chunk for it. Mark resolved
                            // preemptively so nothing can ever open it.
                            println!("[ACK RX] {} unseen", block_id);
                            println!(
                                "[WARN] Complete ack for block {block_id} that the sender never saw \
                                 a single chunk for -- marking resolved preemptively"
                            );
                            block_states.insert(block_id, BlockSlot::Resolved);
                            completed += 1;
                                  
                            
                        }
                    }
                               println!(
    "[DEBUG] block={} prior={:?} completed={}/{} open_slots={}",
    block_id,
    prior,
    completed,
    total_blocks,
    open_slots
);
     
                }
            }
            
            if total_blocks - completed <= 5 {
    println!(
        "========== Remaining {} ==========",
        total_blocks - completed
    );

    for (id, slot) in &block_states {
        match slot {
            BlockSlot::Open(_) => println!("OPEN {}", id),
            BlockSlot::Pending(_) => println!("PENDING {}", id),
            BlockSlot::Resolved => {}
        }
    }

    println!("==================================");
}

           
        }

        println!("==============================");
        println!("Block manager statistics");
        println!("Packets sent        : {}", packets_sent);
        println!("Packets retransmitted: {}", retransmitted);
        println!("Blocks resolved      : {}", completed);
        println!("==============================");

        Ok(bytes_sent)
    }

    fn handshake(&mut self) -> Result<()> {
        println!("Waiting for receiver public key...");

        let mut len = [0u8; 4];

        self.tcp.read_exact(&mut len)?;

        let key_len = u32::from_be_bytes(len) as usize;

        let mut pem = vec![0u8; key_len];

        self.tcp.read_exact(&mut pem)?;

        let pem = String::from_utf8(pem)?;

        let public =
            RsaPublicKey::from_public_key_pem(&pem)?;

        println!("Public key received.");

        let encrypted =
            public.encrypt(
                &mut OsRng,
                Oaep::new::<Sha256>(),
                &self.session_key,
            )?;

        self.tcp.write_all(
            &(encrypted.len() as u32).to_be_bytes(),
        )?;

        self.tcp.write_all(&encrypted)?;

        self.tcp.write_all(&self.nonce)?;

        println!("Handshake complete.");
        Ok(())
    }

    // ------------------------------------------------------------------
    // Orchestrates reader -> encryption workers -> block sender, plus a
    // concurrent control-ack listener that handles repairs and completion
    // as they happen (rather than as a separate phase after the initial
    // blast, as the old transport did).
    // ------------------------------------------------------------------
    fn send_file(
        &mut self,
        total_chunks: u32,
    ) -> Result<u64> {
        println!("Opening file...");

        // Bounded, not unbounded: this is what keeps memory usage constant
        // regardless of file size. Capacity is sized generously relative
        // to the pipeline window so the reader/encryption stages can stay
        // ahead of the network without effectively caching the whole file.
        let channel_capacity = PIPELINE_DEPTH * PACKETS_PER_BLOCK * 2;
        let (read_tx, read_rx) = bounded::<ReadChunk>(channel_capacity);
        let (send_tx, send_rx) = bounded::<EncryptedChunk>(channel_capacity);

        let filename = self.filename.clone();

        let key = self.session_key;
        let nonce = self.nonce;

        let udp_send = self.udp.try_clone()?;
        let control_stream = self.tcp.try_clone()?;
        // Kept only so we can force `ack_relay`'s blocking TCP read to
        // error out once every block is resolved -- see the shutdown call
        // near the end of this function.
        let control_stream_for_shutdown = self.tcp.try_clone()?;

        let total_blocks_count = total_blocks(total_chunks);

        // Unbounded on purpose: this channel just merges two event
        // sources for a single consumer thread. Backpressure is enforced
        // upstream, by the bounded `send_rx` channel (which in turn
        // throttles the encryption workers) and by `block_manager_loop`'s
        // own `pending` buffer -- not by this channel, so that a burst of
        // chunks can never make an incoming BlockAck wait behind them.
        let (events_tx, events_rx) = crossbeam_channel::unbounded::<SenderEvent>();

        // Reader
        let reader = std::thread::spawn(move || {
            Self::reader_thread(
                filename,
                read_tx,
            )
        });

        // Encryption workers
        let mut workers = Vec::new();

        for _ in 0..NUM_WORKERS {
            let rx = read_rx.clone();
            let tx = send_tx.clone();
            let key = key;
            let nonce = nonce;

            workers.push(
                std::thread::spawn(move || {
                    Self::worker_thread(
                        rx,
                        tx,
                        key,
                        nonce,
                    )
                })
            );
        }

        drop(send_tx);

        // Dumb I/O relay: encrypted chunks -> events. Owns no block state.
        let chunk_events_tx = events_tx.clone();
        let chunk_relay_handle = std::thread::spawn(move || {
            Self::chunk_relay(send_rx, chunk_events_tx);
        });

        // Dumb I/O relay: BlockAcks off TCP -> events. Owns no block state.
        let ack_events_tx = events_tx.clone();
        let ack_relay_handle = std::thread::spawn(move || {
            Self::ack_relay(control_stream, ack_events_tx);
        });
        drop(events_tx);

        // The single owner of every block's lifecycle. Runs until every
        // block has been resolved (confirmed complete or force-completed).
        let manager_handle = std::thread::spawn(move || {
            Self::block_manager_loop(
                udp_send,
                events_rx,
                total_chunks,
                PIPELINE_DEPTH,
                total_blocks_count,
            )
        });

        println!("[DEBUG] Waiting for reader...");
reader.join().unwrap()?;
println!("[DEBUG] Reader exited.");

for (i, worker) in workers.into_iter().enumerate() {
    println!("[DEBUG] Waiting for worker {i}...");
    worker.join().unwrap()?;
    println!("[DEBUG] Worker {i} exited.");
}

println!("[DEBUG] All workers exited.");
        println!("[SENDER] Waiting for block manager...");

        let bytes_sent = manager_handle.join().unwrap()?;

        println!("[SENDER] Block manager exited.");
        // The manager has resolved every block, but `ack_relay` is still
        // blocked in a TCP read waiting for a message the receiver will
        // never send again. Force it to unblock instead of leaving it
        // (harmlessly, but permanently) parked -- this is the fix for
        // "the ack thread can wait forever after the sender is done".
        let _ = control_stream_for_shutdown.shutdown(std::net::Shutdown::Both);
        ack_relay_handle.join().unwrap();

        // chunk_relay exits on its own once `send_rx` disconnects (all
        // workers finished and `send_tx` was dropped above), which has
        // already happened by the time we get here.
        chunk_relay_handle.join().unwrap();
        Ok(bytes_sent)
     }

    pub fn run(&mut self) -> Result<()> {
        let start = Instant::now();
        println!("==============================");
        println!(" Secure File Transfer Sender");
        println!("==============================");

        self.handshake()?;
        let file_size = std::fs::metadata(&self.filename)?.len();

        let total_chunks = file_size.div_ceil(CHUNK_SIZE as u64) as u32;
        self.tcp.write_all(
            &total_chunks.to_be_bytes()
        )?;

        self.tcp.write_all(
            &file_size.to_be_bytes()
        )?;

        let transfer_start = Instant::now();

        let bytes_sent = self.send_file(total_chunks)?;

        println!(
            "Transfer (send + all repairs): {:.3?}",
            transfer_start.elapsed()
        );

        println!(
            "Total sender runtime: {:.3?}",
            start.elapsed()
        );

        let elapsed = start.elapsed();
        let seconds = elapsed.as_secs_f64();

        let throughput =
            bytes_sent as f64
                / (1024.0 * 1024.0)
                / seconds;

        println!();
        println!("==============================");
        println!("Transfer Complete");
        println!("==============================");
        println!("Time Taken : {:.3} s", seconds);
        println!("Data Sent  : {:.2} MB",
            bytes_sent as f64 / (1024.0 * 1024.0));
        println!("Throughput : {:.2} MB/s", throughput);

        Ok(())
    }
}
