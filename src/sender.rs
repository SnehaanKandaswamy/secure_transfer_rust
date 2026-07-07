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
        let reader_start = Instant::now();
        let mut total_bytes = 0u64;
        let mut chunk_id = 0u32;

        loop {
            let mut buffer = vec![0u8; CHUNK_SIZE];

            let bytes = file.read(&mut buffer)?;
            total_bytes += bytes as u64;

            if bytes == 0 {
                break;
            }

            buffer.truncate(bytes);

            tx.send(
                ReadChunk {
                    chunk_id,
                    data: buffer,
                }
            )?;

            chunk_id += 1;
        }
        println!(
            "Reader finished: {:.3?} ({:.2} MB)",
            reader_start.elapsed(),
            total_bytes as f64 / 1024.0 / 1024.0
        );
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
        let worker_start = Instant::now();
        let mut encrypt_time = std::time::Duration::ZERO;
        let mut chunks = 0u64;

        while let Ok(chunk) = rx.recv() {
            let t = Instant::now();

            let encrypted = crypto::encrypt_chunk(
                &chunk.data,
                &key,
                &nonce,
                chunk.chunk_id,
            );

            encrypt_time += t.elapsed();
            chunks += 1;

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
        println!(
            "Worker {:?}: {} chunks | encrypt {:?}",
            std::thread::current().id(),
            chunks,
            encrypt_time
        );

        println!(
            "Worker total lifetime: {:?}",
            worker_start.elapsed()
        );
        println!("Worker finished");
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
                Ok(ack) => ack,
                Err(_) => break,
            };
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
        let mut next_print: u64 = 500 * 1024 * 1024;
        let mut last_status_print = Instant::now();
        let mut last_missing_print = Instant::now();

        let mut blocks: HashMap<u32, BlockState> = HashMap::new();
        let mut pending: std::collections::VecDeque<EncryptedChunk> = std::collections::VecDeque::new();

        println!("Block manager thread started");

        let udp_send = |udp: &UdpSocket, packet: &[u8]| {
            if let Err(e) = udp.send(packet) {
                eprintln!("udp send failed (non-fatal, will retry): {e}");
            }
        };

        // Processes one already-dequeued chunk. Returns it back (`Some`)
        // instead of consuming it if it can't be admitted yet because the
        // pipeline is at capacity and this chunk would open a new block --
        // the caller is responsible for buffering it in that case.
        let mut handle_chunk = |chunk: EncryptedChunk,
                                 blocks: &mut HashMap<u32, BlockState>,
                                 bytes_sent: &mut u64,
                                 packets_sent: &mut u64,
                                 next_print: &mut u64|
         -> Option<EncryptedChunk> {
            let (block_id, packet_in_block) = block_of(chunk.chunk_id);
            let block_total = packets_in_block(block_id, total_chunks);

            if !blocks.contains_key(&block_id) && blocks.len() >= pipeline_depth {
                return Some(chunk);
            }

            let entry = blocks
                .entry(block_id)
                .or_insert_with(|| {
                    println!("[DEBUG] Block {block_id} opened ({block_total} packets)");
                    BlockState::new(block_total)
                });

            // Cache-before-send ordering, unchanged from the earlier fix --
            // still correct, and now the only thread that can ever touch
            // this entry, so there is no window for anything to remove it
            // out from under this write either.
            entry.packets[packet_in_block as usize] = Some(chunk.packet.clone());
            udp_send(&udp, &chunk.packet);

            *packets_sent += 1;
            *bytes_sent += chunk.bytes as u64;
            entry.sent += 1;

            if entry.sent == entry.total && !entry.end_emitted {
                // This assert can now never fire from a concurrent-mutation
                // race: this thread is the only writer and only remover of
                // block state, so `all_cached()` reflects exactly what this
                // same thread just finished writing.
                assert!(
                    entry.all_cached(),
                    "invariant violated: about to emit BlockEnd for block {block_id} \
                     but the cache is missing at least one of its {block_total} packets"
                );
                let end = BlockEndPacket::encode(block_id, block_total as u32);
                udp_send(&udp, &end);
                entry.end_emitted = true;
                println!("[DEBUG] Block {block_id} fully sent, BlockEnd emitted");
            }

            if *bytes_sent >= *next_print {
                println!("Sent {:.2} MB", *bytes_sent as f64 / (1024.0 * 1024.0));
                *next_print += 500 * 1024 * 1024;
            }

            None
        };

        while completed < total_blocks {
            let event = events.recv()?;

            match event {
                SenderEvent::Chunk(chunk) => {
                    if let Some(chunk) =
                        handle_chunk(chunk, &mut blocks, &mut bytes_sent, &mut packets_sent, &mut next_print)
                    {
                        // Pipeline is full and this chunk would open a new
                        // block -- buffer it. It'll be retried the moment a
                        // block completes below, never by blocking this
                        // thread (which would also stall draining acks).
                        pending.push_back(chunk);
                    }
                }
                SenderEvent::Ack(BlockAck::Missing { block_id, missing }) => {
                    let Some(entry) = blocks.get(&block_id) else {
                        // No second thread can have removed this out from
                        // under us -- this means the receiver is asking
                        // about a block we've already resolved (e.g. a
                        // stray repeat ack). Safe to ignore.
                        continue;
                    };
                    let mut sent_this_round = 0u64;
                    for &id in &missing {
                        if let Some(Some(packet)) = entry.packets.get(id as usize) {
                            if let Err(e) = udp.send(packet) {
                                eprintln!("udp resend failed (non-fatal, will retry): {e}");
                            } else {
                                retransmitted += 1;
                                sent_this_round += 1;
                            }
                        }
                    }
                    if last_missing_print.elapsed() > Duration::from_secs(1) {
                        println!(
                            "[DEBUG] block {block_id}: {} missing, resent {sent_this_round} packet(s)",
                            missing.len()
                        );
                        last_missing_print = Instant::now();
                    }
                }
                SenderEvent::Ack(BlockAck::Complete { block_id }) => {
                    if blocks.remove(&block_id).is_none() {
                        println!("[WARN] Complete ack for unknown/already-resolved block {block_id}");
                    }
                    completed += 1;
                    println!("[DEBUG] block {block_id} complete ({completed}/{total_blocks} blocks done)");

                    // A slot just freed up -- try to admit buffered chunks
                    // now, including ones that open brand new blocks.
                    while let Some(chunk) = pending.pop_front() {
                        if let Some(chunk) =
                            handle_chunk(chunk, &mut blocks, &mut bytes_sent, &mut packets_sent, &mut next_print)
                        {
                            // Still can't admit (another slot is still
                            // full) -- put it back at the front and stop.
                            // This can't happen right after freeing exactly
                            // one slot unless pipeline_depth == 0, but stay
                            // defensive.
                            pending.push_front(chunk);
                            break;
                        }
                    }
                }
            }

            if last_status_print.elapsed() > Duration::from_secs(1) {
                println!(
                    "[DEBUG] sender: packets_sent={} sent={:.2}MB blocks_open={} pending_chunks={}",
                    packets_sent,
                    bytes_sent as f64 / (1024.0 * 1024.0),
                    blocks.len(),
                    pending.len()
                );
                last_status_print = Instant::now();
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

        reader.join().unwrap()?;

        for worker in workers {
            worker.join().unwrap()?;
        }

        let bytes_sent = manager_handle.join().unwrap()?;

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