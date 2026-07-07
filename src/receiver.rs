//Best
use anyhow::Result;
use std::time::{Duration, Instant};
use rand::rngs::OsRng;
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::io::BufWriter;
use rsa::{
    pkcs8::EncodePublicKey,
    Oaep,
    RsaPrivateKey,
    RsaPublicKey,
};

use sha2::Sha256;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
};
use crate::pipeline::{
    ReceivedPacket,
    DecryptedChunk,
    NUM_WORKERS,
};
use crossbeam_channel::{
    bounded,
    Receiver,
    Sender as ChannelSender,
};
use crate::config::{
    HOST,
    DATA_PORT,
    KEY_PORT,
    PACKETS_PER_BLOCK,
    PIPELINE_DEPTH,
    BLOCK_GRACE_PERIOD_MS,
    BLOCK_IDLE_TIMEOUT_MS,
    MAX_BLOCK_RETRY_ROUNDS,
};
use crate::protocol::{DataPacket, BlockEndPacket, BlockAck, TAG_DATA, TAG_BLOCK_END};
use crate::transport::{SharedReceiverState, chunk_id_of, packets_in_block, total_blocks};

// ------------------------------------------------------------------------
// Raw UDP receiver thread. Demultiplexes incoming datagrams by their tag
// byte into either data packets (forwarded to decryption workers) or
// BlockEnd markers (recorded on the shared block-rx state). This thread
// does not decide anything about acks -- it only feeds the pipeline and
// keeps the per-block activity timers fresh; that keeps its recv loop as
// tight and non-blocking as possible.
// ------------------------------------------------------------------------
fn receiver_thread(
    udp: UdpSocket,
    tx: ChannelSender<ReceivedPacket>,
    state: SharedReceiverState,
    running: Arc<AtomicBool>,
    expected_chunks: u32,
) -> Result<()> {
    println!("Receiver thread started");
    use std::io::ErrorKind;

    let thread_start = Instant::now();
    let mut buffer = vec![0u8; 70000];
    let mut recv_time = Duration::ZERO;
    let mut packets = 0u64;
    let mut block_ends = 0u64;
    let mut malformed = 0u64;
    let mut last_status_print = Instant::now();

    while running.load(Ordering::Acquire) {
        let t = Instant::now();
        match udp.recv_from(&mut buffer) {
            Ok((size, _)) => {
                recv_time += t.elapsed();

                if size < 1 {
                    continue;
                }

                let tag = buffer[0];
                let body = &buffer[1..size];

                match tag {
                    TAG_DATA => {
                        packets += 1;
                        let Some(pkt) = DataPacket::decode(body) else {
                            malformed += 1;
                            continue;
                        };

                        let total = packets_in_block(pkt.block_id, expected_chunks);
                        // Timing signal only -- does NOT mark the packet as
                        // received. See SharedReceiverState's correctness
                        // note: only a verified decrypt does that.
                        state.touch_activity(pkt.block_id, total);

                        let chunk_id = chunk_id_of(pkt.block_id, pkt.packet_in_block);

                        tx.send(ReceivedPacket {
                            chunk_id,
                            block_id: pkt.block_id,
                            packet_in_block: pkt.packet_in_block,
                            encrypted: pkt.payload,
                            hash: pkt.hash,
                        })?;
                    }
                    TAG_BLOCK_END => {
                        let Some((block_id, total_packets)) = BlockEndPacket::decode(body) else {
                            malformed += 1;
                            continue;
                        };
                        block_ends += 1;
                        state.mark_end_seen(block_id, total_packets as usize);
                    }
                    _ => {
                        malformed += 1;
                    }
                }

                if last_status_print.elapsed() > Duration::from_secs(1) {
                    println!(
                        "[DEBUG] receiver: packets={} block_ends={} malformed={}",
                        packets, block_ends, malformed
                    );
                    last_status_print = Instant::now();
                }
            }
            Err(ref e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                recv_time += t.elapsed();
                continue;
            }
            Err(e) => return Err(e.into()),
        }
    }

    println!("==============================");
    println!("Receiver UDP statistics");
    println!("Data packets received : {}", packets);
    println!("BlockEnd markers seen : {}", block_ends);
    println!("Malformed datagrams   : {}", malformed);
    println!("recv_from() time      : {:.3?}", recv_time);
    println!("Thread lifetime       : {:.3?}", thread_start.elapsed());
    println!("==============================");

    Ok(())
}

// ------------------------------------------------------------------------
// Decryption workers -- crypto/checksum logic UNCHANGED from the original
// project. The only addition: on successful verification, report the
// packet's block-relative position to the shared receive state so the ack
// manager can see it. On checksum failure, the packet is simply not marked
// as received (same effect as the old silent `continue`, but now it will
// correctly show up as "missing" in the next BlockAck instead of being
// invisibly dropped from a whole-file bitmap).
// ------------------------------------------------------------------------
fn worker_thread(
    rx: Receiver<ReceivedPacket>,
    tx: ChannelSender<DecryptedChunk>,
    session_key: [u8; 32],
    nonce: [u8; 16],
    state: SharedReceiverState,
    expected_chunks: u32,
) -> Result<()> {
    while let Ok(packet) = rx.recv() {
        let decrypted = crate::crypto::decrypt_chunk(
            &packet.encrypted,
            &session_key,
            &nonce,
            packet.chunk_id,
        );

        let hash = crate::checksum::chunk_hash(&decrypted);

        if hash != packet.hash {
            // Corrupt packet: never marked verified, so it will show up as
            // missing and get retransmitted like any lost packet.
            continue;
        }

        let total = packets_in_block(packet.block_id, expected_chunks);
        state.mark_verified(packet.block_id, packet.packet_in_block, total);

        tx.send(DecryptedChunk {
            chunk_id: packet.chunk_id,
            data: decrypted,
        })?;
    }

    println!("Worker finished.");
    Ok(())
}

// ------------------------------------------------------------------------
// Writer thread -- same sequential, seek-free file-writing approach as the
// original project, but the out-of-order reorder buffer is now a HashMap
// keyed by chunk_id instead of a Vec<Option<_>> sized to the whole file.
// Because the sender only ever keeps PIPELINE_DEPTH blocks open at once,
// this map can never hold more than a small, constant number of chunks
// regardless of file size -- it's pruned as soon as each chunk is written.
// ------------------------------------------------------------------------
fn writer_thread(
    rx: Receiver<DecryptedChunk>,
    expected_bytes: u64,
    expected_chunks: u32,
) -> Result<(u64, u32)> {
    use std::fs::OpenOptions;

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("reconstructed.bin")?;

    file.set_len(expected_bytes)?;

    let mut outfile = BufWriter::with_capacity(32 * 1024 * 1024, file);
    let mut bytes = 0u64;
    let mut chunks_written = 0u32;
    let mut next_chunk = 0u32;
    let mut pending: HashMap<u32, Vec<u8>> = HashMap::new();
    let mut next_print = 500 * 1024 * 1024;
    let mut last_status_print = Instant::now();

    let io_start = Instant::now();

    while let Ok(chunk) = rx.recv() {
        pending.insert(chunk.chunk_id, chunk.data);

        while let Some(data) = pending.remove(&next_chunk) {
            outfile.write_all(&data)?;

            bytes += data.len() as u64;
            chunks_written += 1;
            next_chunk += 1;

            if bytes >= next_print {
                println!(
                    "Received {:.2} MB",
                    bytes as f64 / (1024.0 * 1024.0)
                );
                next_print += 500 * 1024 * 1024;
            }
        }

        if last_status_print.elapsed() > Duration::from_secs(1) {
            println!(
                "[DEBUG] writer: chunks_written={chunks_written}/{expected_chunks} next_chunk={next_chunk} pending_buffer={}",
                pending.len()
            );
            last_status_print = Instant::now();
        }

        if next_chunk >= expected_chunks {
            break;
        }
    }

    outfile.flush()?;

    println!(
        "Actual file writes: {:?}",
        io_start.elapsed()
    );
    println!("==============================");
    println!("Writer statistics");
    println!("Chunks written : {}", chunks_written);
    println!("Bytes written  : {}", bytes);
    println!("Pending buffer at end (should be 0): {}", pending.len());
    println!("Writer time    : {:.3?}", io_start.elapsed());
    println!("==============================");
    println!("Writer finished.");

    Ok((bytes, chunks_written))
}

// ------------------------------------------------------------------------
// Ack manager -- the receiver-side half of the block protocol. Owns the
// TCP control stream for the rest of the transfer (the receiver has
// nothing left to read from it after the handshake, so this is safe to
// move in wholesale). Polls the shared receive state for blocks that are
// ready to be checked (grace period elapsed after BlockEnd, or idle
// timeout elapsed with no BlockEnd ever seen), and for each:
//   - sends BlockComplete if every packet has been verified, freeing that
//     block's tracking state, or
//   - sends a Missing ack naming exactly the still-absent packet ids.
// A block that blows through MAX_BLOCK_RETRY_ROUNDS is force-completed
// (with a loud warning) so a single pathologically broken block can never
// stall the whole transfer forever.
// ------------------------------------------------------------------------
fn ack_manager_loop(
    mut control: TcpStream,
    state: SharedReceiverState,
    total_blocks_count: u32,
) -> Result<()> {
    let grace = Duration::from_millis(BLOCK_GRACE_PERIOD_MS);
    let idle_timeout = Duration::from_millis(BLOCK_IDLE_TIMEOUT_MS);
    // Poll tick for the ack scheduler. This is a control-loop cadence, not
    // a per-packet pacing delay: it only affects how promptly we notice a
    // block is ready to be checked, never how fast data is sent.
    let poll_tick = Duration::from_millis(2);

    let mut completed = 0u32;
    let start = Instant::now();
    let mut last_progress_print = Instant::now();

    println!("Ack manager started, awaiting {} block(s)", total_blocks_count);

    while completed < total_blocks_count {
        println!("ACK thread alive");
        let ready = state.ready_for_check(grace, idle_timeout);
        println!("Ready blocks: {:?}", ready);
        if ready.is_empty() {
            std::thread::sleep(poll_tick);
            continue;
        }

        for block_id in ready {
            let Some((is_complete, missing, rounds)) = state.snapshot_and_tick(block_id) else {
                continue;
            };

            if is_complete {
                BlockAck::Complete { block_id }.write_to(&mut control)?;
                state.remove(block_id);
                completed += 1;
                println!(
                    "[DEBUG] block {block_id} confirmed complete ({completed}/{total_blocks_count} done)"
                );
            } else if rounds > MAX_BLOCK_RETRY_ROUNDS {
                println!(
                    "WARNING: block {} still incomplete after {} rounds ({} packet(s) missing) -- giving up on it to avoid stalling the transfer.",
                    block_id, rounds, missing.len()
                );
                BlockAck::Complete { block_id }.write_to(&mut control)?;
                state.remove(block_id);
                completed += 1;
            } else {
                println!(
    "[ACK] Block {} requesting {} missing packets",
    block_id,
    missing.len()
);

BlockAck::Missing {
    block_id,
    missing,
}
.write_to(&mut control)?;
            }
        }

        if last_progress_print.elapsed() > Duration::from_secs(1) {
            println!(
                "[DEBUG] ack manager: {completed}/{total_blocks_count} blocks confirmed complete so far"
            );
            last_progress_print = Instant::now();
        }
    }

    println!(
        "Ack manager: all {} block(s) resolved in {:.3?}",
        total_blocks_count,
        start.elapsed()
    );

    Ok(())
}

pub fn run() -> Result<()> {
    let overall_start = Instant::now();
    println!("==============================");
    println!(" Secure File Transfer Receiver");
    println!("==============================");
    //---------------- UDP ----------------//

    let udp = UdpSocket::bind(
        format!("{}:{}", HOST, DATA_PORT)
    )?;
    udp.set_read_timeout(Some(Duration::from_millis(100)))?;

    use socket2::Socket;

    let socket = Socket::from(udp.try_clone()?);
    socket.set_recv_buffer_size(64 * 1024 * 1024)?;

    println!("Receiver bound to {}", udp.local_addr()?);
    println!("Waiting for UDP...");
    println!("Receiver UDP: {}", udp.local_addr()?);

    //---------------- TCP ----------------//

    let listener = TcpListener::bind(
        format!("{}:{}", HOST, KEY_PORT)
    )?;

    println!("Waiting for connection...");

    let (mut stream, addr) = listener.accept()?;
    stream.set_nodelay(true)?;

    println!("Connected to {}", addr);

    //---------------- RSA ----------------//

    let private = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let public = RsaPublicKey::from(&private);
    let pem = public.to_public_key_pem(Default::default())?;

    println!("Sending public key...");
    stream.write_all(&(pem.len() as u32).to_be_bytes())?;
    stream.write_all(pem.as_bytes())?;
    stream.flush()?;

    println!("Public key sent.");

    //---------------- Receive AES Key ----------------//

    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;

    let enc_len = u32::from_be_bytes(len) as usize;
    let mut encrypted = vec![0u8; enc_len];
    stream.read_exact(&mut encrypted)?;

    let session_key_vec = private.decrypt(
        Oaep::new::<Sha256>(),
        &encrypted,
    )?;

    let session_key: [u8; 32] = session_key_vec
        .try_into()
        .expect("Invalid AES key length");

    let mut nonce = [0u8; 16];
    stream.read_exact(&mut nonce)?;

    println!("Handshake complete.");

    let mut chunk_buf = [0u8; 4];
    stream.read_exact(&mut chunk_buf)?;
    let expected_chunks = u32::from_be_bytes(chunk_buf);

    let mut size_buf = [0u8; 8];
    stream.read_exact(&mut size_buf)?;
    let expected_bytes = u64::from_be_bytes(size_buf);

    println!("Expecting {} chunks", expected_chunks);
    println!(
        "Expected {:.2} MB",
        expected_bytes as f64 / (1024.0 * 1024.0)
    );

    let start = Instant::now();

    // Bounded channels: this is what keeps memory usage constant regardless
    // of file size. If the writer or workers ever fall behind, backpressure
    // propagates up to the UDP receive path rather than buffering the
    // entire file in memory -- worst case that shows up as more packets
    // needing retransmission, never a deadlock or unbounded growth.
    let channel_capacity = PIPELINE_DEPTH * PACKETS_PER_BLOCK * 2;
    let (packet_tx, packet_rx) = bounded::<ReceivedPacket>(channel_capacity);
    let (write_tx, write_rx) = bounded::<DecryptedChunk>(channel_capacity);

    let received_state = SharedReceiverState::new();
    let running = Arc::new(AtomicBool::new(true));

    // Decryption workers
    let mut workers = Vec::new();
    for _ in 0..NUM_WORKERS {
        let rx = packet_rx.clone();
        let tx = write_tx.clone();
        let key = session_key;
        let nonce = nonce;
        let state = received_state.clone();

        workers.push(
            std::thread::spawn(move || {
                worker_thread(rx, tx, key, nonce, state, expected_chunks)
            })
        );
    }

    drop(write_tx);

    let receive_start = Instant::now();

    // UDP receiver thread
    let udp_receiver = udp.try_clone()?;
    let state_for_recv = received_state.clone();
    let running_clone = running.clone();

    let receiver_handle = std::thread::spawn(move || {
        receiver_thread(
            udp_receiver,
            packet_tx,
            state_for_recv,
            running_clone,
            expected_chunks,
        )
    });

    // Writer thread
    let writer_handle = std::thread::spawn(move || {
        writer_thread(write_rx, expected_bytes, expected_chunks)
    });

    // Ack manager -- owns the TCP control stream for the remainder of the
    // transfer and drives BlockAck/BlockComplete based on the shared
    // receive state populated by the threads above.
    let total_blocks_count = total_blocks(expected_chunks);
    let ack_state = received_state.clone();
    let ack_handle = std::thread::spawn(move || {
        ack_manager_loop(stream, ack_state, total_blocks_count)
    });

    // Blocks until every block has been confirmed complete (or force-
    // completed after exceeding the retry limit).
    ack_handle.join().unwrap()?;

    println!(
        "Ack rounds      : {:.3?}",
        receive_start.elapsed()
    );

    // All blocks resolved -- safe to stop the UDP receive loop now.
    running.store(false, Ordering::Release);
    receiver_handle.join().unwrap()?;

    println!("Joining workers");
    for worker in workers {
        worker.join().unwrap()?;
    }

    let writer_start = Instant::now();
    let (bytes_received, total_chunks_written) = writer_handle.join().unwrap()?;
    println!(
        "Writer          : {:.3?}",
        writer_start.elapsed()
    );

    println!();
    println!("Expected Chunks : {}", expected_chunks);
    println!("Received Chunks : {}", total_chunks_written);
    println!(
        "Expected Data : {:.2} MB",
        expected_bytes as f64 / (1024.0 * 1024.0)
    );

    let elapsed = start.elapsed();
    let seconds = elapsed.as_secs_f64();
    let throughput = bytes_received as f64 / (1024.0 * 1024.0) / seconds;

    println!(
        "Total receiver runtime: {:.3?}",
        overall_start.elapsed()
    );
    println!();
    println!("==============================");
    println!("Transfer Complete");
    println!("==============================");
    println!("Output File : reconstructed.bin");
    println!("Chunks      : {}", total_chunks_written);
    println!(
        "Data        : {:.2} MB",
        bytes_received as f64 / (1024.0 * 1024.0)
    );
    println!("Time        : {:.3} s", seconds);
    println!("Throughput  : {:.2} MB/s", throughput);

    Ok(())
}