//Best
use anyhow::Result;
use std::time::{Duration, Instant};

use rand::rngs::OsRng;
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    Arc,
};
use std::io::BufWriter;
use rsa::{pkcs8::EncodePublicKey, Oaep, RsaPrivateKey, RsaPublicKey};

use sha2::Sha256;

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
};
use crate::pipeline::{DecryptedChunk, ReceivedPacket, NUM_WORKERS};
use crossbeam_channel::{unbounded, Receiver, Sender as ChannelSender};
use crate::config::{ACK_INTERVAL_MS, DATA_PORT, HOST, KEY_PORT, MISSING_LOOKAHEAD};
use crate::protocol;

fn receiver_thread(
    udp: UdpSocket,
    tx: ChannelSender<ReceivedPacket>,
    received: Arc<Vec<AtomicBool>>,
    running: Arc<AtomicBool>,
    packets_seen: Arc<AtomicU64>,
) -> Result<()> {
    println!("Receiver thread started");
    use std::{convert::TryInto, io::ErrorKind};
    let thread_start = Instant::now();
    let mut buffer = vec![0u8; 70000];
    let mut recv_time = std::time::Duration::ZERO;
    let mut packets = 0u64;
    let mut channel_time = Duration::ZERO;

    while running.load(Ordering::Acquire) {
        let t = Instant::now();
        match udp.recv_from(&mut buffer) {
            Ok((size, _)) => {
                recv_time += t.elapsed();
                packets += 1;
                packets_seen.fetch_add(1, Ordering::Relaxed);

                if size < 16 {
                    continue;
                }

                let chunk_id = u32::from_be_bytes(buffer[0..4].try_into()?);
                let encrypted_size = u32::from_be_bytes(buffer[4..8].try_into()?) as usize;

                if size < 16 + encrypted_size {
                    continue;
                }

                let hash = u64::from_be_bytes(buffer[8..16].try_into()?);

                if chunk_id < received.len() as u32 {
                    received[chunk_id as usize].store(true, Ordering::Release);
                }

                let s = Instant::now();
                tx.send(ReceivedPacket {
                    chunk_id,
                    encrypted: buffer[16..16 + encrypted_size].to_vec(),
                    hash,
                })?;
                channel_time += s.elapsed();
            }
            Err(ref e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                recv_time += t.elapsed();
                continue;
            }
            Err(e) => {
                eprintln!("Receiver thread: recv_from failed, exiting: {e}");
                return Err(e.into());
            }
        }
    }
    println!("Total recv_from() time: {:.3?}", recv_time);
    println!("Receiver thread lifetime: {:.3?}", thread_start.elapsed());
    println!("==============================");
    println!("Receiver UDP statistics");
    println!("Packets received : {}", packets);
    println!("recv_from() time : {:.3?}", recv_time);
    println!("==============================");
    println!("Total tx.send() time: {:.3?}", channel_time);

    Ok(())
}

fn worker_thread(
    rx: Receiver<ReceivedPacket>,
    tx: ChannelSender<DecryptedChunk>,
    session_key: [u8; 32],
    nonce: [u8; 16],
) -> Result<()> {
    while let Ok(packet) = rx.recv() {
        let decrypted = crate::crypto::decrypt_chunk(&packet.encrypted, &session_key, &nonce, packet.chunk_id);

        let hash = crate::checksum::chunk_hash(&decrypted);

        if hash != packet.hash {
            continue;
        }

        tx.send(DecryptedChunk {
            chunk_id: packet.chunk_id,
            data: decrypted,
        })?;
    }

    println!("Worker finished.");
    Ok(())
}

fn writer_thread(rx: Receiver<DecryptedChunk>, expected_bytes: u64, expected_chunks: u32) -> Result<(u64, u32)> {
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
    let mut chunks: Vec<Option<Vec<u8>>> = (0..expected_chunks).map(|_| None).collect();
    let mut next_print = 500 * 1024 * 1024;

    let io_start = Instant::now();
    while let Ok(chunk) = rx.recv() {
        chunks[chunk.chunk_id as usize] = Some(chunk.data);

        while next_chunk < expected_chunks {
            let Some(data) = chunks[next_chunk as usize].take() else {
                break;
            };

            outfile.write_all(&data)?;
            bytes += data.len() as u64;
            chunks_written += 1;
            next_chunk += 1;

            if bytes >= next_print {
                println!("Received {:.2} MB", bytes as f64 / (1024.0 * 1024.0));
                next_print += 500 * 1024 * 1024;
            }
        }
    }
    println!("Actual file writes: {:?}", io_start.elapsed());

    outfile.flush()?;
    println!("==============================");
    println!("Writer statistics");
    println!("Chunks written : {}", chunks_written);
    println!("Bytes written  : {}", bytes);
    println!("Writer time    : {:.3?}", io_start.elapsed());
    println!("==============================");
    println!("Writer finished.");

    Ok((bytes, chunks_written))
}

/// Runs for the whole transfer on its own thread, reporting progress back to
/// the sender every `ACK_INTERVAL_MS`. This is what replaces the old
/// "wait for the entire transfer, then report everything missing" round
/// trip - the sender now finds out about gaps within milliseconds instead
/// of after the whole file has already gone out.
fn ack_sender_thread(
    mut stream: TcpStream,
    received: Arc<Vec<AtomicBool>>,
    expected_chunks: u32,
    packets_seen: Arc<AtomicU64>,
) -> Result<()> {
    let mut cursor: u32 = 0;
    let mut last_status_print = Instant::now();

    loop {
        std::thread::sleep(Duration::from_millis(ACK_INTERVAL_MS));

        if last_status_print.elapsed() > Duration::from_secs(2) {
            let total_received = received.iter().filter(|b| b.load(Ordering::Acquire)).count();
            println!(
                "recv status: udp_packets_seen={} cursor={} total_received={}/{}",
                packets_seen.load(Ordering::Relaxed),
                cursor,
                total_received,
                expected_chunks
            );
            last_status_print = Instant::now();
        }

        // Advance the cumulative low-water mark as far as it'll go.
        while cursor < expected_chunks && received[cursor as usize].load(Ordering::Acquire) {
            cursor += 1;
        }

        if cursor >= expected_chunks {
            stream.write_all(&protocol::encode_done())?;
            stream.flush()?;
            println!("All chunks received - sent Done.");
            return Ok(());
        }

        // Only scan/report within a bounded lookahead window so the ACK
        // stays small even on multi-GB files - the sender's own window
        // won't be sending much further ahead than this anyway. Report
        // BOTH which ids in this range are already delivered (selective
        // ack) and which are still missing: without the selective-ack
        // list, a chunk that lands fine after a still-missing earlier one
        // could never be evicted from the sender's inflight set, since the
        // cumulative floor alone never reaches it. That was the exact bug
        // that froze the transfer at a fixed window size.
        let scan_end = expected_chunks.min(cursor + MISSING_LOOKAHEAD);
        let mut acked = Vec::new();
        let mut missing = Vec::new();
        for id in cursor..scan_end {
            if received[id as usize].load(Ordering::Acquire) {
                acked.push(id);
            } else {
                missing.push(id);
            }
        }

        stream.write_all(&protocol::encode_ack(cursor, &acked, &missing))?;
        stream.flush()?;
    }
}

pub fn run() -> Result<()> {
    let overall_start = Instant::now();
    println!("==============================");
    println!(" Secure File Transfer Receiver");
    println!("==============================");
    //---------------- UDP ----------------//

    let udp = UdpSocket::bind(format!("{}:{}", HOST, DATA_PORT))?;
    udp.set_read_timeout(Some(Duration::from_millis(100)))?;

    use socket2::Socket;
    let socket = Socket::from(udp.try_clone()?);
    socket.set_recv_buffer_size(64 * 1024 * 1024)?;

    println!("Receiver bound to {}", udp.local_addr()?);
    println!("Waiting for UDP...");
    println!("Receiver UDP: {}", udp.local_addr()?);

    //---------------- TCP ----------------//

    let listener = TcpListener::bind(format!("{}:{}", HOST, KEY_PORT))?;
    println!("Waiting for connection...");

    let (mut stream, addr) = listener.accept()?;
    stream.set_nodelay(true)?;
    println!("Connected to {}", addr);

    //---------------- RSA ----------------//
    let private = RsaPrivateKey::new(&mut OsRng, 2048)?;
    let public = RsaPublicKey::from(&private);
    let pem = public.to_public_key_pem(Default::default())?;

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

    let session_key_vec = private.decrypt(Oaep::new::<Sha256>(), &encrypted)?;
    let session_key: [u8; 32] = session_key_vec.try_into().expect("Invalid AES key length");

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
    println!("Expected {:.2} MB", expected_bytes as f64 / (1024.0 * 1024.0));
    println!("AES Key Size : {}", session_key.len());

    let start = Instant::now();

    let (packet_tx, packet_rx) = unbounded();
    let (write_tx, write_rx) = unbounded();

    let received = Arc::new(
        (0..expected_chunks as usize)
            .map(|_| AtomicBool::new(false))
            .collect::<Vec<_>>(),
    );
    let running = Arc::new(AtomicBool::new(true));
    let packets_seen = Arc::new(AtomicU64::new(0));

    let mut workers = Vec::new();
    for _ in 0..NUM_WORKERS {
        let rx = packet_rx.clone();
        let tx = write_tx.clone();
        let key = session_key;
        let nonce = nonce;

        workers.push(std::thread::spawn(move || worker_thread(rx, tx, key, nonce)));
    }
    drop(write_tx);

    let receive_start = Instant::now();

    let udp_receiver = udp.try_clone()?;
    let packet_sender = packet_tx.clone();
    let received_flags = received.clone();
    let running_clone = running.clone();

    let packets_seen_recv = packets_seen.clone();
    let receiver_handle = std::thread::spawn(move || {
        receiver_thread(udp_receiver, packet_sender, received_flags, running_clone, packets_seen_recv)
    });

    let writer_handle = std::thread::spawn(move || writer_thread(write_rx, expected_bytes, expected_chunks));

    // Dedicated thread that continuously reports progress back to the
    // sender over TCP - this is the "adapts to any network" part. On a
    // clean link it reports empty `missing` lists and the sender's window
    // grows; the moment loss shows up it reports gaps within milliseconds
    // and the sender's window backs off, instead of the old design where
    // nothing was reported until the entire file had already been sent.
    let ack_stream = stream.try_clone()?;
    let ack_received = received.clone();
    let packets_seen_ack = packets_seen.clone();
    let ack_handle = std::thread::spawn(move || {
        ack_sender_thread(ack_stream, ack_received, expected_chunks, packets_seen_ack)
    });

    // Blocks until the ack thread has told the sender it has everything.
    ack_handle.join().unwrap()?;

    running.store(false, Ordering::Release);
    drop(packet_tx);

    receiver_handle.join().unwrap()?;
    println!("Receiver joined");
    println!("Receive loop     : {:.3?}", receive_start.elapsed());

    let worker_start = Instant::now();
    for worker in workers {
        worker.join().unwrap()?;
    }
    println!("Workers          : {:.3?}", worker_start.elapsed());

    let writer_start = Instant::now();
    let (bytes_received, total_chunks) = writer_handle.join().unwrap()?;
    println!("Writer           : {:.3?}", writer_start.elapsed());

    println!();
    println!("Expected Chunks : {}", expected_chunks);
    println!("Received Chunks : {}", total_chunks);
    println!("Expected Data   : {:.2} MB", expected_bytes as f64 / (1024.0 * 1024.0));

    let elapsed = start.elapsed();
    let seconds = elapsed.as_secs_f64();
    let throughput = bytes_received as f64 / (1024.0 * 1024.0) / seconds;

    println!("Total receiver runtime: {:.3?}", overall_start.elapsed());
    println!();
    println!("==============================");
    println!("Transfer Complete");
    println!("==============================");
    println!("Output File : reconstructed.bin");
    println!("Chunks      : {}", total_chunks);
    println!("Data        : {:.2} MB", bytes_received as f64 / (1024.0 * 1024.0));
    println!("Time        : {:.3} s", seconds);
    println!("Throughput  : {:.2} MB/s", throughput);

    Ok(())
}