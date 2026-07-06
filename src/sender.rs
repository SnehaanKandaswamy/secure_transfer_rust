//BEST
use anyhow::Result;
use std::time::Instant;
use rand::{rngs::OsRng, RngCore};
use rsa::{
    pkcs8::DecodePublicKey,
    Oaep,
    RsaPublicKey,
};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};

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
use crate::transport::{SharedBlockCache, block_of, packets_in_block, total_blocks};

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
    // Block-pipelined send loop (Pipeline Manager + UDP Sender stages).
    //
    // Sends every packet in a block back-to-back with no sleeps and no
    // pacing. Once it has sent every packet currently belonging to a
    // block, it emits a BlockEnd datagram for that block. The only place
    // this loop ever waits is `permits_rx.recv()`, which blocks *only*
    // when PIPELINE_DEPTH blocks are already open and unconfirmed -- i.e.
    // genuine backpressure from outstanding repairs, never a fixed timer.
    // ------------------------------------------------------------------
    fn block_sender_loop(
        udp: UdpSocket,
        rx: Receiver<EncryptedChunk>,
        total_chunks: u32,
        cache: SharedBlockCache,
        permits_rx: Receiver<()>,
    ) -> Result<u64> {
        let mut bytes_sent = 0u64;
        let mut packets_sent = 0u64;
        let mut opened_blocks: HashSet<u32> = HashSet::new();
        let mut sent_counts: HashMap<u32, usize> = HashMap::new();
        let mut next_print: u64 = 500 * 1024 * 1024;

        println!("Block sender thread started");

        while let Ok(chunk) = rx.recv() {
            let (block_id, packet_in_block) = block_of(chunk.chunk_id);
            let block_total = packets_in_block(block_id, total_chunks);

            if !opened_blocks.contains(&block_id) {
                // Backpressure gate: wait for a free pipeline slot. Under
                // normal conditions this never blocks because blocks keep
                // completing continuously; it only engages when repairs
                // are genuinely lagging.
                permits_rx.recv()?;
                opened_blocks.insert(block_id);
                sent_counts.insert(block_id, 0);
                println!("[DEBUG] Block {} opened ({} packets)", block_id, block_total);
            }

            udp.send(&chunk.packet)?;
            packets_sent += 1;
            bytes_sent += chunk.bytes as u64;

            // Cache takes ownership of the datagram bytes for potential
            // retransmission; we've already sent it above.
            cache.record_sent(block_id, packet_in_block, block_total, chunk.packet);

            let count = sent_counts.get_mut(&block_id).unwrap();
            *count += 1;

            if *count == block_total {
                let end = BlockEndPacket::encode(block_id, block_total as u32);
                udp.send(&end)?;
                println!("[DEBUG] Block {} fully sent, BlockEnd emitted", block_id);
            }

            if bytes_sent >= next_print {
                println!(
                    "Sent {:.2} MB",
                    bytes_sent as f64 / (1024.0 * 1024.0)
                );
                next_print += 500 * 1024 * 1024;
            }
        }

        println!("==============================");
        println!("Block sender statistics");
        println!("Packets sent : {}", packets_sent);
        println!("Blocks opened: {}", opened_blocks.len());
        println!("==============================");

        Ok(bytes_sent)
    }

    // ------------------------------------------------------------------
    // Control-ack listener. Runs concurrently with block_sender_loop (not
    // as a separate phase afterwards) so that repairing an early block
    // never stalls later blocks from being sent. Reacts to two message
    // types from the receiver:
    //   - Missing: retransmit exactly the requested packets for that block.
    //   - Complete: free that block's cache and return a pipeline permit.
    // Stops once every block has been confirmed complete.
    // ------------------------------------------------------------------
    fn control_ack_loop(
        mut control: TcpStream,
        udp: UdpSocket,
        cache: SharedBlockCache,
        permits_tx: ChannelSender<()>,
        total_blocks: u32,
    ) -> Result<()> {
        let mut completed = 0u32;
        let mut retransmitted = 0u64;
        let start = Instant::now();

        println!("Control-ack loop started, awaiting {} block(s)", total_blocks);

        while completed < total_blocks {
            println!("[DEBUG] Waiting for BlockAck ({}/{} blocks completed so far)...", completed, total_blocks);
            let ack = BlockAck::read_from(&mut control)?;

            match ack {
                BlockAck::Missing { block_id, missing } => {
                    println!("[DEBUG] BlockAck::Missing for block {} -> {} packet(s) missing: {:?}", block_id, missing.len(), missing);
                    let packets = cache.fetch_for_retransmit(block_id, &missing);
                    for packet in &packets {
                        udp.send(packet)?;
                        retransmitted += 1;
                    }
                    println!("[DEBUG] Retransmitted {} packet(s) for block {}", packets.len(), block_id);
                }
                BlockAck::Complete { block_id } => {
                    println!("[DEBUG] BlockAck::Complete for block {} -- releasing cache, moving to next block", block_id);
                    cache.complete(block_id);
                    completed += 1;
                    // Return a slot to the pipeline. If the sender loop has
                    // already finished and dropped its receiver (shouldn't
                    // happen before this loop exits, but stay defensive),
                    // just ignore the send failure.
                    let _ = permits_tx.send(());
                }
            }
        }

        println!(
            "Control-ack loop: all {} block(s) confirmed complete in {:.3?} ({} packets retransmitted).",
            total_blocks,
            start.elapsed(),
            retransmitted
        );

        Ok(())
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
        let udp_control = self.udp.try_clone()?;
        let control_stream = self.tcp.try_clone()?;

        let cache = SharedBlockCache::new();

        // Semaphore-style permit channel: pre-loaded with PIPELINE_DEPTH
        // tokens. Opening a new block consumes one; confirming a block
        // complete returns one. This is the entire flow-control mechanism
        // for the transport -- no cwnd, no per-packet timers.
        let (permits_tx, permits_rx) = bounded::<()>(PIPELINE_DEPTH);
        for _ in 0..PIPELINE_DEPTH {
            permits_tx.send(())?;
        }

        let total_blocks_count = total_blocks(total_chunks);

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

        // Control-ack listener -- runs concurrently with the block sender.
        let cache_for_control = cache.clone();
        let control_handle = std::thread::spawn(move || {
            Self::control_ack_loop(
                control_stream,
                udp_control,
                cache_for_control,
                permits_tx,
                total_blocks_count,
            )
        });

        // Block-pipelined sender
        let sender_cache = cache.clone();
        let sender_handle = std::thread::spawn(move || {
            Self::block_sender_loop(
                udp_send,
                send_rx,
                total_chunks,
                sender_cache,
                permits_rx,
            )
        });

        reader.join().unwrap()?;

        for worker in workers {
            worker.join().unwrap()?;
        }

        let bytes_sent = sender_handle.join().unwrap()?;

        // Blocks until every block has been confirmed complete, handling
        // repairs as they arrive. This replaces the old sequential
        // "retransmission phase" -- repairs now happen throughout the
        // transfer instead of only after the entire file has been blasted.
        control_handle.join().unwrap()?;

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