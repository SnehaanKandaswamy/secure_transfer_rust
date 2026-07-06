//BEST
use anyhow::Result;
use std::time::{Duration, Instant};

use rand::{rngs::OsRng, RngCore};
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use sha2::Sha256;

use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
};

use crate::{
    config::{CHUNK_SIZE, DATA_PORT, KEY_PORT, RECEIVER_IP},
    crypto, protocol,
};

use crossbeam_channel::{unbounded, Receiver, Sender as ChannelSender, TryRecvError};

use crate::pipeline::{EncryptedChunk, ReadChunk, NUM_WORKERS};

pub struct Sender {
    tcp: TcpStream,
    udp: UdpSocket,

    session_key: [u8; 32],
    nonce: [u8; 16],

    filename: String,
}

use crate::transport::TransportState;

impl Sender {
    pub fn new(filename: &str) -> Result<Self> {
        let tcp = TcpStream::connect(format!("{}:{}", RECEIVER_IP, KEY_PORT))?;

        let udp = UdpSocket::bind("0.0.0.0:0")?;
        udp.connect(format!("{}:{}", RECEIVER_IP, DATA_PORT))?;
        use socket2::SockRef;

        SockRef::from(&udp).set_send_buffer_size(64 * 1024 * 1024)?;
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

    fn reader_thread(filename: String, tx: ChannelSender<ReadChunk>) -> Result<()> {
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

            tx.send(ReadChunk { chunk_id, data: buffer })?;

            chunk_id += 1;
        }
        println!(
            "Reader finished: {:.3?} ({:.2} MB)",
            reader_start.elapsed(),
            total_bytes as f64 / 1024.0 / 1024.0
        );
        Ok(())
    }

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

            let encrypted = crypto::encrypt_chunk(&chunk.data, &key, &nonce, chunk.chunk_id);

            encrypt_time += t.elapsed();
            chunks += 1;

            let hash = checksum_of(&chunk.data);

            let mut packet = Vec::with_capacity(16 + encrypted.len());

            packet.extend_from_slice(&chunk.chunk_id.to_be_bytes());
            packet.extend_from_slice(&(encrypted.len() as u32).to_be_bytes());
            packet.extend_from_slice(&hash.to_be_bytes());
            packet.extend_from_slice(&encrypted);

            tx.send(EncryptedChunk {
                chunk_id: chunk.chunk_id,
                packet,
                bytes: chunk.data.len(),
            })?;
        }
        println!(
            "Worker {:?}: {} chunks | encrypt {:?}",
            std::thread::current().id(),
            chunks,
            encrypt_time
        );
        println!("Worker total lifetime: {:?}", worker_start.elapsed());
        println!("Worker finished");
        Ok(())
    }

    /// The core of the redesign: one continuous loop that both sends new
    /// data and repairs loss, gated by an adaptive sliding window instead of
    /// a fixed pacing sleep.
    ///
    /// It merges three event sources every iteration:
    ///   1. Freshly encrypted chunks from the pipeline (subject to `cwnd`)
    ///   2. Progress reports from the receiver (grow/shrink window, resend
    ///      specific missing ids immediately)
    ///   3. Locally-detected timeouts (resend if an ACK itself was lost)
    ///
    /// It exits once the receiver has confirmed it has every chunk.
    fn send_and_repair(
        udp: UdpSocket,
        chunk_rx: Receiver<EncryptedChunk>,
        ack_rx: Receiver<protocol::ControlMessage>,
        total_chunks: usize,
    ) -> Result<(u64, u32)> {
        let mut bytes_sent: u64 = 0;
        let mut packets_sent = 0u64;
        let mut retransmitted = 0u64;
        let mut packet_cache: Vec<Vec<u8>> = vec![Vec::new(); total_chunks];
        let mut transport = TransportState::new();
        let mut pipeline_done = false;
        let mut receiver_done = false;
        let mut next_print: u64 = 500 * 1024 * 1024;

        println!("Sender transport loop started (initial window = {})", transport.cwnd);

        let mut last_window_print = Instant::now();

        loop {
            let mut did_work = false;

            // 1. Drain every ACK/Done message currently available - react
            // immediately rather than batching, since these are what drive
            // both retransmission and window sizing.
            loop {
                match ack_rx.try_recv() {
                    Ok(protocol::ControlMessage::Ack { highest_contiguous, acked, missing }) => {
                        did_work = true;
                        let to_resend = transport.on_ack(highest_contiguous, &acked, &missing);
                        for id in to_resend {
                            if let Some(packet) = packet_cache.get(id as usize) {
                                if !packet.is_empty() {
                                    udp.send(packet)?;
                                    retransmitted += 1;
                                }
                            }
                        }
                    }
                    Ok(protocol::ControlMessage::Done) => {
                        did_work = true;
                        receiver_done = true;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => break,
                }
            }

            if receiver_done {
                println!("Receiver confirmed it has every chunk.");
                break;
            }

            // 2. Resend anything whose ACK may itself have been lost.
            for id in transport.timed_out() {
                if let Some(packet) = packet_cache.get(id as usize) {
                    if !packet.is_empty() {
                        udp.send(packet)?;
                        retransmitted += 1;
                        did_work = true;
                    }
                }
            }

            // 3. Pull one fresh chunk in if we don't already have pending
            // work queued (keeps this fair with retransmits above).
            if transport.pending.is_empty() && !pipeline_done {
                match chunk_rx.try_recv() {
                    Ok(chunk) => {
                        transport.queue_packet(chunk.chunk_id, chunk.packet, chunk.bytes);
                        did_work = true;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => pipeline_done = true,
                }
            }

            // 4. Send everything the window currently allows.
            while transport.can_send() {
                let Some((chunk_id, packet, bytes)) = transport.next_pending() else {
                    break;
                };

                udp.send(&packet)?;
                packets_sent += 1;
                did_work = true;

                transport.mark_sent(chunk_id);

                packet_cache[chunk_id as usize] = packet;
                bytes_sent += bytes as u64;
            }

            if bytes_sent >= next_print {
                println!("Sent {:.2} MB (window = {})", bytes_sent as f64 / (1024.0 * 1024.0), transport.cwnd);
                next_print += 500 * 1024 * 1024;
            }

            if last_window_print.elapsed() > Duration::from_secs(2) {
                println!(
                    "window={} inflight={} pending={}",
                    transport.cwnd,
                    transport.inflight.len(),
                    transport.pending.len()
                );
                last_window_print = Instant::now();
            }

            if !did_work {
                // Nothing to do right now - avoid busy-spinning the CPU
                // while we wait for the next ACK, timeout, or chunk.
                std::thread::sleep(Duration::from_micros(500));
            }
        }

        println!("==============================");
        println!("Sender statistics");
        println!("Packets sent      : {}", packets_sent);
        println!("Packets resent    : {}", retransmitted);
        println!("Final window size : {}", transport.cwnd);
        println!("==============================");

        Ok((bytes_sent, packets_sent as u32))
    }

    fn handshake(&mut self) -> Result<()> {
        println!("Waiting for receiver public key...");

        let mut len = [0u8; 4];
        self.tcp.read_exact(&mut len)?;
        let key_len = u32::from_be_bytes(len) as usize;

        let mut pem = vec![0u8; key_len];
        self.tcp.read_exact(&mut pem)?;
        let pem = String::from_utf8(pem)?;

        let public = RsaPublicKey::from_public_key_pem(&pem)?;
        println!("Public key received.");

        let encrypted = public.encrypt(&mut OsRng, Oaep::new::<Sha256>(), &self.session_key)?;

        self.tcp.write_all(&(encrypted.len() as u32).to_be_bytes())?;
        self.tcp.write_all(&encrypted)?;
        self.tcp.write_all(&self.nonce)?;

        println!("Handshake complete.");
        Ok(())
    }

    pub fn run(&mut self) -> Result<()> {
        let start = Instant::now();
        println!("==============================");
        println!(" Secure File Transfer Sender");
        println!("==============================");

        self.handshake()?;
        let file_size = std::fs::metadata(&self.filename)?.len();

        let total_chunks = file_size.div_ceil(CHUNK_SIZE as u64) as u32;
        self.tcp.write_all(&total_chunks.to_be_bytes())?;
        self.tcp.write_all(&file_size.to_be_bytes())?;

        // Dedicated thread that just reads the receiver's continuous
        // progress reports off TCP and hands them to the transport loop.
        // Running this on its own thread is what lets the sender react to
        // loss/ACKs *while* still pumping data, instead of the old
        // "send everything, then find out what's missing" split.
        let (ack_tx, ack_rx) = unbounded();
        let mut ack_stream = self.tcp.try_clone()?;
        let ack_reader = std::thread::spawn(move || -> Result<()> {
            loop {
                let msg = protocol::read_control_message(&mut ack_stream)?;
                let is_done = matches!(msg, protocol::ControlMessage::Done);
                ack_tx.send(msg)?;
                if is_done {
                    break;
                }
            }
            Ok(())
        });

        let transfer_start = Instant::now();

        let (read_tx, read_rx) = unbounded();
        let (send_tx, send_rx) = unbounded();

        let filename = self.filename.clone();
        let key = self.session_key;
        let nonce = self.nonce;
        let udp = self.udp.try_clone()?;

        let reader = std::thread::spawn(move || Self::reader_thread(filename, read_tx));

        let mut workers = Vec::new();
        for _ in 0..NUM_WORKERS {
            let rx = read_rx.clone();
            let tx = send_tx.clone();
            let key = key;
            let nonce = nonce;
            workers.push(std::thread::spawn(move || Self::worker_thread(rx, tx, key, nonce)));
        }
        drop(send_tx);

        let (bytes_sent, packets_sent) =
            Self::send_and_repair(udp, send_rx, ack_rx, total_chunks as usize)?;

        reader.join().unwrap()?;
        for worker in workers {
            worker.join().unwrap()?;
        }
        ack_reader.join().unwrap()?;

        println!("Transfer loop: {:.3?}", transfer_start.elapsed());

        let elapsed = start.elapsed();
        let seconds = elapsed.as_secs_f64();
        let throughput = bytes_sent as f64 / (1024.0 * 1024.0) / seconds;

        println!();
        println!("==============================");
        println!("Transfer Complete");
        println!("==============================");
        println!("Time Taken   : {:.3} s", seconds);
        println!("Data Sent    : {:.2} MB", bytes_sent as f64 / (1024.0 * 1024.0));
        println!("Packets Sent : {}", packets_sent);
        println!("Throughput   : {:.2} MB/s", throughput);

        Ok(())
    }
}

fn checksum_of(data: &[u8]) -> u64 {
    crate::checksum::chunk_hash(data)
}
