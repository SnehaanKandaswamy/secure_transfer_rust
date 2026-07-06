//BEST
use anyhow::Result;
use std::time::Instant;
const INITIAL_TRANSFER_COMPLETE: u8 = 0xA1;
const RETRANSMISSION_COMPLETE: u8 = 0xA2;
use std::time::Duration;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use rsa::{
    pkcs8::DecodePublicKey,
    Oaep,
    RsaPublicKey,
};
use sha2::Sha256;
use std::collections::{
    BTreeMap,
    VecDeque,
};

use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
};

use crate::{
    checksum,
    config::{CHUNK_SIZE, DATA_PORT, RECEIVER_IP, KEY_PORT,WINDOW_SIZE},
    crypto,
};

use crossbeam_channel::{unbounded, Receiver, Sender as ChannelSender};

use crate::pipeline::{
    ReadChunk,
    EncryptedChunk,
    NUM_WORKERS,
};
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
    fn worker_thread(
    rx: Receiver<ReadChunk>,
    tx: ChannelSender<EncryptedChunk>,
    key: [u8; 32],
    nonce: [u8; 16],) -> Result<()> {
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

        let mut packet =
            Vec::with_capacity(16 + encrypted.len());

        packet.extend_from_slice(
            &chunk.chunk_id.to_be_bytes()
        );

        packet.extend_from_slice(
            &(encrypted.len() as u32).to_be_bytes()
        );

        packet.extend_from_slice(
            &hash.to_be_bytes()
        );

        packet.extend_from_slice(
            &encrypted
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

fn sender_thread(
    udp: UdpSocket,
    rx: Receiver<EncryptedChunk>,
    total_chunks: usize,
) -> Result<(u64, Vec<Vec<u8>>)>{

        let mut bytes_sent: u64 = 0;
        let mut send_time = std::time::Duration::ZERO;
        let mut packets_sent = 0u64;
        let mut packet_cache = vec![Vec::new(); total_chunks];  
        let mut transport = TransportState::new();
        let mut last_chunk = 0u32;
        let mut next_print: u64 = 500 * 1024 * 1024;
        println!("Sender thread started");
       while let Ok(chunk) = rx.recv() {

transport.queue_packet(
    chunk.chunk_id,
    chunk.packet,
    chunk.bytes,
);

while transport.can_send() {

    let Some((chunk_id, packet, bytes)) =
        transport.next_pending()
    else {
        break;
    };

    let t = Instant::now();
        if chunk_id == 0 {
    println!("First packet size = {}", packet.len());
        }
    udp.send(&packet)?;
    packets_sent += 1;

    // Throttle: pause briefly every BATCH packets instead of every
    // single one. This breaks up the burst enough to avoid whatever
    // is killing the connection on this network, without adding the
    // full sleep cost to every packet. Tune BATCH/PAUSE_MS below -
    // bigger BATCH / smaller PAUSE_MS = faster but burstier.
    const BATCH: u64 = 256;
    const PAUSE_MS: u64 = 1;
    if packets_sent % BATCH == 0 {
        std::thread::sleep(std::time::Duration::from_millis(PAUSE_MS));
    }

    transport.mark_sent(
    chunk_id,
    bytes,
);

    send_time += t.elapsed();

    packet_cache[chunk_id as usize] = packet;

    bytes_sent += bytes as u64;

    last_chunk = last_chunk.max(chunk_id);
}
   
    if bytes_sent >= next_print {

        println!(
            "Sent {:.2} MB",
            bytes_sent as f64 /
            (1024.0 * 1024.0)
        );

        next_print += 500 * 1024 * 1024;
    }
}

println!("Sender channel closed");
      
        println!("==============================");
println!("Sender statistics");
println!("Packets sent : {}", packets_sent);
println!("send() time  : {:.3?}", send_time);
println!("==============================");
        println!("Total send_to() time: {:.3?}", send_time);
        Ok((bytes_sent, packet_cache))
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
   fn send_file(
    &mut self,
    total_chunks: usize,
) -> Result<(u64, Vec<Vec<u8>>)> {

    println!("Opening file...");
   
let (read_tx, read_rx) = unbounded();
let (send_tx, send_rx) = unbounded();

    let filename = self.filename.clone();

    let key = self.session_key;
    let nonce = self.nonce;

    let udp = self.udp.try_clone()?;
    let mut control = self.tcp.try_clone()?;

    // Reader
    let reader = std::thread::spawn(move || {
        Self::reader_thread(
            filename,
            read_tx,
        )
    });

    // Workers
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
    
    // Sender
    let sender =
        std::thread::spawn(move || {
            Self::sender_thread(
    udp,
    send_rx,
    total_chunks,
)
        });

    reader.join().unwrap()?;

    for worker in workers {
        worker.join().unwrap()?;
    }

    sender.join().unwrap()
}

   

fn retransmission_loop(
    &mut self,
    packet_cache: &[Vec<u8>],
) -> Result<()> { 
    let retransmission_start = Instant::now();
let mut retransmitted = 0u64;
    loop {

        let mut count_buf = [0u8; 4];

        self.tcp.read_exact(&mut count_buf)?;

        let count = u32::from_be_bytes(count_buf);

        if count == 0 {

            println!("Receiver has all chunks.");
            break;
        }

        println!(
            "Retransmitting {} chunks...",
            count
        );

        for _ in 0..count {

            let mut id_buf = [0u8; 4];

            self.tcp.read_exact(&mut id_buf)?;

            let chunk_id =
                u32::from_be_bytes(id_buf);

           if let Some(packet) = packet_cache.get(chunk_id as usize) {
                if !packet.is_empty() {
                    self.udp.send(packet)?;
                    retransmitted += 1;
                }
            }
            else {

                println!(
                    "Chunk {} not found in cache!",
                    chunk_id
                );
            }
        }

        println!("Retransmission round complete.");

// Tell receiver this retransmission round is finished
self.tcp.write_all(&[RETRANSMISSION_COMPLETE])?;
self.tcp.flush()?;
    }
    println!(
    "Retransmission phase: {:?} ({} packets)",
    retransmission_start.elapsed(),
    retransmitted
);

    Ok(())
}
   pub fn run(&mut self) -> Result<()> {
    let start = Instant::now();
    println!("==============================");
    println!(" Secure File Transfer Sender");
    println!("==============================");

    self.handshake()?;
    let file_size = std::fs::metadata(&self.filename)?.len();

    let total_chunks =file_size.div_ceil(CHUNK_SIZE as u64) as u32;
    self.tcp.write_all(
        &total_chunks.to_be_bytes()
    )?;

    self.tcp.write_all(
        &file_size.to_be_bytes()
    )?;
    let start = Instant::now();

// ---------------- Handshake already completed ----------------

// Measure initial transfer
let transfer_start = Instant::now();

let (bytes_sent, packet_cache) =
    self.send_file(total_chunks as usize)?;

println!(
    "Initial transfer : {:.3?}",
    transfer_start.elapsed()
);

// Tell receiver the initial UDP transfer is finished
self.tcp.write_all(&[INITIAL_TRANSFER_COMPLETE])?;
self.tcp.flush()?;

// Measure retransmission
let retrans_start = Instant::now();

self.retransmission_loop(
    &packet_cache,
)?;

println!(
    "Retransmission   : {:.3?}",
    retrans_start.elapsed()
);
println!(
    "Total sender runtime: {:.3?}",
    start.elapsed()
);
// Total
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