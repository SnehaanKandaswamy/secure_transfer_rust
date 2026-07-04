use anyhow::Result;
use std::time::Instant;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashMap;
use rsa::{
    pkcs8::DecodePublicKey,
    Oaep,
    RsaPublicKey,
};
use sha2::Sha256;

use std::{
    io::{Read, Write},
    net::{TcpStream, UdpSocket},
};

use crate::{
    checksum,
    config::{CHUNK_SIZE, DATA_PORT, RECEIVER_IP, KEY_PORT},
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

impl Sender {
    pub fn new(filename: &str) -> Result<Self> {
        let tcp = TcpStream::connect(
            format!("{}:{}", RECEIVER_IP, KEY_PORT),
        )?;

        let udp = UdpSocket::bind("0.0.0.0:0")?;
        use socket2::SockRef;

        SockRef::from(&udp)
    .set_send_buffer_size(128 * 1024 * 1024)?;
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

    let mut chunk_id = 0u32;

    loop {

        let mut buffer = vec![0u8; CHUNK_SIZE];

        let bytes = file.read(&mut buffer)?;

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
        println!("Reader finished");
        Ok(())
    }
    fn worker_thread(
    rx: Receiver<ReadChunk>,
    tx: ChannelSender<EncryptedChunk>,
    key: [u8; 32],
    nonce: [u8; 16],) -> Result<()> {

    while let Ok(chunk) = rx.recv() {

        let encrypted = crypto::encrypt_chunk(
            &chunk.data,
            &key,
            &nonce,
            chunk.chunk_id,
        );

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
    println!("Worker finished");
    Ok(())
}

fn sender_thread(
    udp: UdpSocket,
    rx: Receiver<EncryptedChunk>,
) -> Result<(u64, HashMap<u32, Vec<u8>>)> {

        let mut bytes_sent: u64 = 0;
        let mut send_time = std::time::Duration::ZERO;
        let mut packet_cache =
    HashMap::<u32, Vec<u8>>::new();
        let mut last_chunk = 0u32;
        let mut next_print: u64 = 500 * 1024 * 1024;
        println!("Sender thread started");
        while let Ok(chunk) = rx.recv() {

    let chunk_id = chunk.chunk_id;
    let bytes = chunk.bytes;
    let packet = chunk.packet;

    let t = Instant::now();

udp.send_to(
    &packet,
    format!("{}:{}", RECEIVER_IP, DATA_PORT),
)?;

send_time += t.elapsed();

    packet_cache.insert(
        chunk_id,
        packet,
    );

    bytes_sent += bytes as u64;

    last_chunk = last_chunk.max(chunk_id);

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

        let mut end_packet = Vec::with_capacity(16);

        end_packet.extend_from_slice(
            &u32::MAX.to_be_bytes()
        );

        end_packet.extend_from_slice(
      &(last_chunk + 1).to_be_bytes()
        );

        end_packet.extend_from_slice(
            &bytes_sent.to_be_bytes()
        );

        let t = Instant::now();

udp.send_to(
    &end_packet,
    format!("{}:{}", RECEIVER_IP, DATA_PORT),
)?;

send_time += t.elapsed();

        println!("END packet sent.");
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
) -> Result<(u64, HashMap<u32, Vec<u8>>)> {

    println!("Opening file...");

    let (read_tx, read_rx) = unbounded();
    let (send_tx, send_rx) = unbounded();

    let filename = self.filename.clone();

    let key = self.session_key;
    let nonce = self.nonce;

    let udp = self.udp.try_clone()?;

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
    packet_cache: &HashMap<u32, Vec<u8>>,
) -> Result<()> { 

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

            if let Some(packet) =
                packet_cache.get(&chunk_id)
            {
                self.udp.send_to(
                    packet,
                    format!("{}:{}", RECEIVER_IP, DATA_PORT),
                )?;
            }
            else {

                println!(
                    "Chunk {} not found in cache!",
                    chunk_id
                );
            }
        }

        println!("Retransmission round complete.");

        let mut end_packet = Vec::with_capacity(16);

        end_packet.extend_from_slice(
            &u32::MAX.to_be_bytes()
        );

        end_packet.extend_from_slice(
            &0u32.to_be_bytes()
        );

        end_packet.extend_from_slice(
            &0u64.to_be_bytes()
        );

        self.udp.send_to(
            &end_packet,
            format!("{}:{}", RECEIVER_IP, DATA_PORT),
        )?;
    }

    Ok(())
}
   pub fn run(&mut self) -> Result<()> {

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
    self.send_file()?;

println!(
    "Initial transfer : {:.3?}",
    transfer_start.elapsed()
);

// Measure retransmission
let retrans_start = Instant::now();

self.retransmission_loop(
    &packet_cache,
)?;

println!(
    "Retransmission   : {:.3?}",
    retrans_start.elapsed()
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
