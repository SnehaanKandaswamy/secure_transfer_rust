use anyhow::Result;
const INITIAL_TRANSFER_COMPLETE: u8 = 0xA1;
const RETRANSMISSION_COMPLETE: u8 = 0xA2;
use std::time::Instant;
use rand::rngs::OsRng;
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
    net::{TcpListener, UdpSocket},
};
use crate::pipeline::{
    ReceivedPacket,
    DecryptedChunk,
    worker_count,
};
use crossbeam_channel::{
    bounded,
    Receiver,
    Sender as ChannelSender,
};
use crate::config::{
    CHUNK_SIZE,
    DATA_PORT,
    HOST,
    KEY_PORT,
};

fn receiver_thread(
    udp: UdpSocket,
    tx: ChannelSender<ReceivedPacket>,
    received: Arc<Vec<AtomicBool>>,
    running: Arc<AtomicBool>,
) -> Result<()>{
   
    use std::{
        convert::TryInto,
        io::ErrorKind,
    };

    let mut buffer = vec![0u8; 70000];
    let mut recv_time = std::time::Duration::ZERO;
    let mut end_seen = false;
    let mut end_timeout_count = 0;
while running.load(Ordering::Acquire) {
        let t = Instant::now();
        match udp.recv_from(&mut buffer) {
            
            Ok((size, _)) => {
                end_timeout_count = 0;
                 recv_time += t.elapsed();

                if size < 16 {
                    continue;
                }

                let chunk_id =
                    u32::from_be_bytes(
                        buffer[0..4].try_into()?
                    );
               if chunk_id == 7992
    || chunk_id == 9858
    || chunk_id == 12726
    || chunk_id == 13284
{
    println!("Receiver got retransmitted chunk {}", chunk_id);
}
                

                // END packet
                // END packet

 
                let encrypted_size =
                    u32::from_be_bytes(
                        buffer[4..8].try_into()?
                    ) as usize;

                if size < 16 + encrypted_size {
                    continue;
                }

                let hash =
                    u64::from_be_bytes(
                        buffer[8..16].try_into()?
                    );
              if chunk_id < received.len() as u32 {

    received[chunk_id as usize]
        .store(true, Ordering::Relaxed);
    const DEBUG: bool = false;

if DEBUG && chunk_id % 100 == 0 {
    println!("Received chunk {}", chunk_id);
}
        
}

                tx.send(
                    ReceivedPacket {
                        chunk_id,
                        encrypted: buffer[16..16 + encrypted_size]
                            .to_vec(),
                        hash,
                    }
                )?;
            }
          Err(ref e)
if e.kind() == ErrorKind::TimedOut
    || e.kind() == ErrorKind::WouldBlock =>
{
    recv_time += t.elapsed();

    continue;
}

            Err(e) => return Err(e.into()),
        }
    }
    println!(
    "Total recv_from() time: {:.3?}",
    recv_time
);
    Ok(())
}
fn worker_thread(
    rx: Receiver<ReceivedPacket>,
    tx: ChannelSender<DecryptedChunk>,
    session_key: [u8;32],
    nonce: [u8;16],
) -> Result<()> {

    while let Ok(packet) = rx.recv() {

        let decrypted =
            crate::crypto::decrypt_chunk(
                &packet.encrypted,
                &session_key,
                &nonce,
                packet.chunk_id,
            );

       let hash =
    crate::checksum::chunk_hash(
        &decrypted
    );

// Debug only for the problematic chunks
if packet.chunk_id == 7992
    || packet.chunk_id == 9858
    || packet.chunk_id == 12726
    || packet.chunk_id == 13284
{
    println!("Worker processing chunk {}", packet.chunk_id);
}

if hash != packet.hash {

    if packet.chunk_id == 7992
        || packet.chunk_id == 9858
        || packet.chunk_id == 12726
        || packet.chunk_id == 13284
    {
        println!("Hash mismatch for chunk {}", packet.chunk_id);
    }

    continue;
}

        tx.send(
            DecryptedChunk {
                chunk_id: packet.chunk_id,
                data: decrypted,
            }
        )?;
    }

    println!("Worker finished.");

    Ok(())
}
fn writer_thread(
    rx: Receiver<DecryptedChunk>,
    expected_bytes: u64,
    expected_chunks: u32,
) -> Result<(u64,u32)> {

   use std::fs::OpenOptions;

let file = OpenOptions::new()
    .create(true)
    .write(true)
    .truncate(true)
    .open("reconstructed.bin")?;

// Reserve the entire file size
file.set_len(expected_bytes)?;

let mut outfile = BufWriter::with_capacity(
    8 * 1024 * 1024,
    file,
);
    let mut bytes = 0u64;
    let mut chunks_written = 0u32;
    let mut next_chunk = 0u32;
    let mut chunks: Vec<Option<Vec<u8>>> =
    (0..expected_chunks)
        .map(|_| None)
        .collect();
    let mut next_print =
        500 * 1024 * 1024;

    let io_start = Instant::now();
    while let Ok(chunk) = rx.recv() {

    chunks[chunk.chunk_id as usize] = Some(chunk.data);

while next_chunk < expected_chunks {

    let Some(data) =
        chunks[next_chunk as usize].take()
    else {
        break;
    };

    outfile.write_all(&data)?;

    bytes += data.len() as u64;

    chunks_written += 1;

    next_chunk += 1;

    if bytes >= next_print {

        println!(
            "Received {:.2} MB",
            bytes as f64 /
            (1024.0 * 1024.0)
        );

        next_print += 500 * 1024 * 1024;
    }
}


}
    println!(
    "Actual file writes: {:?}",
    io_start.elapsed()
);

    outfile.flush()?;

    println!("Writer finished.");

    Ok((bytes,chunks_written))
}
fn find_missing(
    received: &[AtomicBool]
) -> Vec<u32>
{
    received
        .iter()
        .enumerate()
        .filter_map(|(i, ok)| {

            if !ok.load(Ordering::Relaxed) {
                Some(i as u32)

            } else {

                None
            }
        })
        .collect()
}
pub fn run() -> Result<()> {

    println!("==============================");
    println!(" Secure File Transfer Receiver");
    println!("==============================");
    //---------------- UDP ----------------//


    let udp = UdpSocket::bind(
        format!("{}:{}", HOST, DATA_PORT)
    )?;
    use std::time::Duration;

udp.set_read_timeout(
    Some(Duration::from_millis(100))
)?;
    use socket2::Socket;

    let socket = Socket::from(udp.try_clone()?);

    socket.set_recv_buffer_size(64 * 1024 * 1024)?;

    println!("Receiver bound to {}", udp.local_addr()?);
    println!("Waiting for UDP...");

    println!("Receiver UDP: {}", udp.local_addr()?);
    
    println!("Waiting for UDP packet...");

    //---------------- TCP ----------------//

    let listener =
        TcpListener::bind(
            format!("{}:{}", HOST, KEY_PORT)
        )?;

    println!("Waiting for connection...");

    let (mut stream, addr) =
        listener.accept()?;

    println!("Connected to {}", addr);

    //---------------- RSA ----------------//

    let private =
        RsaPrivateKey::new(
            &mut OsRng,
            2048,
        )?;

    let public =
        RsaPublicKey::from(&private);

    let pem =
        public.to_public_key_pem(
            Default::default()
        )?;

    stream.write_all(
        &(pem.len() as u32).to_be_bytes()
    )?;

    stream.write_all(
        pem.as_bytes()
    )?;

    //---------------- Receive AES Key ----------------//

    let mut len=[0u8;4];


    stream.read_exact(&mut len)?;

    let enc_len=
        u32::from_be_bytes(len) as usize;

    let mut encrypted=
        vec![0u8;enc_len];

    stream.read_exact(&mut encrypted)?;

    let session_key_vec =
    private.decrypt(
        Oaep::new::<Sha256>(),
        &encrypted,
    )?;

    let session_key: [u8; 32] =
        session_key_vec
            .try_into()
            .expect("Invalid AES key length");

    let mut nonce=[0u8;16];

    stream.read_exact(&mut nonce)?;

    println!("Handshake complete.");
    let mut chunk_buf = [0u8; 4];
stream.read_exact(&mut chunk_buf)?;

let expected_chunks =
    u32::from_be_bytes(chunk_buf);

let mut size_buf = [0u8; 8];
stream.read_exact(&mut size_buf)?;

let expected_bytes =
    u64::from_be_bytes(size_buf);

println!(
    "Expecting {} chunks",
    expected_chunks
);

println!(
    "Expected {:.2} MB",
    expected_bytes as f64 /
    (1024.0 * 1024.0)
);

    println!(
        "AES Key Size : {}",
        session_key.len()
    );

let start = Instant::now();
let (packet_tx, packet_rx) = bounded(512);
let (write_tx, write_rx) = bounded(512);


// Receiver thread

let received = Arc::new(
    (0..expected_chunks as usize)
        .map(|_| AtomicBool::new(false))
        .collect::<Vec<_>>()
);
let running = Arc::new(AtomicBool::new(true));

   
// Worker threads
let mut workers = Vec::new();

for _ in 0..worker_count() {
    let rx = packet_rx.clone();

    let tx = write_tx.clone();

    let key = session_key;

    let nonce = nonce;

    workers.push(
        std::thread::spawn(move || {
            worker_thread(
                rx,
                tx,
                key,
                nonce,
            )
        })
    );
}

drop(write_tx);

let receive_start = Instant::now();

let mut round = 1;

// ---------- Spawn ONE UDP receiver thread ----------

let udp_receiver = udp.try_clone()?;

let packet_sender = packet_tx.clone();

let received_flags = received.clone();

let running_clone = running.clone();

let receiver_handle = std::thread::spawn(move || {

    receiver_thread(
        udp_receiver,
        packet_sender,
        received_flags,
        running_clone,
    )
});

// ---------- Writer thread ----------

let writer_handle =
    std::thread::spawn(move || {
        writer_thread(
            write_rx,
            expected_bytes,
            expected_chunks,
        )
    });
// Wait until sender has completed the initial UDP transfer
let mut signal = [0u8; 1];
stream.read_exact(&mut signal)?;

if signal[0] != INITIAL_TRANSFER_COMPLETE {
    anyhow::bail!("Invalid synchronization message");
}

// Allow any in-flight UDP packets to arrive
std::thread::sleep(std::time::Duration::from_millis(50));
loop {

    println!();
    println!("========== Round {} ==========", round);

    
    
let missing = find_missing(&received);

println!("Missing chunks: {}", missing.len());

if !missing.is_empty() {
    println!(
        "First few missing IDs: {:?}",
        &missing[..missing.len().min(10)]
    );
}


if missing.is_empty() {

    println!("All chunks received.");

    stream.write_all(&0u32.to_be_bytes())?;

    running.store(false, Ordering::Release);

    break;
}

println!("Requesting retransmission...");

// Send number of missing chunks
stream.write_all(&(missing.len() as u32).to_be_bytes())?;

// Send each missing chunk ID
// Send each missing chunk ID
for id in &missing {

    stream.write_all(&id.to_be_bytes())?;
}

stream.flush()?;
// Wait until sender has finished retransmitting
let mut signal = [0u8; 1];
stream.read_exact(&mut signal)?;

if signal[0] != RETRANSMISSION_COMPLETE {
    anyhow::bail!("Expected retransmission complete");
}

round += 1;}
drop(packet_tx);   // <-- ADD IT HERE
receiver_handle.join().unwrap()?;
println!(
    "Receive rounds  : {:.3?}",
    receive_start.elapsed()
);
let worker_start = Instant::now();

// Wait for workers
for worker in workers {
    worker.join().unwrap()?;
}
println!(
    "Workers         : {:.3?}",
    worker_start.elapsed()
);
let writer_start = Instant::now();
// Wait for writer
let (bytes_received, total_chunks) =
    writer_handle.join().unwrap()?;
println!(
    "Writer          : {:.3?}",
    writer_start.elapsed()
);
println!();

println!(
    "Expected Chunks : {}",
    expected_chunks
);

println!(
    "Received Chunks : {}",
    total_chunks
);


println!(
    "Expected Data : {:.2} MB",
    expected_bytes as f64 /
    (1024.0 * 1024.0)
);
let elapsed = start.elapsed();

let seconds = elapsed.as_secs_f64();

let throughput =
    bytes_received as f64
        / (1024.0 * 1024.0)
        / seconds;

println!();
println!("==============================");
println!("Transfer Complete");
println!("==============================");
println!("Output File : reconstructed.bin");
println!("Chunks      : {}", total_chunks);
println!(
    "Data        : {:.2} MB",
    bytes_received as f64 / (1024.0 * 1024.0)
);
println!("Time        : {:.3} s", seconds);
println!("Throughput  : {:.2} MB/s", throughput);

Ok(())
}
