use anyhow::Result;
use std::time::Instant;

use rand::rngs::OsRng;

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
    NUM_WORKERS,
};
use crossbeam_channel::{
    unbounded,
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
    expected_chunks: u32,
    expected_bytes: u64,
) -> Result<(u32, u64,Vec<u32>)> {

    use std::{
        convert::TryInto,
        io::ErrorKind,
    };

    let mut buffer = vec![0u8; 70000];
    let mut received =vec![false; expected_chunks as usize];
    let mut end_received = false;

    loop {

        match udp.recv_from(&mut buffer) {

            Ok((size, _)) => {

                if size < 16 {
                    continue;
                }

                let chunk_id =
                    u32::from_be_bytes(
                        buffer[0..4].try_into()?
                    );

                // END packet
                if chunk_id == u32::MAX {

                   
                    end_received = true;

                    println!(
                        "END packet received. Expecting {} chunks.",
                        expected_chunks
                    );

                    continue;
                }

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
                if chunk_id < expected_chunks {
                        received[chunk_id as usize] = true;
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
                if e.kind() == ErrorKind::TimedOut ||
                   e.kind() == ErrorKind::WouldBlock =>
            {
                // Only stop after we've already seen END
                if end_received {
                    println!("Receiver thread finished.");
                    break;
                }

                continue;
            }

            Err(e) => return Err(e.into()),
        }
    }

    drop(tx);
    let mut missing = Vec::new();

    for (id, ok) in received.iter().enumerate() {

        if !*ok {

            missing.push(id as u32);
        }
    }

    println!("Missing chunks: {}", missing.len());
    Ok((expected_chunks, expected_bytes,missing))
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

        if hash != packet.hash {
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
) -> Result<(u64,u32)> {

    use std::{
        fs::OpenOptions,
        io::{Seek,SeekFrom,Write},
    };

    let mut outfile =
        OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("reconstructed.bin")?;

    let mut bytes = 0u64;
    let mut chunks = 0u32;

    let mut next_print =
        500 * 1024 * 1024;

    while let Ok(chunk) = rx.recv() {

        outfile.seek(
            SeekFrom::Start(
                chunk.chunk_id as u64 *
                CHUNK_SIZE as u64
            )
        )?;

        outfile.write_all(
            &chunk.data
        )?;

        bytes += chunk.data.len() as u64;

        chunks += 1;

        if bytes >= next_print {

            println!(
                "Received {:.2} MB",
                bytes as f64 /
                (1024.0*1024.0)
            );

            next_print +=
                500 * 1024 * 1024;
        }
    }

    outfile.flush()?;

    println!("Writer finished.");

    Ok((bytes,chunks))
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
    Some(Duration::from_secs(2))
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

let (packet_tx, packet_rx) = unbounded();
let (write_tx, write_rx) = unbounded();

let udp_receiver = udp.try_clone()?;

// Receiver thread
let receiver_handle = std::thread::spawn(move || {
    receiver_thread(
        udp_receiver,
        packet_tx,
        expected_chunks,
        expected_bytes,
    )
});

// Worker threads
let mut workers = Vec::new();

for _ in 0..NUM_WORKERS {

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

// Writer thread
let writer_handle = std::thread::spawn(move || {
    writer_thread(write_rx)
});

// Wait for receiver
let (
    expected_chunks,
    expected_bytes,
    missing,
) = receiver_handle.join().unwrap()?;
// Wait for workers
for worker in workers {
    worker.join().unwrap()?;
}

// Wait for writer
let (bytes_received, total_chunks) =
    writer_handle.join().unwrap()?;
println!();

println!(
    "Expected Chunks : {}",
    expected_chunks
);

println!(
    "Received Chunks : {}",
    total_chunks
);

if missing.is_empty() {

    println!("All chunks received.");

} else {

    println!("Missing {} chunks.", missing.len());

    println!("{:?}", missing);
}
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