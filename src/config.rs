pub const HOST: &str = "0.0.0.0";
pub const RECEIVER_IP: &str = "192.168.31.120";
pub const DATA_PORT: u16 = 5000;

pub const KEY_PORT: u16 = 5001;

pub const CHUNK_SIZE: usize = 65000;

pub const NUM_WORKERS: usize = 4;

pub const UDP_SEND_BUFFER: usize = 16 * 1024 * 1024;

pub const UDP_RECV_BUFFER: usize = 32 * 1024 * 1024;

pub const TCP_BUFFER: usize = 1024 * 1024;

// Receiver sends one ACK after every
// ACK_INTERVAL newly received packets.
pub const ACK_INTERVAL: u32 = 128;

// Retransmit if we haven't heard an ACK
// for this long.
pub const RETRANSMIT_TIMEOUT_MS: u64 = 25;
pub const WINDOW_SIZE: usize = 512;
pub const RETRANSMIT_BATCH_SIZE: usize = 1024;