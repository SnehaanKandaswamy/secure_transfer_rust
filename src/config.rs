pub const HOST: &str = "127.0.0.1";

pub const DATA_PORT: u16 = 5000;

pub const KEY_PORT: u16 = 5001;

pub const CHUNK_SIZE: usize = 65_000;

pub const NUM_WORKERS: usize = 4;

pub const UDP_SEND_BUFFER: usize = 16 * 1024 * 1024;

pub const UDP_RECV_BUFFER: usize = 32 * 1024 * 1024;

pub const TCP_BUFFER: usize = 1024 * 1024;