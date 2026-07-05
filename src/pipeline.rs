//BEST
pub const NUM_WORKERS: usize = 4;
pub struct ReadChunk {
    pub chunk_id: u32,
    pub data: Vec<u8>,
}


pub struct EncryptedChunk {
    pub chunk_id: u32,
    pub packet: Vec<u8>,
    pub bytes: usize,
}

pub struct ReceivedPacket {
    pub chunk_id: u32,
    pub encrypted: Vec<u8>,
    pub hash: u64,
}

pub struct DecryptedChunk {
    pub chunk_id: u32,
    pub data: Vec<u8>,
}
pub struct MissingRequest {
    pub missing: Vec<u32>,
}