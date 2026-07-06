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

/// A still-encrypted packet as received off the wire, already parsed out of
/// its block-framed DataPacket header. Carries block_id/packet_in_block
/// alongside the recovered global chunk_id so a decryption worker can
/// report the packet's block-relative position back to the receive-side
/// block tracker once it's verified -- see SharedReceiverState::mark_verified.
pub struct ReceivedPacket {
    pub chunk_id: u32,
    pub block_id: u32,
    pub packet_in_block: u16,
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