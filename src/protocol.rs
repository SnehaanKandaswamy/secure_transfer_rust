//! Wire formats for the block-pipelined transport.
//!
//! Two channels carry two different kinds of messages:
//!
//! - UDP (fast, unreliable): `DataPacket`s carrying encrypted file data, and
//!   `BlockEndPacket`s marking the end of a block's initial transmission.
//!   Every UDP datagram starts with a one-byte tag so the receiver can tell
//!   the two apart without guessing from size alone.
//! - TCP (slow, reliable, low-frequency): `BlockAck` messages carrying
//!   either "these packet ids are missing" or "this block is complete".
//!   TCP's reliability is a good fit here specifically because these
//!   messages are rare (one or two per block) -- using it for the bulk data
//!   itself would reintroduce head-of-line blocking, which is why data
//!   stays on UDP.

use std::io::{self, Read, Write};

// ---------------------------------------------------------------------
// UDP datagram tags
// ---------------------------------------------------------------------

pub const TAG_DATA: u8 = 0x01;
pub const TAG_BLOCK_END: u8 = 0x02;

// ---------------------------------------------------------------------
// TCP control message tags
// ---------------------------------------------------------------------

pub const CTRL_BLOCK_ACK: u8 = 0xB1;
pub const CTRL_BLOCK_COMPLETE: u8 = 0xB2;

/// One packet of block-framed, encrypted file data.
///
/// Wire format (after the caller has read/stripped the leading TAG_DATA byte):
/// `[block_id:4][packet_in_block:2][encrypted_size:4][hash:8][payload:N]`
///
/// `block_id` + `packet_in_block` replace the old flat `chunk_id`, but the
/// global chunk id used for the AES-CTR counter is always recoverable as
/// `block_id * PACKETS_PER_BLOCK + packet_in_block`, so encryption is
/// unaffected by this framing change.
pub struct DataPacket;

impl DataPacket {
    /// Length of the header *including* the leading tag byte.
    pub const HEADER_LEN: usize = 1 + 4 + 2 + 4 + 8;

    /// Encodes a full, ready-to-send UDP datagram (tag byte included).
    pub fn encode(block_id: u32, packet_in_block: u16, hash: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::HEADER_LEN + payload.len());
        out.push(TAG_DATA);
        out.extend_from_slice(&block_id.to_be_bytes());
        out.extend_from_slice(&packet_in_block.to_be_bytes());
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&hash.to_be_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Decodes a datagram body (tag byte already stripped by the caller).
    /// Returns `None` on any malformed/truncated input rather than erroring,
    /// since a corrupt or torn UDP datagram should simply be dropped -- it
    /// will show up as "missing" and get repaired like any lost packet.
    pub fn decode(body: &[u8]) -> Option<DecodedDataPacket> {
        const FIXED: usize = 4 + 2 + 4 + 8; // header minus the tag byte
        if body.len() < FIXED {
            return None;
        }

        let block_id = u32::from_be_bytes(body[0..4].try_into().ok()?);
        let packet_in_block = u16::from_be_bytes(body[4..6].try_into().ok()?);
        let encrypted_size = u32::from_be_bytes(body[6..10].try_into().ok()?) as usize;
        let hash = u64::from_be_bytes(body[10..18].try_into().ok()?);

        if body.len() < FIXED + encrypted_size {
            return None;
        }

        Some(DecodedDataPacket {
            block_id,
            packet_in_block,
            hash,
            payload: body[FIXED..FIXED + encrypted_size].to_vec(),
        })
    }
}

pub struct DecodedDataPacket {
    pub block_id: u32,
    pub packet_in_block: u16,
    pub hash: u64,
    pub payload: Vec<u8>,
}

/// Sent over UDP right after the final packet of a block has gone out.
/// Tells the receiver "the sender believes this block's initial
/// transmission is done -- check what you're missing". It is *not* relied
/// on for correctness: the receiver also runs its own idle timer per block
/// so a lost BlockEnd doesn't stall anything (see receiver transport,
/// Phase 3).
///
/// Wire format (after tag byte): `[block_id:4][total_packets:4]`
pub struct BlockEndPacket;

impl BlockEndPacket {
    pub const LEN: usize = 1 + 4 + 4;

    pub fn encode(block_id: u32, total_packets: u32) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::LEN);
        out.push(TAG_BLOCK_END);
        out.extend_from_slice(&block_id.to_be_bytes());
        out.extend_from_slice(&total_packets.to_be_bytes());
        out
    }

    pub fn decode(body: &[u8]) -> Option<(u32, u32)> {
        if body.len() < 8 {
            return None;
        }
        let block_id = u32::from_be_bytes(body[0..4].try_into().ok()?);
        let total_packets = u32::from_be_bytes(body[4..8].try_into().ok()?);
        Some((block_id, total_packets))
    }
}

/// TCP control message, receiver -> sender, scoped to a single block.
///
/// This intentionally carries *only* per-block information (never a
/// whole-file bitmap) so a repair round trip costs a tiny, fixed amount of
/// data no matter how large the file is.
pub enum BlockAck {
    /// Some packets in this block never arrived (or failed their checksum).
    /// `missing` holds their `packet_in_block` ids -- at most
    /// `PACKETS_PER_BLOCK` of them, so this fits comfortably in one TCP
    /// write even for a maximally lossy block.
    Missing { block_id: u32, missing: Vec<u16> },
    /// Every packet in this block has been received and verified.
    Complete { block_id: u32 },
}

impl BlockAck {
    pub fn write_to<W: Write>(&self, stream: &mut W) -> io::Result<()> {
        match self {
            BlockAck::Complete { block_id } => {
                stream.write_all(&[CTRL_BLOCK_COMPLETE])?;
                stream.write_all(&block_id.to_be_bytes())?;
            }
            BlockAck::Missing { block_id, missing } => {
                stream.write_all(&[CTRL_BLOCK_ACK])?;
                stream.write_all(&block_id.to_be_bytes())?;
                stream.write_all(&(missing.len() as u32).to_be_bytes())?;
                for id in missing {
                    stream.write_all(&id.to_be_bytes())?;
                }
            }
        }
        stream.flush()
    }

    pub fn read_from<R: Read>(stream: &mut R) -> io::Result<BlockAck> {
        let mut tag = [0u8; 1];
        stream.read_exact(&mut tag)?;

        let mut block_id_buf = [0u8; 4];
        stream.read_exact(&mut block_id_buf)?;
        let block_id = u32::from_be_bytes(block_id_buf);

        match tag[0] {
            CTRL_BLOCK_COMPLETE => Ok(BlockAck::Complete { block_id }),
            CTRL_BLOCK_ACK => {
                let mut count_buf = [0u8; 4];
                stream.read_exact(&mut count_buf)?;
                let count = u32::from_be_bytes(count_buf) as usize;

                let mut missing = Vec::with_capacity(count);
                let mut id_buf = [0u8; 2];
                for _ in 0..count {
                    stream.read_exact(&mut id_buf)?;
                    missing.push(u16::from_be_bytes(id_buf));
                }

                Ok(BlockAck::Missing { block_id, missing })
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown control tag {other:#x}"),
            )),
        }
    }
}
