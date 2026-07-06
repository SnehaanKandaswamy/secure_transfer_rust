use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;

#[derive(Serialize, Deserialize, Debug)]
pub struct DataPacket {
    pub chunk_id: u32,
    pub encrypted_size: u32,
    pub hash: u64,
    pub encrypted: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FinishPacket {
    pub total_chunks: u32,
    pub file_hash: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MissingPacket {
    pub missing_chunks: Vec<u32>,
}

// ---------------- Continuous control channel (receiver -> sender) ----------------
//
// Sent repeatedly over TCP for the lifetime of a transfer instead of once at
// the very end.
//
// `Ack` is a progress report bounded to the receiver's current lookahead
// window:
//   - `highest_contiguous`: everything below this is fully delivered.
//   - `acked`: ids *above* that floor the receiver already has (selective
//     ack). Needed because a later chunk can land fine while an earlier one
//     is still missing - without reporting these explicitly, the sender has
//     no way to know it can stop tracking them, since the cumulative floor
//     alone never reaches them.
//   - `missing`: ids in the window the receiver is still waiting on.
//
// `Done` closes the loop once every chunk has arrived.

const ACK_TAG: u8 = 0x01;
const DONE_TAG: u8 = 0x02;

pub enum ControlMessage {
    Ack {
        highest_contiguous: u32,
        acked: Vec<u32>,
        missing: Vec<u32>,
    },
    Done,
}

pub fn encode_ack(highest_contiguous: u32, acked: &[u32], missing: &[u32]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 4 + 4 + acked.len() * 4 + 4 + missing.len() * 4);
    buf.push(ACK_TAG);
    buf.extend_from_slice(&highest_contiguous.to_be_bytes());

    buf.extend_from_slice(&(acked.len() as u32).to_be_bytes());
    for id in acked {
        buf.extend_from_slice(&id.to_be_bytes());
    }

    buf.extend_from_slice(&(missing.len() as u32).to_be_bytes());
    for id in missing {
        buf.extend_from_slice(&id.to_be_bytes());
    }

    buf
}

pub fn encode_done() -> Vec<u8> {
    vec![DONE_TAG]
}

/// Blocking read of exactly one control message from a TCP stream.
pub fn read_control_message(stream: &mut impl Read) -> Result<ControlMessage> {
    let mut tag = [0u8; 1];
    stream.read_exact(&mut tag)?;

    match tag[0] {
        ACK_TAG => {
            let mut hc_buf = [0u8; 4];
            stream.read_exact(&mut hc_buf)?;
            let highest_contiguous = u32::from_be_bytes(hc_buf);

            let acked = read_id_list(stream)?;
            let missing = read_id_list(stream)?;

            Ok(ControlMessage::Ack {
                highest_contiguous,
                acked,
                missing,
            })
        }
        DONE_TAG => Ok(ControlMessage::Done),
        other => bail!("unknown control message tag: {other}"),
    }
}

fn read_id_list(stream: &mut impl Read) -> Result<Vec<u32>> {
    let mut count_buf = [0u8; 4];
    stream.read_exact(&mut count_buf)?;
    let count = u32::from_be_bytes(count_buf) as usize;

    let mut id_bytes = vec![0u8; count * 4];
    stream.read_exact(&mut id_bytes)?;

    Ok(id_bytes
        .chunks_exact(4)
        .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
        .collect())
}
