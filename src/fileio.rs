use anyhow::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use crate::config::CHUNK_SIZE;

/// Read a file in chunks.
pub fn read_chunks(path: &str) -> Result<Vec<(u32, Vec<u8>)>> {
    let mut file = File::open(path)?;
    let mut chunks = Vec::new();

    let mut chunk_id = 0u32;

    loop {
        let mut buffer = vec![0u8; CHUNK_SIZE];

        let bytes = file.read(&mut buffer)?;

        if bytes == 0 {
            break;
        }

        buffer.truncate(bytes);

        chunks.push((chunk_id, buffer));

        chunk_id += 1;
    }

    Ok(chunks)
}

/// Write one chunk at its correct location.
pub fn write_chunk(
    file: &mut File,
    chunk_id: u32,
    data: &[u8],
) -> Result<()> {

    let offset = chunk_id as u64 * CHUNK_SIZE as u64;

    file.seek(SeekFrom::Start(offset))?;

    file.write_all(data)?;

    Ok(())
}