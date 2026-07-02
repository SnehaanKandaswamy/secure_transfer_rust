use xxhash_rust::xxh64::Xxh64;
use std::hash::Hasher;

/// Returns the 64-bit xxHash of a chunk.
pub fn chunk_hash(data: &[u8]) -> u64 {
    let mut hasher = Xxh64::new(0);
    hasher.write(data);
    hasher.finish()
}

/// Streaming xxHash for entire file.
pub struct FileHasher {
    hasher: Xxh64,
}

impl FileHasher {
    pub fn new() -> Self {
        Self {
            hasher: Xxh64::new(0),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.write(data);
    }

    pub fn finish(self) -> u64 {
        self.hasher.finish()
    }
}