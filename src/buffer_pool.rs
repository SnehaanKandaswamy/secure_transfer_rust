use crossbeam_queue::ArrayQueue;
use std::{
    mem,
    ops::{Deref, DerefMut},
    sync::Arc,
};

pub const BUFFER_SIZE: usize = 32 * 1024;

/// Thread-safe reusable buffer pool.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<ArrayQueue<Vec<u8>>>,
}

impl BufferPool {
    pub fn new(num_buffers: usize) -> Self {
        let queue = Arc::new(ArrayQueue::new(num_buffers));

        for _ in 0..num_buffers {
            queue
                .push(vec![0u8; BUFFER_SIZE])
                .expect("buffer pool full");
        }

        Self { inner: queue }
    }

    pub fn acquire(&self) -> PooledBuffer {
        let buffer = self
            .inner
            .pop()
            .unwrap_or_else(|| vec![0u8; BUFFER_SIZE]);

        PooledBuffer {
            buffer: Some(buffer),
            pool: self.inner.clone(),
        }
    }
}

pub struct PooledBuffer {
    buffer: Option<Vec<u8>>,
    pool: Arc<ArrayQueue<Vec<u8>>>,
}

impl PooledBuffer {
    pub fn into_vec(mut self) -> Vec<u8> {
        self.buffer.take().unwrap()
    }

    pub fn len(&self) -> usize {
        self.buffer.as_ref().unwrap().len()
    }

    pub fn capacity(&self) -> usize {
        self.buffer.as_ref().unwrap().capacity()
    }

    pub fn resize(&mut self, size: usize) {
        self.buffer.as_mut().unwrap().resize(size, 0);
    }

    pub fn clear(&mut self) {
        self.buffer.as_mut().unwrap().clear();
    }
}

impl Deref for PooledBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        self.buffer.as_ref().unwrap()
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.as_mut().unwrap()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(mut buffer) = self.buffer.take() {
            buffer.clear();

            if buffer.capacity() < BUFFER_SIZE {
                buffer.reserve(BUFFER_SIZE - buffer.capacity());
            }

            if buffer.len() != BUFFER_SIZE {
                buffer.resize(BUFFER_SIZE, 0);
            }

            let _ = self.pool.push(buffer);
        }
    }
}