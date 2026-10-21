//! GATT chunks: one header byte, followed by payload. Sequence resets per message.
pub const MAX_MESSAGE: usize = 1024;
pub const DEFAULT_CHUNK_SIZE: usize = 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    ChunkSize,
    EmptyChunk,
    Sequence,
    Oversize,
}

/// Produces at least one chunk, including for an empty message.
pub fn chunk(message: &[u8], chunk_size: usize) -> Result<Vec<Vec<u8>>, Error> {
    if chunk_size < 2 {
        return Err(Error::ChunkSize);
    }
    if message.len() > MAX_MESSAGE {
        return Err(Error::Oversize);
    }
    if message.is_empty() {
        return Ok(vec![vec![0x80]]);
    }
    let parts = message.chunks(chunk_size - 1);
    let count = parts.len();
    Ok(parts
        .enumerate()
        .map(|(seq, part)| {
            let mut out = Vec::with_capacity(part.len() + 1);
            out.push((seq % 128) as u8 | if seq + 1 == count { 0x80 } else { 0 });
            out.extend_from_slice(part);
            out
        })
        .collect())
}

/// After an error this object stays failed until explicitly reset for a new
/// session. A framing violation requires the caller to close the connection.
#[derive(Debug)]
pub struct Reassembler {
    chunk_size: usize,
    next: u8,
    buffer: Vec<u8>,
    failed: bool,
}

impl Reassembler {
    pub fn new(chunk_size: usize) -> Result<Self, Error> {
        if chunk_size < 2 {
            return Err(Error::ChunkSize);
        }
        Ok(Self {
            chunk_size,
            next: 0,
            buffer: Vec::new(),
            failed: false,
        })
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.next = 0;
        self.failed = false;
    }

    pub fn receive(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let result = self.receive_inner(chunk);
        if result.is_err() {
            self.buffer.clear();
            self.next = 0;
            self.failed = true;
        }
        result
    }

    fn receive_inner(&mut self, chunk: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        if self.failed {
            return Err(Error::Sequence);
        }
        let (&header, data) = chunk.split_first().ok_or(Error::EmptyChunk)?;
        if chunk.len() > self.chunk_size {
            return Err(Error::ChunkSize);
        }
        if header & 0x7f != self.next {
            return Err(Error::Sequence);
        }
        if self.buffer.len() + data.len() > MAX_MESSAGE {
            return Err(Error::Oversize);
        }
        self.buffer.extend_from_slice(data);
        self.next = (self.next + 1) % 128;
        if header & 0x80 != 0 {
            self.next = 0;
            return Ok(Some(std::mem::take(&mut self.buffer)));
        }
        Ok(None)
    }
}
