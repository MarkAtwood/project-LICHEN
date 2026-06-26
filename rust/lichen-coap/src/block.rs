//! CoAP blockwise transfer (RFC 7959).
//!
//! Block options enable chunked transfer of large payloads over the constrained
//! CoAP MTU. Block1 is for request payloads (uploads), Block2 for response
//! payloads (downloads).

use crate::codec::{CoapBuilder, CoapError, CoapOption};
use crate::option::OptionNumber;

/// Block option value (Block1 or Block2).
///
/// Wire format: 1-3 bytes encoding NUM (4-20 bits), M flag (1 bit), SZX (3 bits).
/// - SZX: size exponent (block size = 2^(SZX+4), valid 0-6 = 16-1024 bytes)
/// - M: more blocks follow
/// - NUM: block number (0-based)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockOption {
    /// Block number (0-based).
    pub num: u32,
    /// More blocks follow.
    pub more: bool,
    /// Size exponent (0-6). Block size = 2^(szx+4).
    pub szx: u8,
}

impl BlockOption {
    /// Minimum block size (16 bytes, SZX=0).
    pub const MIN_SIZE: usize = 16;
    /// Maximum block size (1024 bytes, SZX=6).
    pub const MAX_SIZE: usize = 1024;

    /// Create a new block option.
    ///
    /// # Panics
    /// Panics if `szx > 6` or `num > 0xFFFFF` (20-bit max).
    pub fn new(num: u32, more: bool, szx: u8) -> Self {
        assert!(szx <= 6, "SZX must be 0-6");
        assert!(num <= 0xFFFFF, "block number must fit in 20 bits");
        Self { num, more, szx }
    }

    /// Parse from option value bytes (1-3 bytes).
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.is_empty() || data.len() > 3 {
            return None;
        }
        // Decode as big-endian integer
        let mut val = 0u32;
        for &b in data {
            val = (val << 8) | b as u32;
        }
        let szx = (val & 0x07) as u8;
        let more = (val & 0x08) != 0;
        let num = val >> 4;
        if szx > 6 {
            return None;
        }
        Some(Self { num, more, szx })
    }

    /// Encode to bytes (1-3 bytes, minimal encoding).
    pub fn to_bytes(&self) -> ([u8; 3], usize) {
        let val = (self.num << 4) | ((self.more as u32) << 3) | (self.szx as u32);
        if val <= 0xFF {
            ([val as u8, 0, 0], 1)
        } else if val <= 0xFFFF {
            ([(val >> 8) as u8, val as u8, 0], 2)
        } else {
            ([(val >> 16) as u8, (val >> 8) as u8, val as u8], 3)
        }
    }

    /// Block size in bytes.
    pub fn size(&self) -> usize {
        1 << (self.szx + 4)
    }

    /// Byte offset of this block in the complete payload.
    pub fn offset(&self) -> usize {
        self.num as usize * self.size()
    }

    /// Create from block size (rounds down to valid SZX).
    pub fn from_size(num: u32, more: bool, size: usize) -> Self {
        let szx = size_to_szx(size);
        Self::new(num, more, szx)
    }
}

/// Convert block size to SZX exponent (rounds down).
pub fn size_to_szx(size: usize) -> u8 {
    match size {
        0..=15 => 0,
        16..=31 => 0,
        32..=63 => 1,
        64..=127 => 2,
        128..=255 => 3,
        256..=511 => 4,
        512..=1023 => 5,
        _ => 6,
    }
}

/// Convert SZX exponent to block size.
pub fn szx_to_size(szx: u8) -> usize {
    1 << (szx.min(6) + 4)
}

impl<'a> CoapOption<'a> {
    /// True if this is a Block1 option.
    pub fn is_block1(&self) -> bool {
        self.number == OptionNumber::Block1 as u16
    }

    /// True if this is a Block2 option.
    pub fn is_block2(&self) -> bool {
        self.number == OptionNumber::Block2 as u16
    }

    /// True if this is a Size1 option.
    pub fn is_size1(&self) -> bool {
        self.number == OptionNumber::Size1 as u16
    }

    /// True if this is a Size2 option.
    pub fn is_size2(&self) -> bool {
        self.number == OptionNumber::Size2 as u16
    }

    /// Parse as Block1 or Block2 option.
    pub fn as_block(&self) -> Option<BlockOption> {
        if self.is_block1() || self.is_block2() {
            BlockOption::from_bytes(self.value)
        } else {
            None
        }
    }
}

impl<'a> CoapBuilder<'a> {
    /// Add a Block1 option (for request payload chunking).
    pub fn block1(&mut self, block: BlockOption) -> Result<&mut Self, CoapError> {
        let (bytes, len) = block.to_bytes();
        self.option(OptionNumber::Block1 as u16, &bytes[..len])
    }

    /// Add a Block2 option (for response payload chunking).
    pub fn block2(&mut self, block: BlockOption) -> Result<&mut Self, CoapError> {
        let (bytes, len) = block.to_bytes();
        self.option(OptionNumber::Block2 as u16, &bytes[..len])
    }

    /// Add a Size1 option (total request body size).
    pub fn size1(&mut self, size: u32) -> Result<&mut Self, CoapError> {
        let bytes = uint_to_bytes(size);
        self.option(OptionNumber::Size1 as u16, &bytes[..uint_len(size)])
    }

    /// Add a Size2 option (total response body size).
    pub fn size2(&mut self, size: u32) -> Result<&mut Self, CoapError> {
        let bytes = uint_to_bytes(size);
        self.option(OptionNumber::Size2 as u16, &bytes[..uint_len(size)])
    }
}

/// Encode u32 as minimal big-endian bytes.
fn uint_to_bytes(val: u32) -> [u8; 4] {
    val.to_be_bytes()
}

/// Minimal encoding length for u32.
fn uint_len(val: u32) -> usize {
    if val == 0 {
        0
    } else if val <= 0xFF {
        1
    } else if val <= 0xFFFF {
        2
    } else if val <= 0xFFFFFF {
        3
    } else {
        4
    }
}

/// Blockwise transfer sender state.
#[derive(Debug)]
pub struct BlockSender {
    /// Full payload to send.
    data: [u8; 4096],
    data_len: usize,
    /// Block size (negotiated).
    block_size: usize,
    /// Current block number.
    current_block: u32,
    /// True when all blocks acknowledged.
    complete: bool,
}

impl BlockSender {
    /// Maximum payload size for blockwise transfer.
    pub const MAX_PAYLOAD: usize = 4096;

    /// Create a new sender for the given payload.
    pub fn new(payload: &[u8], block_size: usize) -> Option<Self> {
        if payload.len() > Self::MAX_PAYLOAD {
            return None;
        }
        let mut data = [0u8; Self::MAX_PAYLOAD];
        data[..payload.len()].copy_from_slice(payload);
        Some(Self {
            data,
            data_len: payload.len(),
            block_size: block_size.clamp(BlockOption::MIN_SIZE, BlockOption::MAX_SIZE),
            current_block: 0,
            complete: false,
        })
    }

    /// Total payload size.
    pub fn total_size(&self) -> usize {
        self.data_len
    }

    /// Number of blocks needed.
    pub fn block_count(&self) -> u32 {
        ((self.data_len + self.block_size - 1) / self.block_size) as u32
    }

    /// Get the next block to send. Returns (block_option, block_data).
    pub fn next_block(&self) -> Option<(BlockOption, &[u8])> {
        if self.complete {
            return None;
        }
        let offset = self.current_block as usize * self.block_size;
        if offset >= self.data_len {
            return None;
        }
        let end = (offset + self.block_size).min(self.data_len);
        let more = end < self.data_len;
        let block = BlockOption::from_size(self.current_block, more, self.block_size);
        Some((block, &self.data[offset..end]))
    }

    /// Acknowledge current block and advance. Returns true if transfer complete.
    pub fn ack_block(&mut self, block_num: u32) -> bool {
        if block_num == self.current_block {
            self.current_block += 1;
            if self.current_block >= self.block_count() {
                self.complete = true;
            }
        }
        self.complete
    }

    /// Handle server requesting smaller block size.
    pub fn resize(&mut self, new_szx: u8) {
        let new_size = szx_to_size(new_szx);
        if new_size < self.block_size {
            // Server wants smaller blocks - recalculate current position
            let current_offset = self.current_block as usize * self.block_size;
            self.block_size = new_size;
            self.current_block = (current_offset / new_size) as u32;
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

/// Blockwise transfer receiver state.
#[derive(Debug)]
pub struct BlockReceiver {
    /// Accumulated payload.
    data: [u8; 4096],
    data_len: usize,
    /// Expected next block number.
    expected_block: u32,
    /// Negotiated block size.
    block_size: usize,
    /// Expected total size (from Size2 option).
    expected_size: Option<usize>,
    /// True when final block received.
    complete: bool,
}

impl BlockReceiver {
    /// Maximum payload size.
    pub const MAX_PAYLOAD: usize = 4096;

    /// Create a new receiver.
    pub fn new(block_size: usize) -> Self {
        Self {
            data: [0u8; Self::MAX_PAYLOAD],
            data_len: 0,
            expected_block: 0,
            block_size: block_size.clamp(BlockOption::MIN_SIZE, BlockOption::MAX_SIZE),
            expected_size: None,
            complete: false,
        }
    }

    /// Set expected total size (from Size2 option).
    pub fn set_expected_size(&mut self, size: usize) {
        self.expected_size = Some(size);
    }

    /// Receive a block. Returns true if this completes the transfer.
    pub fn receive_block(&mut self, block: BlockOption, data: &[u8]) -> Result<bool, CoapError> {
        if block.num != self.expected_block {
            // Out of order - for now, reject
            return Err(CoapError::InvalidOptionDelta);
        }
        let offset = block.offset();
        if offset + data.len() > Self::MAX_PAYLOAD {
            return Err(CoapError::BufferTooSmall);
        }

        self.data[offset..offset + data.len()].copy_from_slice(data);
        self.data_len = offset + data.len();
        self.expected_block = block.num + 1;

        if !block.more {
            self.complete = true;
        }
        Ok(self.complete)
    }

    /// Get the assembled payload (only valid after complete).
    pub fn payload(&self) -> &[u8] {
        &self.data[..self.data_len]
    }

    /// Next block number to request.
    pub fn next_request_block(&self) -> BlockOption {
        BlockOption::from_size(self.expected_block, false, self.block_size)
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_option_roundtrip() {
        let cases = [
            BlockOption::new(0, false, 2),   // num=0, m=0, szx=2 (64 bytes)
            BlockOption::new(0, true, 2),    // num=0, m=1, szx=2
            BlockOption::new(15, false, 6),  // num=15, m=0, szx=6 (1024 bytes)
            BlockOption::new(255, true, 4),  // num=255, m=1, szx=4
            BlockOption::new(4095, true, 0), // large block number
        ];
        for original in cases {
            let (bytes, len) = original.to_bytes();
            let parsed = BlockOption::from_bytes(&bytes[..len]).unwrap();
            assert_eq!(parsed, original, "roundtrip failed for {:?}", original);
        }
    }

    #[test]
    fn block_option_size() {
        assert_eq!(BlockOption::new(0, false, 0).size(), 16);
        assert_eq!(BlockOption::new(0, false, 1).size(), 32);
        assert_eq!(BlockOption::new(0, false, 2).size(), 64);
        assert_eq!(BlockOption::new(0, false, 3).size(), 128);
        assert_eq!(BlockOption::new(0, false, 4).size(), 256);
        assert_eq!(BlockOption::new(0, false, 5).size(), 512);
        assert_eq!(BlockOption::new(0, false, 6).size(), 1024);
    }

    #[test]
    fn block_option_offset() {
        let block = BlockOption::new(3, false, 4); // block 3, 256 bytes
        assert_eq!(block.offset(), 768);
    }

    #[test]
    fn size_to_szx_values() {
        assert_eq!(size_to_szx(16), 0);
        assert_eq!(size_to_szx(32), 1);
        assert_eq!(size_to_szx(64), 2);
        assert_eq!(size_to_szx(128), 3);
        assert_eq!(size_to_szx(256), 4);
        assert_eq!(size_to_szx(512), 5);
        assert_eq!(size_to_szx(1024), 6);
        assert_eq!(size_to_szx(2048), 6); // capped
    }

    #[test]
    fn sender_single_block() {
        let payload = b"hello";
        let sender = BlockSender::new(payload, 64).unwrap();
        assert_eq!(sender.block_count(), 1);
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 0);
        assert!(!block.more);
        assert_eq!(data, b"hello");
    }

    #[test]
    fn sender_multiple_blocks() {
        let payload = [0u8; 200];
        let mut sender = BlockSender::new(&payload, 64).unwrap();
        assert_eq!(sender.block_count(), 4); // 200/64 = 3.125 → 4 blocks

        // Block 0
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 0);
        assert!(block.more);
        assert_eq!(data.len(), 64);

        sender.ack_block(0);

        // Block 1
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 1);
        assert!(block.more);
        assert_eq!(data.len(), 64);

        sender.ack_block(1);

        // Block 2
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 2);
        assert!(block.more);
        assert_eq!(data.len(), 64);

        sender.ack_block(2);

        // Block 3 (final)
        let (block, data) = sender.next_block().unwrap();
        assert_eq!(block.num, 3);
        assert!(!block.more);
        assert_eq!(data.len(), 8); // 200 - 192 = 8

        assert!(sender.ack_block(3));
        assert!(sender.is_complete());
    }

    #[test]
    fn receiver_single_block() {
        let mut receiver = BlockReceiver::new(64);
        let block = BlockOption::new(0, false, 2);
        let done = receiver.receive_block(block, b"hello").unwrap();
        assert!(done);
        assert_eq!(receiver.payload(), b"hello");
    }

    #[test]
    fn receiver_multiple_blocks() {
        let mut receiver = BlockReceiver::new(64);

        // Block 0
        let block0 = BlockOption::new(0, true, 2);
        assert!(!receiver.receive_block(block0, &[1u8; 64]).unwrap());

        // Block 1
        let block1 = BlockOption::new(1, true, 2);
        assert!(!receiver.receive_block(block1, &[2u8; 64]).unwrap());

        // Block 2 (final)
        let block2 = BlockOption::new(2, false, 2);
        assert!(receiver.receive_block(block2, &[3u8; 32]).unwrap());

        let payload = receiver.payload();
        assert_eq!(payload.len(), 160);
        assert!(payload[..64].iter().all(|&b| b == 1));
        assert!(payload[64..128].iter().all(|&b| b == 2));
        assert!(payload[128..160].iter().all(|&b| b == 3));
    }
}
