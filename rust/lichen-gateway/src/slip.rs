//! SLIP framing (RFC 1055).
//!
//! SLIP is a trivial byte-stuffing framing protocol.  Each packet is bounded
//! by END (0xC0) bytes; END and ESC bytes in the payload are replaced by
//! two-byte escape sequences.
//!
//! Provides both async functions (`send_packet`/`recv_packet`) and a stateful
//! `SlipFramer` for non-blocking queue-based I/O.

use std::collections::VecDeque;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const END: u8 = 0xC0;
const ESC: u8 = 0xDB;
const ESC_END: u8 = 0xDC; // sent in place of END inside a packet
const ESC_ESC: u8 = 0xDD; // sent in place of ESC inside a packet

/// SLIP framing error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlipError {
    /// Packet too large for buffer.
    PacketTooLarge,
    /// TX queue is full.
    QueueFull,
}

impl std::fmt::Display for SlipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketTooLarge => write!(f, "packet too large"),
            Self::QueueFull => write!(f, "TX queue full"),
        }
    }
}

impl std::error::Error for SlipError {}

/// Stateful SLIP framer with RX accumulation and TX queue.
///
/// Feed incoming bytes with `feed()`, retrieve complete packets from the
/// returned iterator. Queue outgoing packets with `queue_send()`, drain
/// encoded bytes with `try_get_tx()`.
///
/// # Example
///
/// ```
/// use lichen_gateway::slip::SlipFramer;
///
/// let mut framer = SlipFramer::new();
///
/// // Queue a packet to send
/// framer.queue_send(b"hello").unwrap();
///
/// // Get encoded bytes to write to serial
/// let mut tx_buf = [0u8; 64];
/// if let Some(len) = framer.try_get_tx(&mut tx_buf) {
///     // tx_buf[..len] contains: END, escaped data, END
/// }
///
/// // Feed incoming bytes from serial
/// let wire_data = [0xC0, 0x48, 0x69, 0xC0]; // "Hi" framed
/// let packets: Vec<_> = framer.feed(&wire_data).collect();
/// assert_eq!(packets.len(), 1);
/// assert_eq!(packets[0], b"Hi");
/// ```
pub struct SlipFramer {
    rx_buffer: Vec<u8>,
    rx_in_escape: bool,
    tx_queue: VecDeque<Vec<u8>>,
}

impl Default for SlipFramer {
    fn default() -> Self {
        Self::new()
    }
}

impl SlipFramer {
    /// Create a new framer.
    pub fn new() -> Self {
        Self {
            rx_buffer: Vec::with_capacity(2048),
            rx_in_escape: false,
            tx_queue: VecDeque::with_capacity(8),
        }
    }

    /// Feed incoming bytes and return an iterator of complete packets.
    ///
    /// Each call processes the input and yields any complete packets found.
    /// Partial packets are accumulated internally until complete.
    pub fn feed<'a>(&'a mut self, data: &'a [u8]) -> impl Iterator<Item = Vec<u8>> + 'a {
        SlipFeedIter {
            framer: self,
            data,
            pos: 0,
        }
    }

    /// Queue a packet for transmission.
    ///
    /// The packet is SLIP-encoded and stored in the TX queue.
    /// Returns error if queue is full (max 8 pending packets).
    pub fn queue_send(&mut self, packet: &[u8]) -> Result<(), SlipError> {
        if self.tx_queue.len() >= 8 {
            return Err(SlipError::QueueFull);
        }

        // Encode: leading END + escaped data + trailing END
        let mut encoded = Vec::with_capacity(packet.len() + 4);
        encoded.push(END);
        for &byte in packet {
            match byte {
                END => {
                    encoded.push(ESC);
                    encoded.push(ESC_END);
                }
                ESC => {
                    encoded.push(ESC);
                    encoded.push(ESC_ESC);
                }
                b => encoded.push(b),
            }
        }
        encoded.push(END);

        self.tx_queue.push_back(encoded);
        Ok(())
    }

    /// Try to get the next encoded TX frame.
    ///
    /// Returns the number of bytes written to `out`, or `None` if queue is empty.
    pub fn try_get_tx(&mut self, out: &mut [u8]) -> Option<usize> {
        let frame = self.tx_queue.pop_front()?;
        let len = frame.len().min(out.len());
        out[..len].copy_from_slice(&frame[..len]);
        Some(len)
    }

    /// Number of packets waiting in TX queue.
    pub fn tx_pending(&self) -> usize {
        self.tx_queue.len()
    }

    /// Check if TX queue is empty.
    pub fn tx_empty(&self) -> bool {
        self.tx_queue.is_empty()
    }

    /// Clear RX state and TX queue.
    pub fn clear(&mut self) {
        self.rx_buffer.clear();
        self.rx_in_escape = false;
        self.tx_queue.clear();
    }

    /// Process one byte, returning a complete packet if END delimiter received.
    fn process_byte(&mut self, byte: u8) -> Option<Vec<u8>> {
        match byte {
            END => {
                if self.rx_buffer.is_empty() {
                    // Empty END: inter-packet separator, ignore
                    None
                } else {
                    // Complete packet
                    Some(std::mem::take(&mut self.rx_buffer))
                }
            }
            ESC => {
                self.rx_in_escape = true;
                None
            }
            ESC_END if self.rx_in_escape => {
                self.rx_in_escape = false;
                self.rx_buffer.push(END);
                None
            }
            ESC_ESC if self.rx_in_escape => {
                self.rx_in_escape = false;
                self.rx_buffer.push(ESC);
                None
            }
            b => {
                self.rx_in_escape = false;
                self.rx_buffer.push(b);
                None
            }
        }
    }
}

/// Iterator over complete packets from a feed() call.
struct SlipFeedIter<'a> {
    framer: &'a mut SlipFramer,
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for SlipFeedIter<'a> {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.pos < self.data.len() {
            let byte = self.data[self.pos];
            self.pos += 1;
            if let Some(packet) = self.framer.process_byte(byte) {
                return Some(packet);
            }
        }
        None
    }
}

/// Send `packet` as a single SLIP frame on `writer`.
///
/// Surrounds the packet with END bytes and escapes any END/ESC bytes in the
/// payload per RFC 1055 §2.
pub async fn send_packet<W: AsyncWrite + Unpin>(writer: &mut W, packet: &[u8]) -> io::Result<()> {
    // Leading END flushes any garbage from a previous interrupted packet.
    writer.write_all(&[END]).await?;

    let mut buf = Vec::with_capacity(packet.len() + 2);
    for &byte in packet {
        match byte {
            END => {
                buf.push(ESC);
                buf.push(ESC_END);
            }
            ESC => {
                buf.push(ESC);
                buf.push(ESC_ESC);
            }
            b => buf.push(b),
        }
    }
    buf.push(END);
    writer.write_all(&buf).await?;
    Ok(())
}

/// Read one SLIP packet from `reader` into `buf`.
///
/// Blocks until a complete packet is received (terminated by END).
/// Returns the number of bytes written into `buf`, or an error if `buf`
/// is too small.
pub async fn recv_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> io::Result<usize> {
    let mut out = 0usize;
    let mut in_escape = false;

    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte).await?;
        let byte = byte[0];

        match byte {
            END => {
                if out > 0 {
                    // Non-empty packet complete.
                    return Ok(out);
                }
                // Empty END: inter-packet separator, keep reading.
            }
            ESC => {
                in_escape = true;
            }
            ESC_END if in_escape => {
                in_escape = false;
                if out >= buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SLIP packet too large",
                    ));
                }
                buf[out] = END;
                out += 1;
            }
            ESC_ESC if in_escape => {
                in_escape = false;
                if out >= buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SLIP packet too large",
                    ));
                }
                buf[out] = ESC;
                out += 1;
            }
            b => {
                in_escape = false;
                if out >= buf.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SLIP packet too large",
                    ));
                }
                buf[out] = b;
                out += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn roundtrip(packet: &[u8]) -> Vec<u8> {
        let mut wire = Vec::new();
        send_packet(&mut wire, packet).await.unwrap();

        let mut decoded = vec![0u8; packet.len() + 4];
        let n = recv_packet(&mut wire.as_slice(), &mut decoded)
            .await
            .unwrap();
        decoded.truncate(n);
        decoded
    }

    #[tokio::test]
    async fn plain_packet() {
        let data = b"hello SLIP";
        assert_eq!(roundtrip(data).await, data);
    }

    #[tokio::test]
    async fn packet_with_end_byte() {
        let data = [0x01, END, 0x02];
        assert_eq!(roundtrip(&data).await, &data);
    }

    #[tokio::test]
    async fn packet_with_esc_byte() {
        let data = [0x01, ESC, 0x02];
        assert_eq!(roundtrip(&data).await, &data);
    }

    #[tokio::test]
    async fn packet_with_both_special_bytes() {
        let data = [END, ESC, END, 0x42, ESC];
        assert_eq!(roundtrip(&data).await, &data);
    }

    #[test]
    fn framer_simple_rx() {
        let mut framer = SlipFramer::new();
        let packets: Vec<_> = framer.feed(&[END, b'H', b'i', END]).collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], b"Hi");
    }

    #[test]
    fn framer_partial_rx() {
        let mut framer = SlipFramer::new();

        // Feed partial packet
        let packets1: Vec<_> = framer.feed(&[END, b'H']).collect();
        assert!(packets1.is_empty());

        // Complete it
        let packets2: Vec<_> = framer.feed(&[b'i', END]).collect();
        assert_eq!(packets2.len(), 1);
        assert_eq!(packets2[0], b"Hi");
    }

    #[test]
    fn framer_multiple_rx() {
        let mut framer = SlipFramer::new();
        let packets: Vec<_> = framer.feed(&[END, b'A', END, END, b'B', END]).collect();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], b"A");
        assert_eq!(packets[1], b"B");
    }

    #[test]
    fn framer_rx_with_escapes() {
        let mut framer = SlipFramer::new();
        // "A" + END (escaped) + "B"
        let packets: Vec<_> = framer.feed(&[END, b'A', ESC, ESC_END, b'B', END]).collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], &[b'A', END, b'B']);
    }

    #[test]
    fn framer_tx_queue() {
        let mut framer = SlipFramer::new();
        let mut out = [0u8; 64];

        framer.queue_send(b"Hi").unwrap();
        assert_eq!(framer.tx_pending(), 1);

        let len = framer.try_get_tx(&mut out).unwrap();
        assert_eq!(&out[..len], &[END, b'H', b'i', END]);
        assert!(framer.tx_empty());
    }

    #[test]
    fn framer_tx_with_escapes() {
        let mut framer = SlipFramer::new();
        let mut out = [0u8; 64];

        framer.queue_send(&[b'A', END, b'B']).unwrap();
        let len = framer.try_get_tx(&mut out).unwrap();
        assert_eq!(&out[..len], &[END, b'A', ESC, ESC_END, b'B', END]);
    }

    #[test]
    fn framer_roundtrip() {
        let mut tx_framer = SlipFramer::new();
        let mut rx_framer = SlipFramer::new();
        let mut wire = [0u8; 64];

        // Encode with TX framer
        tx_framer.queue_send(b"Hello").unwrap();
        let len = tx_framer.try_get_tx(&mut wire).unwrap();

        // Decode with RX framer
        let packets: Vec<_> = rx_framer.feed(&wire[..len]).collect();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], b"Hello");
    }
}
