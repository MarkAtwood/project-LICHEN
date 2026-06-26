//! Async UDP CoAP client (requires `tokio` feature).
//!
//! Sends a single CoAP request and waits for a response, with a 5-second
//! timeout.  Supports GET, POST, and PUT with optional CBOR payloads.
//!
//! This is intentionally minimal — no retransmission logic, no Observe, no
//! block-wise transfer.  It is suitable for CLI and TUI tools that talk to a
//! local LICHEN node over the loopback or LAN.

use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

const COAP_VERSION_CON: u8 = 0x40; // Ver=1 | T=CON
const TIMEOUT_S: u64 = 5;

/// A decoded CoAP response.
#[derive(Debug)]
pub struct Response {
    /// Raw CoAP code byte (class in upper 3 bits, detail in lower 5).
    pub code: u8,
    /// Response payload (empty if none).
    pub payload: Vec<u8>,
}

impl Response {
    /// True for 2.xx success codes.
    pub fn is_success(&self) -> bool {
        self.code >> 5 == 2
    }

    /// Human-readable code string, e.g. `"2.05"`.
    pub fn code_str(&self) -> String {
        format!("{}.{:02}", self.code >> 5, self.code & 0x1f)
    }
}

/// GET coap://[addr][path].
pub async fn get(addr: SocketAddr, path: &str) -> std::io::Result<Response> {
    request(addr, 0x01, path, None).await
}

/// POST coap://[addr][path] with CBOR body.
pub async fn post(addr: SocketAddr, path: &str, body: &[u8]) -> std::io::Result<Response> {
    request(addr, 0x02, path, Some(body)).await
}

/// PUT coap://[addr][path] with CBOR body.
pub async fn put(addr: SocketAddr, path: &str, body: &[u8]) -> std::io::Result<Response> {
    request(addr, 0x03, path, Some(body)).await
}

/// DELETE coap://[addr][path].
pub async fn delete(addr: SocketAddr, path: &str) -> std::io::Result<Response> {
    request(addr, 0x04, path, None).await
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

async fn request(
    addr: SocketAddr,
    code: u8,
    path: &str,
    payload: Option<&[u8]>,
) -> std::io::Result<Response> {
    let bind = if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;

    let mid = mid_from_time();
    let token = [0x4c, 0x49, 0x43, 0x48]; // "LICH"
    let frame = encode(code, mid, &token, path, payload)?;

    sock.send(&frame).await?;

    let mut buf = vec![0u8; 1280];
    let n = timeout(Duration::from_secs(TIMEOUT_S), sock.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "CoAP timeout"))??;

    decode(&buf[..n])
}

/// Build a CoAP message.
///
/// Handles Uri-Path options (11) and Content-Format (12, value 60 = CBOR)
/// when a payload is present.  Both delta and length must fit in 4 bits
/// for these options, which holds for all LICHEN path segments and for
/// Content-Format 60 (1-byte value).
fn encode(
    code: u8,
    mid: u16,
    token: &[u8],
    path: &str,
    payload: Option<&[u8]>,
) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(256);

    // Header
    buf.push(COAP_VERSION_CON | token.len() as u8);
    buf.push(code);
    buf.push((mid >> 8) as u8);
    buf.push(mid as u8);
    buf.extend_from_slice(token);

    // Uri-Path options (option 11)
    let mut prev: u16 = 0;
    for seg in path.trim_start_matches('/').split('/') {
        if seg.is_empty() {
            continue;
        }
        let delta = 11u16 - prev;
        if delta > 12 || seg.len() > 12 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "path segment or option delta too large for basic encoder",
            ));
        }
        buf.push(((delta as u8) << 4) | seg.len() as u8);
        buf.extend_from_slice(seg.as_bytes());
        prev = 11;
    }

    // Content-Format 12 (value 60 = CBOR, 1 byte) when body is present
    if payload.map(|p| !p.is_empty()).unwrap_or(false) {
        let delta = 12u16 - prev;
        if delta <= 12 {
            buf.push(((delta as u8) << 4) | 1u8);
            buf.push(60u8); // CBOR
            prev = 12;
        }
        let _ = prev;
    }

    // Payload
    if let Some(p) = payload {
        if !p.is_empty() {
            buf.push(0xff); // payload marker
            buf.extend_from_slice(p);
        }
    }

    Ok(buf)
}

/// Parse a CoAP response.  Returns code + payload; ignores option values.
fn decode(data: &[u8]) -> std::io::Result<Response> {
    if data.len() < 4 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response too short",
        ));
    }
    let tkl = (data[0] & 0x0f) as usize;
    let code = data[1];

    let payload_start = skip_options(data, 4 + tkl)?;
    Ok(Response {
        code,
        payload: data[payload_start..].to_vec(),
    })
}

/// Walk past CoAP options and return the index of the first payload byte.
/// Returns `data.len()` if there is no payload marker.
fn skip_options(data: &[u8], mut i: usize) -> std::io::Result<usize> {
    while i < data.len() {
        if data[i] == 0xff {
            return Ok(i + 1);
        }
        let delta_nibble = (data[i] >> 4) & 0x0f;
        let len_nibble = data[i] & 0x0f;
        i += 1;

        // Extended delta
        i += match delta_nibble {
            13 => { i += 1; 0 }
            14 => { i += 2; 0 }
            15 => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, "reserved option delta 15")),
            _ => 0,
        };

        // Extended length
        let opt_len = match len_nibble {
            13 => {
                let v = *data.get(i).ok_or_else(|| trunc())? as usize + 13;
                i += 1;
                v
            }
            14 => {
                let hi = *data.get(i).ok_or_else(|| trunc())? as usize;
                let lo = *data.get(i + 1).ok_or_else(|| trunc())? as usize;
                i += 2;
                (hi << 8 | lo) + 269
            }
            15 => return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData, "reserved option length 15")),
            n => n as usize,
        };

        i = i.saturating_add(opt_len);
    }
    Ok(data.len())
}

fn trunc() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "truncated CoAP option")
}

/// Generate a pseudo-random 16-bit message ID from the system clock.
fn mid_from_time() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x1234)
}
