// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! OSCORE (RFC 8613) implementation for LICHEN.
//!
//! Provides end-to-end security for CoAP using AES-CCM-16-64-128 and HKDF-SHA256.
//!
//! # ponytail: pure-Rust OSCORE
//!
//! Using `ccm` + `hkdf` crates directly until a battle-tested no_std OSCORE crate
//! exists. `liboscore` requires C FFI which complicates embedded cross-compilation.
//! Switch to `liboscore` or `coapcore` when they mature for embedded targets.

#![cfg_attr(not(feature = "std"), no_std)]

use aes::Aes128;
use ccm::{
    aead::{AeadInPlace, KeyInit},
    consts::{U13, U8},
    Ccm,
};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// AES-CCM-16-64-128: 128-bit key, 13-byte nonce, 8-byte tag.
type AesCcm = Ccm<Aes128, U8, U13>;

/// Key length (16 bytes for AES-128).
pub const KEY_LEN: usize = 16;

/// Nonce length (13 bytes for CCM L=2).
pub const NONCE_LEN: usize = 13;

/// Authentication tag length (8 bytes).
pub const TAG_LEN: usize = 8;

/// Maximum sender/recipient ID length.
pub const ID_MAX_LEN: usize = 8;

/// Maximum Partial IV length.
pub const PIV_MAX_LEN: usize = 5;

/// COSE Algorithm ID for AES-CCM-16-64-128.
pub const ALG_AEAD: u8 = 10;

/// OSCORE CoAP option number.
pub const COAP_OPTION_OSCORE: u16 = 9;

/// OSCORE error types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid parameter provided.
    InvalidParam,
    /// Security context not found.
    NoContext,
    /// Replay attack detected.
    Replay,
    /// Decryption/authentication failed.
    DecryptFailed,
    /// Output buffer too small.
    BufferTooSmall,
    /// Key derivation failed.
    KeyDerivation,
}

/// OSCORE security context.
///
/// Contains cryptographic material and state for one peer.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct Context {
    // Common context
    master_secret: [u8; KEY_LEN],
    master_salt: [u8; 8],
    master_salt_len: u8,
    common_iv: [u8; NONCE_LEN],
    id_context: [u8; 8],
    id_context_len: u8,

    // Sender context
    sender_id: [u8; ID_MAX_LEN],
    sender_id_len: u8,
    sender_key: [u8; KEY_LEN],
    sender_seq: u32,

    // Recipient context
    recipient_id: [u8; ID_MAX_LEN],
    recipient_id_len: u8,
    recipient_key: [u8; KEY_LEN],
    recipient_seq: u32,
    replay_window: u32,
}

impl Context {
    /// Create a new OSCORE security context.
    ///
    /// Derives sender and recipient keys from master secret using HKDF-SHA256.
    pub fn new(
        master_secret: &[u8; KEY_LEN],
        master_salt: Option<&[u8]>,
        sender_id: &[u8],
        recipient_id: &[u8],
    ) -> Result<Self, Error> {
        if sender_id.len() > ID_MAX_LEN || recipient_id.len() > ID_MAX_LEN {
            return Err(Error::InvalidParam);
        }

        let salt = master_salt.unwrap_or(&[]);
        if salt.len() > 8 {
            return Err(Error::InvalidParam);
        }

        let mut ctx = Self {
            master_secret: *master_secret,
            master_salt: [0u8; 8],
            master_salt_len: salt.len() as u8,
            common_iv: [0u8; NONCE_LEN],
            id_context: [0u8; 8],
            id_context_len: 0,
            sender_id: [0u8; ID_MAX_LEN],
            sender_id_len: sender_id.len() as u8,
            sender_key: [0u8; KEY_LEN],
            sender_seq: 0,
            recipient_id: [0u8; ID_MAX_LEN],
            recipient_id_len: recipient_id.len() as u8,
            recipient_key: [0u8; KEY_LEN],
            recipient_seq: 0,
            replay_window: 0,
        };

        ctx.master_salt[..salt.len()].copy_from_slice(salt);
        ctx.sender_id[..sender_id.len()].copy_from_slice(sender_id);
        ctx.recipient_id[..recipient_id.len()].copy_from_slice(recipient_id);

        // Derive keys
        ctx.sender_key = derive_key(
            master_secret,
            salt,
            sender_id,
            &[],
            "Key",
            KEY_LEN,
        )?;

        ctx.recipient_key = derive_key(
            master_secret,
            salt,
            recipient_id,
            &[],
            "Key",
            KEY_LEN,
        )?;

        // Derive Common IV (empty ID for common context)
        let common_iv_bytes = derive_key(
            master_secret,
            salt,
            &[],
            &[],
            "IV",
            NONCE_LEN,
        )?;
        ctx.common_iv.copy_from_slice(&common_iv_bytes[..NONCE_LEN]);

        Ok(ctx)
    }

    /// Get the current sender sequence number.
    pub fn sender_seq(&self) -> u32 {
        self.sender_seq
    }

    /// Get sender ID.
    pub fn sender_id(&self) -> &[u8] {
        &self.sender_id[..self.sender_id_len as usize]
    }

    /// Get recipient ID.
    pub fn recipient_id(&self) -> &[u8] {
        &self.recipient_id[..self.recipient_id_len as usize]
    }

    /// Protect (encrypt) a CoAP request.
    ///
    /// Returns (ciphertext, OSCORE option value).
    pub fn protect_request(
        &mut self,
        code: u8,
        class_e_options: &[u8],
        payload: &[u8],
    ) -> Result<(heapless::Vec<u8, 280>, heapless::Vec<u8, 16>), Error> {
        // Get and increment sequence number
        let seq = self.sender_seq;
        self.sender_seq = self.sender_seq.wrapping_add(1);

        // Encode PIV
        let mut piv = [0u8; PIV_MAX_LEN];
        let piv_len = encode_piv(seq, &mut piv);

        // Compute nonce
        let nonce = compute_nonce(
            self.sender_id(),
            &piv[..piv_len],
            &self.common_iv,
        );

        // Build plaintext: code || options || 0xFF || payload
        let mut plaintext = heapless::Vec::<u8, 256>::new();
        plaintext.push(code).map_err(|_| Error::BufferTooSmall)?;
        plaintext.extend_from_slice(class_e_options).map_err(|_| Error::BufferTooSmall)?;
        if !payload.is_empty() {
            plaintext.push(0xFF).map_err(|_| Error::BufferTooSmall)?;
            plaintext.extend_from_slice(payload).map_err(|_| Error::BufferTooSmall)?;
        }

        // Encrypt in place
        // ponytail: empty AAD for now, proper AAD structure in RFC 8613 Section 5.4
        let cipher = AesCcm::new_from_slice(&self.sender_key).map_err(|_| Error::KeyDerivation)?;
        let mut ct_out = heapless::Vec::<u8, 280>::new();
        ct_out.extend_from_slice(&plaintext).map_err(|_| Error::BufferTooSmall)?;
        cipher
            .encrypt_in_place((&nonce).into(), &[], &mut ct_out)
            .map_err(|_| Error::DecryptFailed)?;

        // Build OSCORE option
        let mut opt = heapless::Vec::<u8, 16>::new();
        let flags = 0x08 | (piv_len as u8 & 0x07); // k=1, n=piv_len
        opt.push(flags).map_err(|_| Error::BufferTooSmall)?;
        opt.extend_from_slice(&piv[..piv_len]).map_err(|_| Error::BufferTooSmall)?;
        opt.extend_from_slice(self.sender_id()).map_err(|_| Error::BufferTooSmall)?;

        Ok((ct_out, opt))
    }

    /// Unprotect (decrypt) an OSCORE-protected request.
    ///
    /// Returns (code, class_e_options, payload).
    pub fn unprotect_request(
        &mut self,
        oscore_option: &[u8],
        ciphertext: &[u8],
    ) -> Result<(u8, heapless::Vec<u8, 128>, heapless::Vec<u8, 128>), Error> {
        if ciphertext.len() < TAG_LEN + 1 {
            return Err(Error::InvalidParam);
        }

        // Parse OSCORE option
        let opt = parse_option(oscore_option)?;

        if !opt.has_piv {
            return Err(Error::InvalidParam);
        }

        // Check replay
        let seq = decode_piv(&opt.piv[..opt.piv_len as usize]);
        if !self.check_replay(seq) {
            return Err(Error::Replay);
        }

        // Compute nonce
        let nonce = compute_nonce(
            self.recipient_id(),
            &opt.piv[..opt.piv_len as usize],
            &self.common_iv,
        );

        // Decrypt in place
        let cipher = AesCcm::new_from_slice(&self.recipient_key).map_err(|_| Error::KeyDerivation)?;
        let mut plaintext = heapless::Vec::<u8, 256>::new();
        plaintext.extend_from_slice(ciphertext).map_err(|_| Error::BufferTooSmall)?;
        cipher
            .decrypt_in_place((&nonce).into(), &[], &mut plaintext)
            .map_err(|_| Error::DecryptFailed)?;

        // Parse plaintext: code || options || 0xFF || payload
        if plaintext.is_empty() {
            return Err(Error::InvalidParam);
        }

        let code = plaintext[0];
        let rest = &plaintext[1..];

        // Find payload marker
        let marker_pos = rest.iter().position(|&b| b == 0xFF);

        let (options_slice, payload_slice) = match marker_pos {
            Some(pos) => (&rest[..pos], &rest[pos + 1..]),
            None => (rest, &[][..]),
        };

        let mut options = heapless::Vec::new();
        options.extend_from_slice(options_slice).map_err(|_| Error::BufferTooSmall)?;

        let mut payload = heapless::Vec::new();
        payload.extend_from_slice(payload_slice).map_err(|_| Error::BufferTooSmall)?;

        Ok((code, options, payload))
    }

    /// Check replay window and update if valid.
    fn check_replay(&mut self, seq: u32) -> bool {
        const WINDOW_SIZE: u32 = 32;

        if seq > self.recipient_seq {
            // New highest - shift window
            let shift = seq - self.recipient_seq;
            if shift >= 32 {
                self.replay_window = 0;
            } else {
                self.replay_window <<= shift;
            }
            self.replay_window |= 1;
            self.recipient_seq = seq;
            true
        } else {
            // Check if within window
            let diff = self.recipient_seq - seq;
            if diff >= WINDOW_SIZE {
                return false; // Too old
            }

            let mask = 1u32 << diff;
            if self.replay_window & mask != 0 {
                return false; // Already seen
            }

            self.replay_window |= mask;
            true
        }
    }
}

/// Parsed OSCORE option.
struct OscoreOption {
    piv: [u8; PIV_MAX_LEN],
    piv_len: u8,
    kid: [u8; ID_MAX_LEN],
    kid_len: u8,
    has_piv: bool,
    has_kid: bool,
}

fn parse_option(data: &[u8]) -> Result<OscoreOption, Error> {
    let mut opt = OscoreOption {
        piv: [0; PIV_MAX_LEN],
        piv_len: 0,
        kid: [0; ID_MAX_LEN],
        kid_len: 0,
        has_piv: false,
        has_kid: false,
    };

    if data.is_empty() {
        return Ok(opt);
    }

    let mut pos = 0;
    let flags = data[pos];
    pos += 1;

    if flags & 0x80 != 0 {
        return Err(Error::InvalidParam); // Reserved bit
    }

    let h_flag = flags & 0x10 != 0;
    let k_flag = flags & 0x08 != 0;
    let n = (flags & 0x07) as usize;

    // PIV
    if n > 0 {
        if n > PIV_MAX_LEN || pos + n > data.len() {
            return Err(Error::InvalidParam);
        }
        opt.piv[..n].copy_from_slice(&data[pos..pos + n]);
        opt.piv_len = n as u8;
        opt.has_piv = true;
        pos += n;
    }

    // KID Context (skip if present)
    if h_flag {
        if pos >= data.len() {
            return Err(Error::InvalidParam);
        }
        let s = data[pos] as usize;
        pos += 1;
        if pos + s > data.len() {
            return Err(Error::InvalidParam);
        }
        pos += s;
    }

    // KID
    if k_flag {
        let remaining = data.len() - pos;
        if remaining > ID_MAX_LEN {
            return Err(Error::InvalidParam);
        }
        opt.kid[..remaining].copy_from_slice(&data[pos..]);
        opt.kid_len = remaining as u8;
        opt.has_kid = true;
    }

    Ok(opt)
}

/// Derive key using HKDF-SHA256.
fn derive_key(
    master_secret: &[u8],
    master_salt: &[u8],
    id: &[u8],
    id_context: &[u8],
    type_str: &str,
    out_len: usize,
) -> Result<[u8; KEY_LEN], Error> {
    // Build CBOR info structure per RFC 8613 Section 3.2.1
    let mut info = [0u8; 64];
    let info_len = build_info_cbor(id, id_context, type_str, out_len, &mut info)?;

    let hk = Hkdf::<Sha256>::new(Some(master_salt), master_secret);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info[..info_len], &mut okm[..out_len])
        .map_err(|_| Error::KeyDerivation)?;

    Ok(okm)
}

/// Build OSCORE HKDF info CBOR structure.
fn build_info_cbor(
    id: &[u8],
    id_context: &[u8],
    type_str: &str,
    out_len: usize,
    buf: &mut [u8],
) -> Result<usize, Error> {
    let mut off = 0;

    // Array of 5 elements
    buf[off] = 0x85;
    off += 1;

    // id: bstr
    if id.len() <= 23 {
        buf[off] = 0x40 | (id.len() as u8);
        off += 1;
    } else {
        buf[off] = 0x58;
        buf[off + 1] = id.len() as u8;
        off += 2;
    }
    buf[off..off + id.len()].copy_from_slice(id);
    off += id.len();

    // id_context: bstr or null
    if id_context.is_empty() {
        buf[off] = 0xf6; // null
        off += 1;
    } else {
        if id_context.len() <= 23 {
            buf[off] = 0x40 | (id_context.len() as u8);
            off += 1;
        } else {
            buf[off] = 0x58;
            buf[off + 1] = id_context.len() as u8;
            off += 2;
        }
        buf[off..off + id_context.len()].copy_from_slice(id_context);
        off += id_context.len();
    }

    // alg_aead: int (10)
    buf[off] = ALG_AEAD;
    off += 1;

    // type: tstr
    let type_bytes = type_str.as_bytes();
    buf[off] = 0x60 | (type_bytes.len() as u8);
    off += 1;
    buf[off..off + type_bytes.len()].copy_from_slice(type_bytes);
    off += type_bytes.len();

    // L: uint
    if out_len <= 23 {
        buf[off] = out_len as u8;
        off += 1;
    } else {
        buf[off] = 0x18;
        buf[off + 1] = out_len as u8;
        off += 2;
    }

    Ok(off)
}

/// Compute nonce from Partial IV and Common IV per RFC 8613 Section 5.2.
fn compute_nonce(sender_id: &[u8], piv: &[u8], common_iv: &[u8; NONCE_LEN]) -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];

    // Left-padded sender ID
    let id_offset = NONCE_LEN - 6;
    if sender_id.len() <= 6 {
        let start = id_offset + (6 - sender_id.len());
        nonce[start..start + sender_id.len()].copy_from_slice(sender_id);
    }
    nonce[NONCE_LEN - 6 - 1] = sender_id.len() as u8;

    // Left-padded PIV (XOR)
    if !piv.is_empty() && piv.len() <= 5 {
        let piv_start = NONCE_LEN - piv.len();
        for (i, &b) in piv.iter().enumerate() {
            nonce[piv_start + i] ^= b;
        }
    }

    // XOR with common IV
    for (i, &b) in common_iv.iter().enumerate() {
        nonce[i] ^= b;
    }

    nonce
}

/// Encode sequence number as variable-length big-endian PIV.
fn encode_piv(seq: u32, piv: &mut [u8; PIV_MAX_LEN]) -> usize {
    if seq == 0 {
        piv[0] = 0;
        return 1;
    }

    let mut len = 0;
    let mut tmp = seq;
    while tmp > 0 {
        len += 1;
        tmp >>= 8;
    }

    let mut s = seq;
    for i in 0..len {
        piv[len - 1 - i] = (s & 0xFF) as u8;
        s >>= 8;
    }

    len
}

/// Decode PIV to sequence number.
fn decode_piv(piv: &[u8]) -> u32 {
    piv.iter().fold(0u32, |acc, &b| (acc << 8) | (b as u32))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_piv_encode_decode() {
        let mut piv = [0u8; PIV_MAX_LEN];

        let len = encode_piv(0, &mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 0);
        assert_eq!(decode_piv(&piv[..len]), 0);

        let len = encode_piv(1, &mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 1);
        assert_eq!(decode_piv(&piv[..len]), 1);

        let len = encode_piv(256, &mut piv);
        assert_eq!(len, 2);
        assert_eq!(&piv[..2], &[0x01, 0x00]);
        assert_eq!(decode_piv(&piv[..len]), 256);

        let len = encode_piv(0x123456, &mut piv);
        assert_eq!(len, 3);
        assert_eq!(&piv[..3], &[0x12, 0x34, 0x56]);
        assert_eq!(decode_piv(&piv[..len]), 0x123456);
    }

    #[test]
    fn test_context_creation() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let sender_id = &[0x00];
        let recipient_id = &[0x01];

        let ctx = Context::new(&master_secret, None, sender_id, recipient_id).unwrap();

        assert_eq!(ctx.sender_id(), &[0x00]);
        assert_eq!(ctx.recipient_id(), &[0x01]);
        assert_eq!(ctx.sender_seq(), 0);
    }

    #[test]
    fn test_replay_window() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut ctx = Context::new(&master_secret, None, &[0], &[1]).unwrap();

        // First packet accepted
        assert!(ctx.check_replay(0));
        // Replay rejected
        assert!(!ctx.check_replay(0));
        // New packet accepted
        assert!(ctx.check_replay(1));
        // Earlier replay rejected
        assert!(!ctx.check_replay(0));
        // Out of window rejected
        assert!(ctx.check_replay(100));
        assert!(!ctx.check_replay(50)); // Too old
    }

    #[test]
    fn test_protect_unprotect_roundtrip() {
        let master_secret = hex!("0102030405060708090a0b0c0d0e0f10");
        let mut sender_ctx = Context::new(&master_secret, None, &[0x00], &[0x01]).unwrap();
        let mut recipient_ctx = Context::new(&master_secret, None, &[0x01], &[0x00]).unwrap();

        let code = 0x01; // GET
        let payload = b"hello";

        let (ciphertext, oscore_opt) = sender_ctx
            .protect_request(code, &[], payload)
            .unwrap();

        let (dec_code, _options, dec_payload) = recipient_ctx
            .unprotect_request(&oscore_opt, &ciphertext)
            .unwrap();

        assert_eq!(dec_code, code);
        assert_eq!(dec_payload.as_slice(), payload);
    }
}
