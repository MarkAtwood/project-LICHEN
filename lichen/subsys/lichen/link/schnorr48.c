/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schnorr48.c
 * @brief Schnorr-48 signatures per draft-lichen-schnorr-00
 *
 * IMPLEMENTATION STATUS: STUB
 *
 * This file provides the API stubs for Schnorr-48 signatures.
 * Full implementation requires Ed25519 primitives not available
 * in Zephyr's bundled mbedTLS (which lacks Edwards curves).
 *
 * Options for completing this implementation:
 *
 * 1. SUPERCOP ref10 - public domain Ed25519 reference, ~8KB code
 * 2. TweetNaCl - minimal Ed25519 in ~1KB, but variable-time
 * 3. Monocypher - small, audited, constant-time Ed25519
 * 4. Rust FFI - use lichen-link crate via cbindgen
 *
 * Monocypher is recommended for production embedded use.
 *
 * Test vectors: test/vectors/schnorr48.json
 * Reference impl: python/src/lichen/crypto/schnorr48.py
 */

#include <lichen/schnorr48.h>
#include <string.h>

/*
 * SHA-512 is available via mbedTLS or Zephyr's tinycrypt.
 * Ed25519 point operations need an external library.
 *
 * ponytail: placeholder implementation returns fixed patterns
 * for development builds; production MUST use real crypto.
 */

#ifdef CONFIG_LICHEN_LINK_SCHNORR_STUB
#warning "Using stub Schnorr-48 implementation - NOT FOR PRODUCTION"
#endif

void schnorr48_derive_keypair(const uint8_t seed[32],
			      uint8_t privkey[32],
			      uint8_t pubkey[32])
{
	/*
	 * Real implementation:
	 *   h = SHA-512(seed)
	 *   privkey = clamp(h[0:32])
	 *   pubkey = privkey * B (Ed25519 base point multiplication)
	 */

	/* ponytail: stub copies seed to privkey, zeros pubkey */
	memcpy(privkey, seed, 32);
	memset(pubkey, 0, 32);

	/* Stub: set pubkey[0] = 0x01 to indicate stub mode */
	pubkey[0] = 0x01;
}

void schnorr48_sign(const uint8_t privkey[32],
		    const uint8_t pubkey[32],
		    const uint8_t *msg, size_t msg_len,
		    uint8_t sig[48])
{
	/*
	 * Real implementation (draft-lichen-schnorr-00 Section 4.2):
	 *
	 * 1. r = H(privkey || msg) mod L       // deterministic nonce
	 * 2. R = r * B                         // commitment point
	 * 3. e = H(R || pubkey || msg)[0:16]   // truncated challenge
	 * 4. e_scalar = e || 0x00*16           // extend to 32 bytes
	 * 5. s = (r + e_scalar * privkey) mod L // response
	 * 6. sig = e || s                       // 48 bytes
	 */

	(void)privkey;
	(void)pubkey;
	(void)msg;
	(void)msg_len;

	/* ponytail: stub returns zeros */
	memset(sig, 0, 48);
}

bool schnorr48_verify(const uint8_t pubkey[32],
		      const uint8_t *msg, size_t msg_len,
		      const uint8_t sig[48])
{
	/*
	 * Real implementation (draft-lichen-schnorr-00 Section 4.3):
	 *
	 * 1. e_received = sig[0:16], s = sig[16:48]
	 * 2. Check s is canonical (< L) and non-zero
	 * 3. e_extended = e_received || 0x00*16
	 * 4. R' = s*B - e_extended*pubkey
	 * 5. e' = H(R' || pubkey || msg)[0:16]
	 * 6. Return e' == e_received (constant-time)
	 */

	(void)pubkey;
	(void)msg;
	(void)msg_len;
	(void)sig;

	/* ponytail: stub always returns false (fail-safe) */
	return false;
}

void schnorr48_sign_frame(uint8_t epoch, uint16_t seqnum,
			  const uint8_t *dst_addr, size_t dst_addr_len,
			  const uint8_t *payload, size_t payload_len,
			  const uint8_t privkey[32],
			  const uint8_t pubkey[32],
			  uint8_t sig[48])
{
	/*
	 * Build signable data: epoch(1) || seqnum(2, BE) || dst_addr || payload
	 * Then call schnorr48_sign() on the result.
	 */
	uint8_t buf[256];
	size_t off = 0;

	buf[off++] = epoch;
	buf[off++] = (uint8_t)(seqnum >> 8);
	buf[off++] = (uint8_t)(seqnum & 0xFF);

	if (dst_addr_len > 0 && dst_addr_len <= 8) {
		memcpy(&buf[off], dst_addr, dst_addr_len);
		off += dst_addr_len;
	}

	size_t copy_len = (payload_len < (sizeof(buf) - off)) ?
			  payload_len : (sizeof(buf) - off);
	memcpy(&buf[off], payload, copy_len);
	off += copy_len;

	schnorr48_sign(privkey, pubkey, buf, off, sig);
}

bool schnorr48_verify_frame(uint8_t epoch, uint16_t seqnum,
			    const uint8_t *dst_addr, size_t dst_addr_len,
			    const uint8_t *payload, size_t payload_len,
			    const uint8_t pubkey[32])
{
	if (payload_len < SCHNORR48_SIG_LEN) {
		return false;
	}

	size_t inner_len = payload_len - SCHNORR48_SIG_LEN;
	const uint8_t *sig = &payload[inner_len];

	/* Build signable data */
	uint8_t buf[256];
	size_t off = 0;

	buf[off++] = epoch;
	buf[off++] = (uint8_t)(seqnum >> 8);
	buf[off++] = (uint8_t)(seqnum & 0xFF);

	if (dst_addr_len > 0 && dst_addr_len <= 8) {
		memcpy(&buf[off], dst_addr, dst_addr_len);
		off += dst_addr_len;
	}

	size_t copy_len = (inner_len < (sizeof(buf) - off)) ?
			  inner_len : (sizeof(buf) - off);
	memcpy(&buf[off], payload, copy_len);
	off += copy_len;

	return schnorr48_verify(pubkey, buf, off, sig);
}
