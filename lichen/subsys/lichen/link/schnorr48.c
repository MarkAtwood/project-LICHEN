/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schnorr48.c
 * @brief Schnorr-48 signatures per draft-lichen-schnorr-00
 *
 * 48-byte deterministic Schnorr signatures over Ed25519:
 *   16-byte truncated challenge (e) || 32-byte response (s)
 *
 * Uses Monocypher for Ed25519 primitives and SHA-512.
 * Test vectors: test/vectors/schnorr48.json
 * Reference impl: python/src/lichen/crypto/schnorr48.py
 */

#include <lichen/schnorr48.h>
#include <string.h>
#include <stdbool.h>

/* ─── Logging ─────────────────────────────────────────────────────────────── */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(schnorr48, CONFIG_LICHEN_LINK_LOG_LEVEL);
#else
/* Minimal logging for non-Zephyr builds */
#include <stdio.h>
#define LOG_WRN(...) fprintf(stderr, "WRN: " __VA_ARGS__)
#endif

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
#include "monocypher.h"
#include "monocypher-ed25519.h"

/**
 * @brief Apply Ed25519 clamping to a scalar.
 *
 * Clears bits 0-2, sets bit 254, clears bit 255.
 */
static void clamp_scalar(uint8_t s[32])
{
	s[0] &= 248;
	s[31] &= 127;
	s[31] |= 64;
}

void schnorr48_derive_keypair(const uint8_t seed[32],
			      uint8_t privkey[32],
			      uint8_t pubkey[32])
{
	uint8_t hash[64];

	/* h = SHA-512(seed) */
	crypto_sha512(hash, seed, 32);

	/* privkey = clamp(h[0:32]) */
	memcpy(privkey, hash, 32);
	clamp_scalar(privkey);

	/* pubkey = privkey * B */
	crypto_eddsa_scalarbase(pubkey, privkey);

	/* Wipe sensitive data */
	crypto_wipe(hash, sizeof(hash));
}

void schnorr48_sign(const uint8_t privkey[32],
		    const uint8_t pubkey[32],
		    const uint8_t *msg, size_t msg_len,
		    uint8_t sig[48])
{
	uint8_t nonce_hash[64];
	uint8_t r_scalar[32];
	uint8_t R[32];
	uint8_t e_hash[64];
	uint8_t e_extended[32];
	crypto_sha512_ctx ctx;

	/*
	 * 1. Deterministic nonce: r = SHA-512(privkey || msg) mod L
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, privkey, 32);
	crypto_sha512_update(&ctx, msg, msg_len);
	crypto_sha512_final(&ctx, nonce_hash);

	/* Reduce 64-byte hash to scalar mod L */
	crypto_eddsa_reduce(r_scalar, nonce_hash);

	/*
	 * 2. Commitment: R = r * B
	 */
	crypto_eddsa_scalarbase(R, r_scalar);

	/*
	 * 3. Challenge: e = SHA-512(R || pubkey || msg)[0:16]
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, R, 32);
	crypto_sha512_update(&ctx, pubkey, 32);
	crypto_sha512_update(&ctx, msg, msg_len);
	crypto_sha512_final(&ctx, e_hash);

	/* Copy truncated challenge to signature */
	memcpy(sig, e_hash, 16);

	/*
	 * 4. e_extended = e || 0x00*16 (32-byte scalar)
	 */
	memcpy(e_extended, e_hash, 16);
	memset(e_extended + 16, 0, 16);

	/*
	 * 5. s = (r + e_extended * privkey) mod L
	 *    Using crypto_eddsa_mul_add: r + a*b = r + e*priv
	 */
	crypto_eddsa_mul_add(sig + 16, e_extended, privkey, r_scalar);

	/* Wipe sensitive data */
	crypto_wipe(nonce_hash, sizeof(nonce_hash));
	crypto_wipe(r_scalar, sizeof(r_scalar));
	crypto_wipe(R, sizeof(R));
	crypto_wipe(e_hash, sizeof(e_hash));
	crypto_wipe(e_extended, sizeof(e_extended));
	crypto_wipe(&ctx, sizeof(ctx));
}

bool schnorr48_verify(const uint8_t pubkey[32],
		      const uint8_t *msg, size_t msg_len,
		      const uint8_t sig[48])
{
	const uint8_t *e_received = sig;
	const uint8_t *s = sig + 16;
	uint8_t e_extended[32];
	uint8_t R_prime[32];
	uint8_t e_hash[64];
	crypto_sha512_ctx ctx;

	/*
	 * 1. Check s is non-zero
	 */
	uint8_t s_is_zero = 0;
	for (int i = 0; i < 32; i++) {
		s_is_zero |= s[i];
	}
	if (s_is_zero == 0) {
		return false;
	}

	/*
	 * 2. e_extended = e_received || 0x00*16
	 */
	memcpy(e_extended, e_received, 16);
	memset(e_extended + 16, 0, 16);

	/*
	 * 3. R' = s*B - e_extended*pubkey
	 *    Returns -1 if pubkey is invalid or s >= L
	 */
	if (crypto_eddsa_recover_r(R_prime, pubkey, s, e_extended) != 0) {
		return false;
	}

	/*
	 * 4. e' = SHA-512(R' || pubkey || msg)[0:16]
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, R_prime, 32);
	crypto_sha512_update(&ctx, pubkey, 32);
	crypto_sha512_update(&ctx, msg, msg_len);
	crypto_sha512_final(&ctx, e_hash);

	/*
	 * 5. Constant-time comparison of e' and e_received
	 */
	return crypto_verify16(e_hash, e_received) == 0;
}

#else /* !CONFIG_LICHEN_CRYPTO_MONOCYPHER */

/*
 * Stub implementation for builds without Monocypher.
 * Returns fixed patterns for development; NOT FOR PRODUCTION.
 */
#ifdef CONFIG_LICHEN_LINK_SCHNORR
#warning "Using stub Schnorr-48 implementation - NOT FOR PRODUCTION"
#endif

/* Runtime warning flag - warn once per function */
static bool stub_warned_keypair = false;
static bool stub_warned_sign = false;
static bool stub_warned_verify = false;

void schnorr48_derive_keypair(const uint8_t seed[32],
			      uint8_t privkey[32],
			      uint8_t pubkey[32])
{
	if (!stub_warned_keypair) {
		LOG_WRN("INSECURE: using stub schnorr48_derive_keypair - NOT FOR PRODUCTION\n");
		stub_warned_keypair = true;
	}
	memcpy(privkey, seed, 32);
	memset(pubkey, 0, 32);
	pubkey[0] = 0x01;
}

void schnorr48_sign(const uint8_t privkey[32],
		    const uint8_t pubkey[32],
		    const uint8_t *msg, size_t msg_len,
		    uint8_t sig[48])
{
	if (!stub_warned_sign) {
		LOG_WRN("INSECURE: using stub schnorr48_sign - NOT FOR PRODUCTION\n");
		stub_warned_sign = true;
	}
	(void)privkey;
	(void)pubkey;
	(void)msg;
	(void)msg_len;
	memset(sig, 0, 48);
}

bool schnorr48_verify(const uint8_t pubkey[32],
		      const uint8_t *msg, size_t msg_len,
		      const uint8_t sig[48])
{
	if (!stub_warned_verify) {
		LOG_WRN("INSECURE: using stub schnorr48_verify - NOT FOR PRODUCTION\n");
		stub_warned_verify = true;
	}
	(void)pubkey;
	(void)msg;
	(void)msg_len;
	(void)sig;
	return false;
}

#endif /* CONFIG_LICHEN_CRYPTO_MONOCYPHER */

/*
 * Frame helpers - real implementation uses SHA-512 streaming to avoid
 * fixed-size buffers and handle arbitrary payload lengths.
 */
#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER

void schnorr48_sign_frame(uint8_t epoch, uint16_t seqnum,
			  const uint8_t *dst_addr, size_t dst_addr_len,
			  const uint8_t *payload, size_t payload_len,
			  const uint8_t privkey[32],
			  const uint8_t pubkey[32],
			  uint8_t sig[48])
{
	uint8_t header[11]; /* epoch(1) + seqnum(2) + dst_addr(up to 8) */
	size_t header_len = 0;
	uint8_t nonce_hash[64];
	uint8_t r_scalar[32];
	uint8_t R[32];
	uint8_t e_hash[64];
	uint8_t e_extended[32];
	crypto_sha512_ctx ctx;

	/* Build header: epoch || seqnum (big-endian) || dst_addr */
	header[header_len++] = epoch;
	header[header_len++] = (uint8_t)(seqnum >> 8);
	header[header_len++] = (uint8_t)(seqnum & 0xFF);
	if (dst_addr_len > 0 && dst_addr_len <= 8) {
		memcpy(&header[header_len], dst_addr, dst_addr_len);
		header_len += dst_addr_len;
	}

	/*
	 * 1. Deterministic nonce: r = SHA-512(privkey || header || payload) mod L
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, privkey, 32);
	crypto_sha512_update(&ctx, header, header_len);
	crypto_sha512_update(&ctx, payload, payload_len);
	crypto_sha512_final(&ctx, nonce_hash);
	crypto_eddsa_reduce(r_scalar, nonce_hash);

	/*
	 * 2. Commitment: R = r * B
	 */
	crypto_eddsa_scalarbase(R, r_scalar);

	/*
	 * 3. Challenge: e = SHA-512(R || pubkey || header || payload)[0:16]
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, R, 32);
	crypto_sha512_update(&ctx, pubkey, 32);
	crypto_sha512_update(&ctx, header, header_len);
	crypto_sha512_update(&ctx, payload, payload_len);
	crypto_sha512_final(&ctx, e_hash);

	/* Copy truncated challenge to signature */
	memcpy(sig, e_hash, 16);

	/*
	 * 4. e_extended = e || 0x00*16 (32-byte scalar)
	 */
	memcpy(e_extended, e_hash, 16);
	memset(e_extended + 16, 0, 16);

	/*
	 * 5. s = (r + e_extended * privkey) mod L
	 */
	crypto_eddsa_mul_add(sig + 16, e_extended, privkey, r_scalar);

	/* Wipe sensitive data */
	crypto_wipe(nonce_hash, sizeof(nonce_hash));
	crypto_wipe(r_scalar, sizeof(r_scalar));
	crypto_wipe(R, sizeof(R));
	crypto_wipe(e_hash, sizeof(e_hash));
	crypto_wipe(e_extended, sizeof(e_extended));
	crypto_wipe(&ctx, sizeof(ctx));
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
	const uint8_t *e_received = sig;
	const uint8_t *s = sig + 16;

	uint8_t header[11]; /* epoch(1) + seqnum(2) + dst_addr(up to 8) */
	size_t header_len = 0;
	uint8_t e_extended[32];
	uint8_t R_prime[32];
	uint8_t e_hash[64];
	crypto_sha512_ctx ctx;

	/* Build header: epoch || seqnum (big-endian) || dst_addr */
	header[header_len++] = epoch;
	header[header_len++] = (uint8_t)(seqnum >> 8);
	header[header_len++] = (uint8_t)(seqnum & 0xFF);
	if (dst_addr_len > 0 && dst_addr_len <= 8) {
		memcpy(&header[header_len], dst_addr, dst_addr_len);
		header_len += dst_addr_len;
	}

	/*
	 * 1. Check s is non-zero
	 */
	uint8_t s_is_zero = 0;
	for (int i = 0; i < 32; i++) {
		s_is_zero |= s[i];
	}
	if (s_is_zero == 0) {
		return false;
	}

	/*
	 * 2. e_extended = e_received || 0x00*16
	 */
	memcpy(e_extended, e_received, 16);
	memset(e_extended + 16, 0, 16);

	/*
	 * 3. R' = s*B - e_extended*pubkey
	 */
	if (crypto_eddsa_recover_r(R_prime, pubkey, s, e_extended) != 0) {
		return false;
	}

	/*
	 * 4. e' = SHA-512(R' || pubkey || header || payload)[0:16]
	 */
	crypto_sha512_init(&ctx);
	crypto_sha512_update(&ctx, R_prime, 32);
	crypto_sha512_update(&ctx, pubkey, 32);
	crypto_sha512_update(&ctx, header, header_len);
	crypto_sha512_update(&ctx, payload, inner_len);
	crypto_sha512_final(&ctx, e_hash);

	/*
	 * 5. Constant-time comparison of e' and e_received
	 */
	return crypto_verify16(e_hash, e_received) == 0;
}

#else /* !CONFIG_LICHEN_CRYPTO_MONOCYPHER */

/* Runtime warning flags for frame helpers */
static bool stub_warned_sign_frame = false;
static bool stub_warned_verify_frame = false;

void schnorr48_sign_frame(uint8_t epoch, uint16_t seqnum,
			  const uint8_t *dst_addr, size_t dst_addr_len,
			  const uint8_t *payload, size_t payload_len,
			  const uint8_t privkey[32],
			  const uint8_t pubkey[32],
			  uint8_t sig[48])
{
	if (!stub_warned_sign_frame) {
		LOG_WRN("INSECURE: using stub schnorr48_sign_frame - NOT FOR PRODUCTION\n");
		stub_warned_sign_frame = true;
	}
	(void)epoch;
	(void)seqnum;
	(void)dst_addr;
	(void)dst_addr_len;
	(void)payload;
	(void)payload_len;
	(void)privkey;
	(void)pubkey;
	memset(sig, 0, 48);
}

bool schnorr48_verify_frame(uint8_t epoch, uint16_t seqnum,
			    const uint8_t *dst_addr, size_t dst_addr_len,
			    const uint8_t *payload, size_t payload_len,
			    const uint8_t pubkey[32])
{
	if (!stub_warned_verify_frame) {
		LOG_WRN("INSECURE: using stub schnorr48_verify_frame - NOT FOR PRODUCTION\n");
		stub_warned_verify_frame = true;
	}
	(void)epoch;
	(void)seqnum;
	(void)dst_addr;
	(void)dst_addr_len;
	(void)payload;
	(void)payload_len;
	(void)pubkey;
	return false;
}

#endif /* CONFIG_LICHEN_CRYPTO_MONOCYPHER */
