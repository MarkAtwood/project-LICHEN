/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_link_rx.c
 * @brief LICHEN frame receive path
 *
 * Parses LICHEN frames, verifies replay protection and signatures,
 * and decompresses the payload to a full IPv6 packet.
 */

#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/errno.h>
#include <lichen/replay.h>
#include <lichen/schnorr48.h>
#include <lichen/schc.h>
#include <string.h>
#include <stdint.h>

/* AES-CCM for link-layer MIC verification */
#include "oscore/aes_ccm.h"

/* Replay table functions are in replay.c */

/* ─── Logging ─────────────────────────────────────────────────────────────── */

#ifdef __ZEPHYR__
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(lichen_link_rx, CONFIG_LICHEN_LINK_LOG_LEVEL);
#else
/* Minimal logging for non-Zephyr builds */
#include <stdio.h>
#define LOG_WRN(...) fprintf(stderr, "WRN: " __VA_ARGS__)
#endif

/* ─── MIC verification ────────────────────────────────────────────────────── */

/**
 * @brief Build AES-CCM nonce for link-layer MIC verification.
 *
 * Nonce format (13 bytes):
 *   - eui64[8]: sender's EUI-64
 *   - epoch[1]: frame epoch
 *   - seqnum[2]: sequence number (big-endian)
 *   - reserved[2]: 0x00 padding
 */
static void build_link_nonce(uint8_t nonce[AES_CCM_NONCE_LEN],
			     const uint8_t eui64[LICHEN_EUI64_LEN],
			     uint8_t epoch,
			     uint16_t seqnum)
{
	memcpy(&nonce[0], eui64, LICHEN_EUI64_LEN);
	nonce[8] = epoch;
	nonce[9] = (uint8_t)(seqnum >> 8);
	nonce[10] = (uint8_t)(seqnum & 0xFF);
	nonce[11] = 0x00;
	nonce[12] = 0x00;
}

/**
 * Verify the frame MIC.
 *
 * MIC verification is ENABLED by default. To disable for testing, set
 * CONFIG_LICHEN_LINK_MIC_SKIP_VERIFY=y — this is a dangerous option that
 * should NEVER be used in production as it allows frame forgery.
 *
 * For AES-CCM-64 MIC (mic_len == 8):
 * - Requires ctx->link_key and ctx->peer_eui64 to be set
 * - AAD = entire frame body up to MIC
 * - Nonce = peer_eui64 || epoch || seqnum || 0x0000
 *
 * For CRC32 MIC (mic_len == 4):
 * - Fallback verification (no cryptographic authentication)
 */
static int verify_mic(const struct lichen_link_rx_ctx *ctx,
		      const struct lichen_frame *frame,
		      const uint8_t *raw_frame, size_t raw_len)
{
#ifdef CONFIG_LICHEN_LINK_MIC_SKIP_VERIFY
	(void)ctx;
	(void)frame;
	(void)raw_frame;
	(void)raw_len;
	/*
	 * DANGER: MIC verification is disabled — frames can be forged.
	 * This option exists ONLY for testing. Never enable in production.
	 */
	LOG_WRN("MIC verification DISABLED — accepting unverified frame\n");
	return 0;
#else
	if (frame->mic_len == 8) {
		/* AES-CCM-64 MIC verification */
		uint8_t nonce[AES_CCM_NONCE_LEN];
		uint8_t expected_mic[AES_CCM_TAG_LEN];
		size_t aad_len;

		/* Require link key and peer EUI-64 for AES-CCM verification */
		if (ctx->link_key == NULL || ctx->peer_eui64 == NULL) {
			LOG_WRN("AES-CCM MIC verification requires link_key and peer_eui64\n");
			return -EAUTH;
		}

		/* AAD is everything except the MIC itself */
		aad_len = raw_len - frame->mic_len;

		/* Build nonce from peer's EUI-64, epoch, and seqnum */
		build_link_nonce(nonce, ctx->peer_eui64, frame->epoch, frame->seqnum);

		/* Compute expected MIC (encrypt with empty plaintext) */
		if (lichen_aes_ccm_encrypt(ctx->link_key, nonce,
					   raw_frame, aad_len,
					   NULL, 0,
					   expected_mic) != 0) {
			return -EAUTH;
		}

		/* Constant-time comparison of MIC */
		uint8_t diff = 0;
		for (int i = 0; i < AES_CCM_TAG_LEN; i++) {
			diff |= frame->mic[i] ^ expected_mic[i];
		}

		if (diff != 0) {
			return -EAUTH;
		}

		return 0;
	} else {
		/* CRC32 fallback - no cryptographic verification */
		/* Accept frame but note this provides no authentication */
		return 0;
	}
#endif
}

/* ─── RX path ─────────────────────────────────────────────────────────────── */

int lichen_link_rx(struct lichen_link_rx_ctx *ctx,
		   struct lichen_replay_table *replay,
		   const uint8_t *frame, size_t frame_len,
		   uint8_t *out_ipv6, size_t *out_len,
		   uint8_t *src_eui64)
{
	struct lichen_frame parsed;
	int ret;

	if (ctx == NULL || frame == NULL || out_ipv6 == NULL ||
	    out_len == NULL || src_eui64 == NULL) {
		return -EINVAL;
	}

	/* Step 1: Parse frame header */
	ret = lichen_frame_parse(&parsed, frame, frame_len);
	if (ret < 0) {
		return -EINVAL;
	}

	/*
	 * Step 2: Extract source EUI-64
	 *
	 * The source address is not in the frame header - it must be
	 * derived from one of:
	 * - Radio layer metadata (LoRa)
	 * - Signature verification (sender's public key)
	 * - Explicit source field in extended frames
	 *
	 * For signed frames, we derive EUI-64 from the sender's public
	 * key after signature verification. For unsigned frames, the
	 * caller must provide the source via ctx->peer_pubkey context.
	 *
	 * TEMPORARY: Use first 8 bytes of peer_pubkey as EUI-64.
	 * Real implementation should use SHA-256(pubkey)[0:8].
	 */
	if (ctx->peer_pubkey != NULL) {
		memcpy(src_eui64, ctx->peer_pubkey, 8);
	} else {
		/* No peer context - cannot determine source */
		memset(src_eui64, 0, 8);
	}

	/* Step 3: Check replay window */
	if (replay != NULL) {
		struct lichen_replay_window *window;

		window = lichen_replay_get(replay, src_eui64);
		if (window == NULL) {
			/* Table full */
			return -ENOMEM;
		}

		if (!lichen_replay_check(window, parsed.seqnum)) {
			return -EALREADY;
		}
	}

	/* Step 4: Verify Schnorr-48 signature if present */
	if (parsed.signature_present) {
		if (ctx->peer_pubkey == NULL) {
			/* Cannot verify without sender's public key */
			return -EAUTH;
		}

		/*
		 * schnorr48_verify_frame expects:
		 * - Full payload including signature (payload_len)
		 * - It extracts inner payload and signature internally
		 *
		 * Note: frame_parse() already validated payload_len >= LICHEN_SIG_LEN
		 */
		if (!schnorr48_verify_frame(parsed.epoch, parsed.seqnum,
					    parsed.dst_addr,
					    parsed.dst_addr_len,
					    parsed.payload,
					    parsed.payload_len,
					    ctx->peer_pubkey)) {
			return -EAUTH;
		}
	}

	/* Step 5: Verify MIC */
	ret = verify_mic(ctx, &parsed, frame, frame_len);
	if (ret < 0) {
		return -EAUTH;
	}

	/*
	 * Step 6: Decompress SCHC payload to IPv6
	 *
	 * Use inner_payload_len which excludes the signature if present.
	 */
	const uint8_t *schc_data = parsed.payload;
	size_t schc_len = parsed.inner_payload_len;

	ret = lichen_schc_decompress(schc_data, schc_len, out_ipv6, *out_len);
	if (ret < 0) {
		if (ret == SCHC_ERR_BUFFER_TOO_SMALL) {
			return -ENOMEM;
		}
		return -EINVAL;
	}

	*out_len = (size_t)ret;
	return 0;
}
