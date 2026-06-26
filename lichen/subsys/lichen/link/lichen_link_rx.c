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
#include <lichen/replay.h>
#include <lichen/schnorr48.h>
#include <lichen/schc.h>
#include <string.h>
#include <stdint.h>

/* Error codes */
#ifdef __ZEPHYR__
#include <errno.h>
#else
#define EINVAL   22
#define ENOMEM   12
#define EALREADY 114
#endif

/* EAUTH is not standard - define if missing */
#ifndef EAUTH
#define EAUTH 80
#endif

/* Replay table functions are in replay.c */

/* ─── MIC verification stub ───────────────────────────────────────────────── */

/**
 * Verify the frame MIC.
 *
 * NOTE: This is a stub implementation. Real MIC verification requires:
 * - Link-layer key derivation from the security context
 * - AES-CCM computation over (LLSec || epoch || seqnum || dst_addr || payload)
 *
 * For now, we accept any MIC. Enable CONFIG_LICHEN_LINK_MIC_VERIFY
 * when AES-CCM integration is complete.
 */
static int verify_mic(const struct lichen_link_rx_ctx *ctx,
		      const struct lichen_frame *frame,
		      const uint8_t *raw_frame, size_t raw_len)
{
	(void)ctx;
	(void)frame;
	(void)raw_frame;
	(void)raw_len;

#ifdef CONFIG_LICHEN_LINK_MIC_VERIFY
	/* TODO: Implement AES-CCM MIC verification */
	/* 1. Build AAD: length || LLSec || epoch || seqnum || dst_addr */
	/* 2. Compute expected MIC using link-layer key */
	/* 3. Compare with frame->mic using constant-time comparison */
	return -EAUTH;
#else
	/* Accept without verification during development */
	return 0;
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

		if (parsed.payload_len < SCHNORR48_SIG_LEN) {
			/* Payload too short to contain signature */
			return -EINVAL;
		}

		/*
		 * schnorr48_verify_frame expects:
		 * - Full payload including signature
		 * - It extracts inner payload and signature internally
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
	 * If signature was present, the actual SCHC data is the payload
	 * minus the trailing 48-byte signature.
	 */
	const uint8_t *schc_data;
	size_t schc_len;

	if (parsed.signature_present) {
		schc_data = parsed.payload;
		schc_len = parsed.payload_len - SCHNORR48_SIG_LEN;
	} else {
		schc_data = parsed.payload;
		schc_len = parsed.payload_len;
	}

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
