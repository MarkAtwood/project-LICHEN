/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_link_tx.c
 * @brief LICHEN frame TX path
 *
 * Takes an IPv6 packet, compresses with SCHC, builds a LICHEN frame with
 * optional Schnorr-48 signature, and outputs the wire-ready frame.
 */

#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/schc.h>
#include <lichen/schnorr48.h>
#include <string.h>

/* Error codes */
#ifdef __ZEPHYR__
#include <errno.h>
#else
#define EINVAL 22
#define ENOMEM 12
#define EMSGSIZE 90
#endif

/* CRC32 polynomial (IEEE 802.3) */
#define CRC32_POLY 0xEDB88320

/**
 * @brief Simple CRC32 computation (placeholder for AES-CCM MIC).
 *
 * Uses the IEEE 802.3 polynomial with bit-reflected algorithm.
 */
static uint32_t crc32(const uint8_t *data, size_t len)
{
	uint32_t crc = 0xFFFFFFFF;

	for (size_t i = 0; i < len; i++) {
		crc ^= data[i];
		for (int j = 0; j < 8; j++) {
			if (crc & 1) {
				crc = (crc >> 1) ^ CRC32_POLY;
			} else {
				crc >>= 1;
			}
		}
	}

	return ~crc;
}

int lichen_link_tx(struct lichen_link_ctx *ctx,
		   const uint8_t *ipv6_pkt, size_t ipv6_len,
		   const uint8_t *dst_eui64,
		   uint8_t *out_frame, size_t *out_len)
{
	uint8_t compressed[256];
	uint8_t payload_buf[256];
	int compressed_len;
	size_t payload_len;
	uint8_t addr_mode;
	uint8_t dst_addr[8];
	uint8_t dst_addr_len;
	uint16_t seqnum;
	size_t off;
	size_t frame_body_len;
	uint32_t mic;

	if (ctx == NULL || ipv6_pkt == NULL || out_frame == NULL || out_len == NULL) {
		return -EINVAL;
	}

	if (*out_len < 16) {
		return -ENOMEM;
	}

	/* Step 1: Compress IPv6 packet with SCHC */
	compressed_len = lichen_schc_compress(ipv6_pkt, ipv6_len,
					      compressed, sizeof(compressed));
	if (compressed_len < 0) {
		return compressed_len;
	}

	/* Determine address mode and destination */
	if (dst_eui64 != NULL) {
		addr_mode = LICHEN_ADDR_EUI64;
		memcpy(dst_addr, dst_eui64, 8);
		dst_addr_len = 8;
	} else {
		addr_mode = LICHEN_ADDR_BROADCAST;
		dst_addr_len = 0;
	}

	/* Get next sequence number using the link context API */
	seqnum = lichen_link_next_seq(ctx);

	/* Step 2: If signing enabled (has_key set), compute Schnorr-48 signature */
	if (ctx->has_key) {
		/* Signature is appended to the compressed payload */
		if ((size_t)compressed_len + SCHNORR48_SIG_LEN > sizeof(payload_buf)) {
			return -EMSGSIZE;
		}

		memcpy(payload_buf, compressed, compressed_len);

		schnorr48_sign_frame(ctx->epoch, seqnum,
				     dst_addr, dst_addr_len,
				     compressed, compressed_len,
				     ctx->ed25519_sk, ctx->ed25519_pk,
				     &payload_buf[compressed_len]);

		payload_len = compressed_len + SCHNORR48_SIG_LEN;
	} else {
		/* No signature */
		if ((size_t)compressed_len > sizeof(payload_buf)) {
			return -EMSGSIZE;
		}
		memcpy(payload_buf, compressed, compressed_len);
		payload_len = compressed_len;
	}

	/* Calculate frame body length (everything after the length byte):
	 * LLSec(1) + Epoch(1) + SeqNum(2) + DstAddr(0/2/8) + Payload + MIC(4)
	 */
	frame_body_len = 1 + 1 + 2 + dst_addr_len + payload_len + 4;

	if (frame_body_len > 255) {
		return -EMSGSIZE;
	}

	/* Total frame = length byte + body */
	if (1 + frame_body_len > *out_len) {
		return -ENOMEM;
	}

	/* Step 3: Build frame header */
	off = 0;

	/* Length byte (body length, excludes itself) */
	out_frame[off++] = (uint8_t)frame_body_len;

	/* LLSec byte:
	 * bits 0-1: AddrMode
	 * bits 2-4: MicLength (0 = 32-bit)
	 * bit 5: signature present
	 * bit 6: encrypted (0 for now)
	 * bit 7: reserved (0)
	 */
	out_frame[off] = addr_mode & 0x03;
	/* MIC length is always 32-bit for now (bit 2 = 0) */
	if (ctx->has_key) {
		out_frame[off] |= 0x20; /* signature present */
	}
	off++;

	/* Epoch */
	out_frame[off++] = ctx->epoch;

	/* Sequence number (big-endian) */
	out_frame[off++] = (uint8_t)(seqnum >> 8);
	out_frame[off++] = (uint8_t)(seqnum & 0xFF);

	/* Destination address */
	if (dst_addr_len > 0) {
		memcpy(&out_frame[off], dst_addr, dst_addr_len);
		off += dst_addr_len;
	}

	/* Step 4: Append payload (includes signature if present) */
	memcpy(&out_frame[off], payload_buf, payload_len);
	off += payload_len;

	/* Step 5: Compute MIC over entire frame body (excluding MIC itself)
	 * MIC covers: LLSec || Epoch || SeqNum || DstAddr || Payload
	 * Using CRC32 as placeholder for AES-CCM
	 */
	mic = crc32(&out_frame[1], off - 1);

	/* Append 32-bit MIC (little-endian per CRC32 convention) */
	out_frame[off++] = (uint8_t)(mic & 0xFF);
	out_frame[off++] = (uint8_t)((mic >> 8) & 0xFF);
	out_frame[off++] = (uint8_t)((mic >> 16) & 0xFF);
	out_frame[off++] = (uint8_t)((mic >> 24) & 0xFF);

	*out_len = off;
	return 0;
}
