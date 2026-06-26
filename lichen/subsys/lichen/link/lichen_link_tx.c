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

/* AES-CCM for link-layer MIC */
#include "oscore/aes_ccm.h"

/**
 * @brief CRC32 lookup table (IEEE 802.3 polynomial, bit-reflected).
 *
 * Generated from polynomial 0xEDB88320. Table-driven CRC runs in O(n) with
 * one lookup per byte, vs O(8n) for bit-by-bit computation.
 */
static const uint32_t crc32_table[256] = {
	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
	0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
	0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
	0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
	0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
	0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	0x35B5A8FA, 0x42B2986C, 0xDBBBCBD6, 0xACBCFBC0,
	0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
	0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
	0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
	0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
	0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
	0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
	0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
	0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
	0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
	0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7C89,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
	0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E03F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
	0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
	0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
	0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
	0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
	0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
	0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
	0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
	0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
	0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
	0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
	0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
	0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
	0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
	0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
	0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
	0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
	0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
	0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};

/**
 * @brief Table-driven CRC32 computation (fallback when no link key).
 *
 * Uses the IEEE 802.3 polynomial with bit-reflected algorithm.
 * One lookup per byte: O(n) vs O(8n) for bit-by-bit.
 */
static uint32_t crc32(const uint8_t *data, size_t len)
{
	uint32_t crc = 0xFFFFFFFF;

	for (size_t i = 0; i < len; i++) {
		crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
	}

	return ~crc;
}

/**
 * @brief Build AES-CCM nonce for link-layer MIC.
 *
 * Nonce format (13 bytes):
 *   - eui64[8]: sender's EUI-64
 *   - epoch[1]: current epoch
 *   - seqnum[2]: sequence number (big-endian)
 *   - reserved[2]: 0x00 padding
 */
static void build_link_nonce(uint8_t nonce[AES_CCM_NONCE_LEN],
			     const uint8_t eui64[8],
			     uint8_t epoch,
			     uint16_t seqnum)
{
	memcpy(&nonce[0], eui64, 8);
	nonce[8] = epoch;
	nonce[9] = (uint8_t)(seqnum >> 8);
	nonce[10] = (uint8_t)(seqnum & 0xFF);
	nonce[11] = 0x00;
	nonce[12] = 0x00;
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
	uint8_t mic_len;

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

	/* MIC length: 8 bytes for AES-CCM-64, 4 bytes for CRC32 fallback */
	mic_len = ctx->has_link_key ? 8 : 4;

	/* Calculate frame body length (everything after the length byte):
	 * LLSec(1) + Epoch(1) + SeqNum(2) + DstAddr(0/2/8) + Payload + MIC(4/8)
	 */
	frame_body_len = 1 + 1 + 2 + dst_addr_len + payload_len + mic_len;

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
	 * bit 2: MicLength (0 = 32-bit, 1 = 64-bit)
	 * bit 5: signature present
	 * bit 6: encrypted (0 for now)
	 * bit 7: reserved (0)
	 */
	out_frame[off] = addr_mode & 0x03;
	if (ctx->has_link_key) {
		out_frame[off] |= 0x04; /* 64-bit MIC */
	}
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

	/* Step 5: Compute MIC over frame body (excluding MIC itself) */
	if (ctx->has_link_key) {
		/*
		 * AES-CCM-64 MIC
		 *
		 * AAD = length || LLSec || epoch || seqnum || dst_addr
		 * The payload is empty (no encryption), we just compute the tag.
		 * Nonce = eui64 || epoch || seqnum || 0x0000
		 */
		uint8_t nonce[AES_CCM_NONCE_LEN];
		uint8_t mic_out[AES_CCM_TAG_LEN];
		size_t aad_len = off;  /* Everything built so far is AAD */

		build_link_nonce(nonce, ctx->eui64, ctx->epoch, seqnum);

		/* AES-CCM encrypt with empty plaintext to get just the tag */
		if (lichen_aes_ccm_encrypt(ctx->link_key, nonce,
					   &out_frame[0], aad_len,
					   NULL, 0,
					   mic_out) != 0) {
			return -EINVAL;
		}

		/* Append 64-bit MIC */
		memcpy(&out_frame[off], mic_out, AES_CCM_TAG_LEN);
		off += AES_CCM_TAG_LEN;
	} else {
		/* CRC32 fallback (no link key configured) */
		uint32_t mic = crc32(&out_frame[1], off - 1);

		/* Append 32-bit MIC (little-endian per CRC32 convention) */
		out_frame[off++] = (uint8_t)(mic & 0xFF);
		out_frame[off++] = (uint8_t)((mic >> 8) & 0xFF);
		out_frame[off++] = (uint8_t)((mic >> 16) & 0xFF);
		out_frame[off++] = (uint8_t)((mic >> 24) & 0xFF);
	}

	*out_len = off;
	return 0;
}
