/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file frame.c
 * @brief LICHEN frame parsing and serialization
 */

#include <lichen/link.h>
#include <string.h>

/* LLSec byte bit positions */
#define LLSEC_ADDR_MODE_MASK  0x03
#define LLSEC_MIC_LEN_SHIFT   2
#define LLSEC_MIC_LEN_MASK    0x04
#define LLSEC_SIG_PRESENT     0x20
#define LLSEC_ENCRYPTED       0x40
#define LLSEC_RESERVED        0x80

/* Address lengths by mode */
static const uint8_t addr_lens[] = { 0, 2, 8, 0 };

int lichen_frame_parse(struct lichen_frame *frame,
		       const uint8_t *data, size_t len)
{
	if (len < 5) {
		/* Minimum: length(1) + llsec(1) + epoch(1) + seqnum(2) */
		return -1;
	}

	size_t off = 0;
	uint8_t frame_len = data[off++];

	if (frame_len != len - 1) {
		return -2; /* Length mismatch */
	}

	uint8_t llsec = data[off++];

	if (llsec & LLSEC_RESERVED) {
		return -3; /* Reserved bit set */
	}

	frame->addr_mode = llsec & LLSEC_ADDR_MODE_MASK;
	frame->mic_length = (llsec & LLSEC_MIC_LEN_MASK) ? LICHEN_MIC_64 : LICHEN_MIC_32;
	frame->signature_present = (llsec & LLSEC_SIG_PRESENT) != 0;
	frame->encrypted = (llsec & LLSEC_ENCRYPTED) != 0;

	frame->epoch = data[off++];
	frame->seqnum = ((uint16_t)data[off] << 8) | data[off + 1];
	off += 2;

	/* Destination address */
	frame->dst_addr_len = addr_lens[frame->addr_mode];
	if (off + frame->dst_addr_len > len) {
		return -4; /* Truncated address */
	}
	memcpy(frame->dst_addr, &data[off], frame->dst_addr_len);
	off += frame->dst_addr_len;

	/* MIC at the end */
	frame->mic_len = (frame->mic_length == LICHEN_MIC_64) ? 8 : 4;
	if (off + frame->mic_len > len) {
		return -5; /* Truncated MIC */
	}
	memcpy(frame->mic, &data[len - frame->mic_len], frame->mic_len);

	/* Payload is everything between address and MIC */
	frame->payload = &data[off];
	frame->payload_len = len - off - frame->mic_len;

	return 0;
}

int lichen_frame_write(const struct lichen_frame *frame,
		       uint8_t *buf, size_t buflen)
{
	uint8_t addr_len = addr_lens[frame->addr_mode];
	uint8_t mic_len = (frame->mic_length == LICHEN_MIC_64) ? 8 : 4;

	/* Calculate total frame size */
	size_t frame_len = 1 + 1 + 1 + 2 + addr_len + frame->payload_len + mic_len;

	if (frame_len > buflen || frame_len > 256) {
		return -1; /* Buffer too small or frame too large */
	}

	size_t off = 0;

	/* Length byte (excludes itself) */
	buf[off++] = (uint8_t)(frame_len - 1);

	/* LLSec byte */
	uint8_t llsec = frame->addr_mode & LLSEC_ADDR_MODE_MASK;
	if (frame->mic_length == LICHEN_MIC_64) {
		llsec |= LLSEC_MIC_LEN_MASK;
	}
	if (frame->signature_present) {
		llsec |= LLSEC_SIG_PRESENT;
	}
	if (frame->encrypted) {
		llsec |= LLSEC_ENCRYPTED;
	}
	buf[off++] = llsec;

	/* Epoch */
	buf[off++] = frame->epoch;

	/* Sequence number (big-endian) */
	buf[off++] = (uint8_t)(frame->seqnum >> 8);
	buf[off++] = (uint8_t)(frame->seqnum & 0xFF);

	/* Destination address */
	memcpy(&buf[off], frame->dst_addr, addr_len);
	off += addr_len;

	/* Payload */
	memcpy(&buf[off], frame->payload, frame->payload_len);
	off += frame->payload_len;

	/* MIC */
	memcpy(&buf[off], frame->mic, mic_len);
	off += mic_len;

	return (int)off;
}
