/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/link.h
 * @brief LICHEN link layer API
 *
 * Implements the LICHEN frame format with LLSec flags, replay-window tracking,
 * and Schnorr-48 link signatures per spec section 4.
 *
 * Wire layout:
 *   +--------+--------+-------+--------+----------+---------+-------+
 *   | Length | LLSec  | Epoch | SeqNum | Dst Addr | Payload |  MIC  |
 *   +--------+--------+-------+--------+----------+---------+-------+
 *      1B       1B       1B      2B       0/2/8B     var      4/8B
 */

#ifndef LICHEN_LINK_H_
#define LICHEN_LINK_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum LICHEN frame payload size (LoRa SF10 255B - overhead) */
#define LICHEN_MAX_PAYLOAD 200

/** Schnorr-48 signature length in bytes */
#define LICHEN_SIG_LEN 48

/** Maximum destination address length (EUI-64) */
#define LICHEN_ADDR_MAX 8

/**
 * @brief Address mode (LLSec bits 0-1)
 */
enum lichen_addr_mode {
	LICHEN_ADDR_BROADCAST = 0,  /**< No address (broadcast) */
	LICHEN_ADDR_SHORT = 1,      /**< 16-bit short address */
	LICHEN_ADDR_EUI64 = 2,      /**< 64-bit EUI-64 */
	LICHEN_ADDR_ELIDED = 3,     /**< Address elided (context-dependent) */
};

/**
 * @brief MIC length (LLSec bits 2-4)
 */
enum lichen_mic_len {
	LICHEN_MIC_32 = 0,  /**< 32-bit MIC (4 bytes) */
	LICHEN_MIC_64 = 1,  /**< 64-bit MIC (8 bytes) */
};

/**
 * @brief LICHEN frame structure for parsing/building frames
 */
struct lichen_frame {
	uint8_t epoch;           /**< Epoch counter (key rotation) */
	uint16_t seqnum;         /**< Sequence number (replay protection) */
	uint8_t dst_addr[8];     /**< Destination address (0-8 bytes) */
	uint8_t dst_addr_len;    /**< Destination address length */
	const uint8_t *payload;  /**< Payload (may include signature) */
	size_t payload_len;      /**< Payload length */
	uint8_t mic[8];          /**< Message integrity code */
	uint8_t mic_len;         /**< MIC length (4 or 8) */

	/* LLSec flags */
	enum lichen_addr_mode addr_mode;
	enum lichen_mic_len mic_length;
	bool signature_present;  /**< Schnorr-48 appended to payload */
	bool encrypted;          /**< AES-CCM encrypted */
};

/**
 * @brief Parse a LICHEN frame from wire bytes.
 *
 * @param[out] frame  Parsed frame structure
 * @param[in]  data   Wire bytes
 * @param[in]  len    Length of wire data
 * @return 0 on success, negative error code on failure
 */
int lichen_frame_parse(struct lichen_frame *frame,
		       const uint8_t *data, size_t len);

/**
 * @brief Serialize a LICHEN frame to wire bytes.
 *
 * @param[in]  frame  Frame to serialize
 * @param[out] buf    Output buffer
 * @param[in]  buflen Buffer size
 * @return Number of bytes written, or negative error code
 */
int lichen_frame_write(const struct lichen_frame *frame,
		       uint8_t *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LINK_H_ */
