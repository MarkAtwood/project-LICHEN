/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rpl_dao_tx_persist.h>

#include <string.h>

size_t lichen_rpl_dao_tx_encode(const uint8_t public_key[32],
				const uint8_t local_origin[16],
				uint8_t rpl_instance_id,
				const uint8_t dodag_id[16], uint64_t sequence,
				const uint8_t *signed_dao, size_t signed_dao_len,
				uint8_t *out, size_t out_len)
{
	if (public_key == NULL || local_origin == NULL || dodag_id == NULL ||
	    out == NULL ||
	    (signed_dao == NULL && signed_dao_len > 0) ||
	    signed_dao_len > LICHEN_DAO_TX_MAX_SIGNED_LEN ||
	    out_len < LICHEN_DAO_TX_HEADER_LEN + signed_dao_len) {
		return 0;
	}
	memcpy(&out[0], public_key, 32);
	memcpy(&out[32], local_origin, 16);
	out[48] = rpl_instance_id;
	memcpy(&out[49], dodag_id, 16);
	for (unsigned int i = 0; i < 8; i++) {
		out[65 + i] = (uint8_t)(sequence >> (8 * (7 - i)));
	}
	uint16_t signed_len16 = (uint16_t)signed_dao_len;

	out[73] = (uint8_t)(signed_len16 >> 8);
	out[74] = (uint8_t)signed_len16;
	if (signed_dao_len > 0) {
		memcpy(&out[LICHEN_DAO_TX_HEADER_LEN], signed_dao,
		       signed_dao_len);
	}
	return LICHEN_DAO_TX_HEADER_LEN + signed_dao_len;
}

bool lichen_rpl_dao_tx_parse(const uint8_t *payload, size_t payload_len,
			     struct lichen_rpl_dao_tx_header *header)
{
	if (payload == NULL || header == NULL ||
	    payload_len < LICHEN_DAO_TX_HEADER_LEN) {
		return false;
	}
	uint16_t signed_len = (uint16_t)(((uint16_t)payload[73] << 8) |
					 (uint16_t)payload[74]);

	if (signed_len > LICHEN_DAO_TX_MAX_SIGNED_LEN ||
	    payload_len != LICHEN_DAO_TX_HEADER_LEN + (size_t)signed_len) {
		return false;
	}
	header->public_key = &payload[0];
	header->local_origin = &payload[32];
	header->rpl_instance_id = payload[48];
	header->dodag_id = &payload[49];
	uint64_t sequence = 0;

	for (unsigned int i = 65; i < 73; i++) {
		sequence = (sequence << 8) | payload[i];
	}
	header->sequence = sequence;
	header->signed_dao_len = signed_len;
	header->signed_dao = &payload[LICHEN_DAO_TX_HEADER_LEN];
	return true;
}
