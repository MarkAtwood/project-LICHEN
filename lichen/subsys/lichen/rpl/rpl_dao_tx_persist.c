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

/* ------------------------------------------------------------------ */
/* DAO TX state open/provision (rust persistence.rs DaoTxState).       */
/* ------------------------------------------------------------------ */

#include <lichen/hal_storage_redundant.h>

static const char *const dao_tx_keys[2] = { LICHEN_DAO_TX_KEYS_0,
					    LICHEN_DAO_TX_KEYS_1 };
static const uint8_t dao_tx_magic[4] = { 'D', 'T', 'X', '2' };

enum lichen_rpl_dao_tx_open_status lichen_rpl_dao_tx_open(
	const struct lichen_hal_storage_ops *ops, void *user,
	const uint8_t expected_key[32], const uint8_t local_origin[16],
	uint8_t rpl_instance_id, const uint8_t dodag_id[16],
	struct lichen_rpl_dao_tx_state *state)
{
	uint8_t slot_a[LICHEN_DAO_TX_HEADER_LEN +
		       LICHEN_DAO_TX_MAX_SIGNED_LEN];
	uint8_t slot_b[LICHEN_DAO_TX_HEADER_LEN +
		       LICHEN_DAO_TX_MAX_SIGNED_LEN];
	uint8_t payload[LICHEN_DAO_TX_HEADER_LEN +
			LICHEN_DAO_TX_MAX_SIGNED_LEN];
	size_t payload_len = sizeof(payload);
	struct lichen_hal_storage_value current;
	struct lichen_rpl_dao_tx_header header;
	enum lichen_hal_storage_open_status status;

	if (ops == NULL || expected_key == NULL || local_origin == NULL ||
	    dodag_id == NULL || state == NULL) {
		return LICHEN_DAO_TX_OPEN_STORAGE_ERROR;
	}
	status = lichen_hal_storage_open_redundant(
		ops, user, dao_tx_keys, dao_tx_magic, slot_a, sizeof(slot_a),
		slot_b, sizeof(slot_b), payload, &payload_len, &current);
	if (status == LICHEN_STORAGE_OPEN_MISSING) {
		return LICHEN_DAO_TX_OPEN_MISSING;
	}
	if (status == LICHEN_STORAGE_OPEN_CORRUPT) {
		return LICHEN_DAO_TX_OPEN_CORRUPT;
	}
	if (status != LICHEN_STORAGE_OPEN_OK) {
		return LICHEN_DAO_TX_OPEN_STORAGE_ERROR;
	}
	if (payload_len < LICHEN_DAO_TX_HEADER_LEN) {
		return LICHEN_DAO_TX_OPEN_CORRUPT;
	}
	/* Extract the header fields first so key/scope mismatches are
	 * reported with Rust's precedence even for structurally odd
	 * records (persistence.rs:206-221 order). */
	uint64_t sequence = 0;
	uint16_t signed_len = 0;

	for (unsigned int i = 0; i < 32; i++) {
		state->public_key[i] = payload[i];
	}
	if (memcmp(payload, expected_key, 32) != 0) {
		return LICHEN_DAO_TX_OPEN_KEY_MISMATCH;
	}
	if (memcmp(&payload[32], local_origin, 16) != 0 ||
	    payload[48] != rpl_instance_id ||
	    memcmp(&payload[49], dodag_id, 16) != 0) {
		return LICHEN_DAO_TX_OPEN_SCOPE_MISMATCH;
	}
	for (unsigned int i = 65; i < 73; i++) {
		sequence = (sequence << 8) | payload[i];
	}
	signed_len = (uint16_t)(((uint16_t)payload[73] << 8) |
				(uint16_t)payload[74]);
	if (signed_len > LICHEN_DAO_TX_MAX_SIGNED_LEN ||
	    payload_len != LICHEN_DAO_TX_HEADER_LEN + (size_t)signed_len) {
		return LICHEN_DAO_TX_OPEN_CORRUPT;
	}
	/* Full structural validation (reserved bytes, CRC-32 trailer) —
	 * this is the Rust open()'s final Corrupt gate. */
	if (!lichen_rpl_dao_tx_parse(payload, payload_len, &header) ||
	    header.signed_dao_len != signed_len ||
	    header.sequence != sequence) {
		return LICHEN_DAO_TX_OPEN_CORRUPT;
	}
	memcpy(state->public_key, header.public_key, 32);
	memcpy(state->local_origin, header.local_origin, 16);
	state->rpl_instance_id = header.rpl_instance_id;
	memcpy(state->dodag_id, header.dodag_id, 16);
	state->last_reserved = header.sequence;
	state->last_signed_dao_len = header.signed_dao_len;
	if (header.signed_dao_len > 0) {
		memcpy(state->last_signed_dao, header.signed_dao,
		       header.signed_dao_len);
	}
	state->current = current;
	return LICHEN_DAO_TX_OPEN_OK;
}

enum lichen_rpl_dao_tx_provision_status lichen_rpl_dao_tx_provision(
	const struct lichen_hal_storage_ops *ops, void *user,
	const uint8_t expected_key[32], const uint8_t local_origin[16],
	uint8_t rpl_instance_id, const uint8_t dodag_id[16],
	struct lichen_rpl_dao_tx_state *state)
{
	uint8_t payload[LICHEN_DAO_TX_HEADER_LEN];
	uint8_t record[LICHEN_DAO_TX_HEADER_LEN +
		       LICHEN_DAO_TX_MAX_SIGNED_LEN];
	size_t payload_len;
	enum lichen_rpl_dao_tx_open_status opened;

	if (ops == NULL || expected_key == NULL || local_origin == NULL ||
	    dodag_id == NULL || state == NULL) {
		return LICHEN_DAO_TX_PROVISION_STORAGE_ERROR;
	}
	opened = lichen_rpl_dao_tx_open(ops, user, expected_key, local_origin,
					rpl_instance_id, dodag_id, state);
	if (opened == LICHEN_DAO_TX_OPEN_OK) {
		return LICHEN_DAO_TX_PROVISION_ALREADY;
	}
	if (opened == LICHEN_DAO_TX_OPEN_STORAGE_ERROR) {
		return LICHEN_DAO_TX_PROVISION_STORAGE_ERROR;
	}
	if (opened != LICHEN_DAO_TX_OPEN_MISSING) {
		return LICHEN_DAO_TX_PROVISION_CORRUPT;
	}
	payload_len = lichen_rpl_dao_tx_encode(expected_key, local_origin,
					       rpl_instance_id, dodag_id, 0,
					       NULL, 0, payload,
					       sizeof(payload));
	if (payload_len == 0) {
		return LICHEN_DAO_TX_PROVISION_STORAGE_ERROR;
	}
	if (lichen_hal_storage_provision_redundant(
		    ops, user, dao_tx_keys, dao_tx_magic, payload, payload_len,
		    record, sizeof(record)) != LICHEN_STORAGE_PROVISION_OK) {
		return LICHEN_DAO_TX_PROVISION_STORAGE_ERROR;
	}
	opened = lichen_rpl_dao_tx_open(ops, user, expected_key, local_origin,
					rpl_instance_id, dodag_id, state);
	if (opened != LICHEN_DAO_TX_OPEN_OK) {
		return LICHEN_DAO_TX_PROVISION_CORRUPT;
	}
	return LICHEN_DAO_TX_PROVISION_OK;
}

static enum lichen_rpl_dao_tx_tx_status tx_persist(
	const struct lichen_hal_storage_ops *ops, void *user,
	struct lichen_rpl_dao_tx_state *state, uint64_t sequence,
	const uint8_t *signed_dao, size_t signed_dao_len, uint8_t *record,
	size_t record_len)
{
	uint8_t payload[LICHEN_DAO_TX_HEADER_LEN +
			LICHEN_DAO_TX_MAX_SIGNED_LEN];
	size_t payload_len = lichen_rpl_dao_tx_encode(
		state->public_key, state->local_origin,
		state->rpl_instance_id, state->dodag_id, sequence, signed_dao,
		signed_dao_len, payload, sizeof(payload));
	struct lichen_hal_storage_value updated;
	enum lichen_hal_storage_update_status status;

	if (payload_len == 0) {
		return LICHEN_DAO_TX_TX_STORAGE_ERROR;
	}
	status = lichen_hal_storage_update_redundant(
		ops, user, dao_tx_keys, dao_tx_magic, &state->current,
		payload, payload_len, record, record_len, &updated);
	if (status == LICHEN_STORAGE_UPDATE_STALE) {
		return LICHEN_DAO_TX_TX_STALE;
	}
	if (status == LICHEN_STORAGE_UPDATE_EXHAUSTED) {
		return LICHEN_DAO_TX_TX_EXHAUSTED;
	}
	if (status == LICHEN_STORAGE_UPDATE_CORRUPT ||
	    status == LICHEN_STORAGE_UPDATE_BUFFER_TOO_SMALL) {
		return LICHEN_DAO_TX_TX_CORRUPT;
	}
	if (status != LICHEN_STORAGE_UPDATE_OK) {
		return LICHEN_DAO_TX_TX_STORAGE_ERROR;
	}
	state->current = updated;
	return LICHEN_DAO_TX_TX_OK;
}

enum lichen_rpl_dao_tx_tx_status lichen_rpl_dao_tx_reserve_next(
	const struct lichen_hal_storage_ops *ops, void *user,
	struct lichen_rpl_dao_tx_state *state, uint8_t *record,
	size_t record_len, uint64_t *next)
{
	uint64_t next_seq;
	enum lichen_rpl_dao_tx_tx_status status;

	if (ops == NULL || state == NULL || record == NULL || next == NULL) {
		return LICHEN_DAO_TX_TX_STORAGE_ERROR;
	}
	if (state->last_reserved == UINT64_MAX) {
		return LICHEN_DAO_TX_TX_EXHAUSTED;
	}
	next_seq = state->last_reserved + 1;
	status = tx_persist(ops, user, state, next_seq,
			    state->last_signed_dao, state->last_signed_dao_len,
			    record, record_len);
	if (status != LICHEN_DAO_TX_TX_OK) {
		return status;
	}
	state->last_reserved = next_seq;
	*next = next_seq;
	return LICHEN_DAO_TX_TX_OK;
}

enum lichen_rpl_dao_tx_tx_status lichen_rpl_dao_tx_clear_transmitted(
	const struct lichen_hal_storage_ops *ops, void *user,
	struct lichen_rpl_dao_tx_state *state, uint8_t *record,
	size_t record_len)
{
	if (ops == NULL || state == NULL || record == NULL) {
		return LICHEN_DAO_TX_TX_STORAGE_ERROR;
	}
	if (state->last_signed_dao_len == 0) {
		return LICHEN_DAO_TX_TX_INVALID_STATE;
	}
	enum lichen_rpl_dao_tx_tx_status status =
		tx_persist(ops, user, state, state->last_reserved, NULL, 0,
			   record, record_len);

	if (status == LICHEN_DAO_TX_TX_OK) {
		state->last_signed_dao_len = 0;
	}
	return status;
}

/* ------------------------------------------------------------------ */
/* Signed DAO envelope validation + finalize_signed (rust message.rs   */
/* SignedDaoEnvelope::from_bytes / persistence.rs finalize_signed).    */
/* ------------------------------------------------------------------ */

#define LICHEN_RPL_OPT_PAD1 0u
#define LICHEN_RPL_OPT_RPL_TARGET 5u
#define LICHEN_RPL_OPT_TRANSIT_INFO 6u
#define LICHEN_RPL_OPT_RPL_TARGET_DESCRIPTOR 9u
#define LICHEN_RPL_OPT_DAO_ORIGIN_SIGNATURE 0x12u
#define LICHEN_RPL_DAO_BASE_LEN 20u /* D=1 common case */
#define LICHEN_RPL_TRANSIT_INFO_DATA_LEN 20u

/* Generalized RPL Target body (spec/05-routing 8.7.1): flags 0,
 * prefix length 1..=128, at least ceil(prefix_len/8) prefix octets. */
static bool generalized_target_body_ok(const uint8_t *body, size_t len)
{
	return len >= 2 && body[0] == 0 && body[1] <= 128 &&
	       len - 2 >= ((size_t)body[1] + 7u) / 8u;
}

int lichen_rpl_dao_envelope_sequence(const uint8_t *data, size_t len,
				     uint64_t *sequence)
{
	if (data == NULL || sequence == NULL || len < 4) {
		return -LICHEN_DAO_TX_FINALIZE_ENCODING;
	}
	/* DAO base: reject local RPLInstanceID 0xC0-0xFF (RFC 6550 5.1). */
	if (data[0] >= 0xC0 || (data[1] & 0x3F) != 0 || data[2] != 0) {
		return -LICHEN_DAO_TX_FINALIZE_ENCODING;
	}
	size_t base_len = (len > LICHEN_RPL_DAO_BASE_LEN)
				  ? LICHEN_RPL_DAO_BASE_LEN
				  : len;
	size_t pos = base_len;
	bool found = false;
	uint64_t seq = 0;

	while (pos < len) {
		if (data[pos] == LICHEN_RPL_OPT_PAD1) {
			if (found) {
				return -LICHEN_DAO_TX_FINALIZE_ENCODING;
			}
			pos++;
			continue;
		}
		if (pos + 2 > len) {
			return -LICHEN_DAO_TX_FINALIZE_ENCODING;
		}
		size_t opt_end = pos + 2 + (size_t)data[pos + 1];

		if (opt_end > len) {
			return -LICHEN_DAO_TX_FINALIZE_ENCODING;
		}
		if (data[pos] == LICHEN_RPL_OPT_DAO_ORIGIN_SIGNATURE) {
			if (found || opt_end - (pos + 2) != 56) {
				return -LICHEN_DAO_TX_FINALIZE_ENCODING;
			}
			const uint8_t *sig = &data[pos + 2];

			seq = 0;
			for (unsigned int i = 0; i < 8; i++) {
				seq = (seq << 8) | sig[i];
			}
			if (seq == 0) {
				return -LICHEN_DAO_TX_FINALIZE_ENCODING;
			}
			found = true;
		} else {
			if (found) {
				return -LICHEN_DAO_TX_FINALIZE_ENCODING;
			}
			size_t body_len = opt_end - (pos + 2);

			if (data[pos] == LICHEN_RPL_OPT_RPL_TARGET) {
				if (!generalized_target_body_ok(&data[pos + 2],
								body_len)) {
					return -LICHEN_DAO_TX_FINALIZE_ENCODING;
				}
			} else if (data[pos] ==
					   LICHEN_RPL_OPT_TRANSIT_INFO &&
				   body_len !=
					   LICHEN_RPL_TRANSIT_INFO_DATA_LEN) {
				return -LICHEN_DAO_TX_FINALIZE_ENCODING;
			} else if (data[pos] ==
					   LICHEN_RPL_OPT_RPL_TARGET_DESCRIPTOR &&
				   body_len != 4) {
				return -LICHEN_DAO_TX_FINALIZE_ENCODING;
			} else if (data[pos] ==
					   LICHEN_RPL_OPT_RPL_TARGET ||
				   data[pos] ==
					   LICHEN_RPL_OPT_TRANSIT_INFO ||
				   data[pos] ==
					   LICHEN_RPL_OPT_RPL_TARGET_DESCRIPTOR) {
				return -LICHEN_DAO_TX_FINALIZE_ENCODING;
			} else {
				return -LICHEN_DAO_TX_FINALIZE_ENCODING;
			}
		}
		pos = opt_end;
	}
	if (!found) {
		return -LICHEN_DAO_TX_FINALIZE_ENCODING;
	}
	*sequence = seq;
	return 0;
}

enum lichen_rpl_dao_tx_finalize_status lichen_rpl_dao_tx_finalize_signed(
	const struct lichen_hal_storage_ops *ops, void *user,
	struct lichen_rpl_dao_tx_state *state, uint64_t sequence,
	const uint8_t *signed_dao, size_t signed_dao_len, uint8_t *record,
	size_t record_len)
{
	uint64_t envelope_seq = 0;
	uint64_t pending_seq = 0;
	bool pending_valid;
	enum lichen_rpl_dao_tx_tx_status status;

	if (ops == NULL || state == NULL || signed_dao == NULL ||
	    record == NULL) {
		return LICHEN_DAO_TX_FINALIZE_STORAGE_ERROR;
	}
	if (sequence != state->last_reserved) {
		return LICHEN_DAO_TX_FINALIZE_INVALID_STATE;
	}
	if (signed_dao_len > LICHEN_DAO_TX_MAX_SIGNED_LEN) {
		return LICHEN_DAO_TX_FINALIZE_OVERSIZED;
	}
	if (lichen_rpl_dao_envelope_sequence(signed_dao, signed_dao_len,
					     &envelope_seq) != 0) {
		return LICHEN_DAO_TX_FINALIZE_ENCODING;
	}
	if (envelope_seq != sequence) {
		return LICHEN_DAO_TX_FINALIZE_INVALID_STATE;
	}
	/* Already-finalized equal-sequence rebuild rejection. */
	pending_valid = state->last_signed_dao_len > 0 &&
			lichen_rpl_dao_envelope_sequence(
				state->last_signed_dao,
				state->last_signed_dao_len,
				&pending_seq) == 0;
	if (pending_valid && pending_seq == sequence) {
		return LICHEN_DAO_TX_FINALIZE_INVALID_STATE;
	}
	status = (enum lichen_rpl_dao_tx_tx_status)tx_persist(
		ops, user, state, sequence, signed_dao, signed_dao_len,
		record, record_len);
	switch (status) {
	case LICHEN_DAO_TX_TX_OK:
		memcpy(state->last_signed_dao, signed_dao, signed_dao_len);
		state->last_signed_dao_len = signed_dao_len;
		return LICHEN_DAO_TX_FINALIZE_OK;
	case LICHEN_DAO_TX_TX_INVALID_STATE:
		return LICHEN_DAO_TX_FINALIZE_INVALID_STATE;
	case LICHEN_DAO_TX_TX_EXHAUSTED:
		return LICHEN_DAO_TX_FINALIZE_EXHAUSTED;
	case LICHEN_DAO_TX_TX_STALE:
		return LICHEN_DAO_TX_FINALIZE_STALE;
	case LICHEN_DAO_TX_TX_CORRUPT:
		return LICHEN_DAO_TX_FINALIZE_CORRUPT;
	default:
		return LICHEN_DAO_TX_FINALIZE_STORAGE_ERROR;
	}
}
