/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file beacon.c
 * @brief TDMA beacon wire codec (spec 02a-coordinated-capacity.md §2a.2).
 *
 * Merge resolution (main + beads-worker-7): both sides implemented bead
 * l9sb independently. HEAD's API (enum lichen_beacon_status, bounds-checked
 * serialize, flag predicates, signed_data with signed_len, cbor_options) is
 * kept because it is the complete port of the Python/Rust reference codecs
 * that bead l9sb requires ("signature_bytes/signed_data/cbor_options
 * extraction"); the incoming beads-worker-7 codec drops cbor_options and
 * the flag predicates and its serialize is not bounds-checked. The @file
 * doc comment above is retained from beads-worker-7. Note: the incoming
 * host test lichen/tests/tdma_beacon/src/main.c calls the beads-worker-7
 * parse_header/serialize_header API and must be reconciled with this API.
 */

#include <lichen/beacon.h>

#include <string.h>

enum lichen_beacon_status
lichen_beacon_header_parse(const uint8_t *data, size_t len,
			   struct lichen_beacon_header *out)
{
	if (data == NULL || out == NULL || len < LICHEN_BEACON_HEADER_SIZE) {
		return LICHEN_BEACON_TOO_SHORT;
	}
	if (data[13] & LICHEN_BEACON_FLAG_RESERVED_MASK) {
		return LICHEN_BEACON_RESERVED_FLAG_SET;
	}
	out->epoch = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
		     ((uint32_t)data[2] << 8) | (uint32_t)data[3];
	out->num_slots = data[4];
	out->sfn = ((uint32_t)data[5] << 24) | ((uint32_t)data[6] << 16) |
		   ((uint32_t)data[7] << 8) | (uint32_t)data[8];
	out->timestamp = ((uint32_t)data[9] << 24) | ((uint32_t)data[10] << 16) |
			 ((uint32_t)data[11] << 8) | (uint32_t)data[12];
	out->flags = data[13];
	out->rx_chains = data[14];
	out->setup_window =
		(uint16_t)(((uint16_t)data[15] << 8) | (uint16_t)data[16]);
	out->occupied_time =
		(uint16_t)(((uint16_t)data[17] << 8) | (uint16_t)data[18]);
	out->guard = data[19];
	out->channel_mask = ((uint32_t)data[20] << 24) |
			    ((uint32_t)data[21] << 16) |
			    ((uint32_t)data[22] << 8) | (uint32_t)data[23];
	return LICHEN_BEACON_OK;
}

enum lichen_beacon_status
lichen_beacon_header_serialize(const struct lichen_beacon_header *header,
			       uint8_t *out, size_t out_len)
{
	if (header == NULL || out == NULL ||
	    out_len < LICHEN_BEACON_HEADER_SIZE) {
		return LICHEN_BEACON_TOO_SHORT;
	}
	if (header->flags & LICHEN_BEACON_FLAG_RESERVED_MASK) {
		return LICHEN_BEACON_RESERVED_FLAG_SET;
	}
	out[0] = (uint8_t)(header->epoch >> 24);
	out[1] = (uint8_t)(header->epoch >> 16);
	out[2] = (uint8_t)(header->epoch >> 8);
	out[3] = (uint8_t)header->epoch;
	out[4] = (uint8_t)header->num_slots;
	out[5] = (uint8_t)(header->sfn >> 24);
	out[6] = (uint8_t)(header->sfn >> 16);
	out[7] = (uint8_t)(header->sfn >> 8);
	out[8] = (uint8_t)header->sfn;
	out[9] = (uint8_t)(header->timestamp >> 24);
	out[10] = (uint8_t)(header->timestamp >> 16);
	out[11] = (uint8_t)(header->timestamp >> 8);
	out[12] = (uint8_t)header->timestamp;
	out[13] = header->flags;
	out[14] = header->rx_chains;
	out[15] = (uint8_t)(header->setup_window >> 8);
	out[16] = (uint8_t)header->setup_window;
	out[17] = (uint8_t)(header->occupied_time >> 8);
	out[18] = (uint8_t)header->occupied_time;
	out[19] = header->guard;
	out[20] = (uint8_t)(header->channel_mask >> 24);
	out[21] = (uint8_t)(header->channel_mask >> 16);
	out[22] = (uint8_t)(header->channel_mask >> 8);
	out[23] = (uint8_t)header->channel_mask;
	return LICHEN_BEACON_OK;
}

bool lichen_beacon_is_scheduled(uint8_t flags)
{
	return (flags & LICHEN_BEACON_FLAG_SCHEDULED) != 0;
}

bool lichen_beacon_is_csma(uint8_t flags)
{
	return (flags & LICHEN_BEACON_FLAG_CSMA) != 0;
}

bool lichen_beacon_is_ch0_rx(uint8_t flags)
{
	return (flags & LICHEN_BEACON_FLAG_CH0_RX) != 0;
}

bool lichen_beacon_has_gnss_pps(uint8_t flags)
{
	return (flags & LICHEN_BEACON_FLAG_GNSS_PPS) != 0;
}

const uint8_t *lichen_beacon_signature_bytes(const uint8_t *beacon, size_t len)
{
	if (beacon == NULL || len < LICHEN_BEACON_MIN_SIZE) {
		return NULL;
	}
	return &beacon[len - LICHEN_BEACON_SIG_SIZE];
}

const uint8_t *lichen_beacon_signed_data(const uint8_t *beacon, size_t len,
					 size_t *signed_len)
{
	if (beacon == NULL || signed_len == NULL ||
	    len < LICHEN_BEACON_MIN_SIZE) {
		return NULL;
	}
	*signed_len = len - LICHEN_BEACON_SIG_SIZE;
	return beacon;
}

const uint8_t *lichen_beacon_cbor_options(const uint8_t *beacon, size_t len,
					  size_t *options_len)
{
	if (beacon == NULL || options_len == NULL ||
	    len <= LICHEN_BEACON_MIN_SIZE) {
		return NULL;
	}
	*options_len = len - LICHEN_BEACON_MIN_SIZE;
	return &beacon[LICHEN_BEACON_HEADER_SIZE];
}

enum lichen_slot_map_status
lichen_beacon_parse_slot_map(const uint8_t *cbor, size_t cbor_len,
			     uint8_t num_slots, uint8_t *out, size_t out_cap,
			     size_t *out_len)
{
	size_t pos = 0;
	size_t count = 0;
	uint8_t prev = 0;
	bool have_prev = false;

	if (out_len == NULL) {
		return LICHEN_SLOT_MAP_TRUNCATED;
	}
	if (cbor == NULL || cbor_len == 0) {
		*out_len = 0;
		return LICHEN_SLOT_MAP_EMPTY;
	}
	if (out == NULL) {
		return LICHEN_SLOT_MAP_TRUNCATED;
	}

	uint8_t first = cbor[pos];
	pos++;
	size_t len;
	if (first >= 0x80u && first <= 0x97u) {
		len = (size_t)(first - 0x80u);
	} else if (first == 0x98u) {
		if (pos >= cbor_len) {
			return LICHEN_SLOT_MAP_TRUNCATED;
		}
		len = (size_t)cbor[pos];
		pos++;
	} else {
		return LICHEN_SLOT_MAP_NOT_AN_ARRAY;
	}
	if (len > LICHEN_SLOT_MAP_MAX_ENTRIES) {
		return LICHEN_SLOT_MAP_TOO_MANY_SLOTS;
	}

	while (count < len) {
		if (pos >= cbor_len) {
			return LICHEN_SLOT_MAP_TRUNCATED;
		}
		uint8_t byte = cbor[pos];
		pos++;
		uint8_t slot;
		if (byte <= 0x17u) {
			slot = byte;
		} else if (byte == 0x18u) {
			if (pos >= cbor_len) {
				return LICHEN_SLOT_MAP_TRUNCATED;
			}
			slot = cbor[pos];
			pos++;
		} else {
			return LICHEN_SLOT_MAP_INVALID_ENCODING;
		}
		if (slot >= num_slots) {
			return LICHEN_SLOT_MAP_OUT_OF_BOUNDS;
		}
		if (have_prev && slot <= prev) {
			return LICHEN_SLOT_MAP_NOT_SORTED;
		}
		if (count >= out_cap) {
			return LICHEN_SLOT_MAP_TOO_MANY_SLOTS;
		}
		out[count] = slot;
		count++;
		prev = slot;
		have_prev = true;
	}
	if (pos != cbor_len) {
		return LICHEN_SLOT_MAP_TRAILING_BYTES;
	}
	*out_len = count;
	return LICHEN_SLOT_MAP_OK;
}

size_t lichen_beacon_write_slot_map(const uint8_t *slots, size_t slot_count,
				    uint8_t *out, size_t out_len)
{
	if (slot_count > LICHEN_SLOT_MAP_MAX_ENTRIES || out == NULL) {
		return 0;
	}
	if (slots == NULL && slot_count != 0) {
		return 0;
	}

	/* Header: 0x80+len short form (<= 23) or 0x98 + one-byte length. */
	size_t pos = 0;
	if (slot_count <= 23) {
		if (out_len < 1) {
			return 0;
		}
		out[pos++] = (uint8_t)(0x80 + slot_count);
	} else {
		if (out_len < 2) {
			return 0;
		}
		out[pos++] = 0x98;
		out[pos++] = (uint8_t)slot_count;
	}

	/* Entries: CBOR immediate 0x00..0x17 for 0..23; 0x18 prefix for
	 * 24..255 — entries > 0x17 take two bytes, so bound-check each. */
	for (size_t i = 0; i < slot_count; i++) {
		uint8_t v = slots[i];
		size_t need = (v <= 0x17u) ? 1u : 2u;

		if (out_len - pos < need) {
			return 0;
		}
		if (v <= 0x17u) {
			out[pos++] = v;
		} else {
			out[pos++] = 0x18;
			out[pos++] = v;
		}
	}
	return pos;
}
