/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file beacon.c
 * @brief TDMA beacon wire codec (spec 02a-coordinated-capacity.md §2a.2).
 */

#include <lichen/beacon.h>

#include <string.h>

static uint32_t beacon_read_be32(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int lichen_beacon_parse_header(const uint8_t *data, size_t len,
			       struct lichen_beacon_header *out)
{
	if (data == NULL || out == NULL) {
		return LICHEN_BEACON_ERR_SHORT;
	}
	if (len < LICHEN_BEACON_HEADER_SIZE) {
		return LICHEN_BEACON_ERR_SHORT;
	}
	uint8_t flags = data[13];
	if (flags & LICHEN_BEACON_FLAG_RESERVED_MASK) {
		return LICHEN_BEACON_ERR_RESERVED;
	}

	memset(out, 0, sizeof(*out));
	out->epoch = beacon_read_be32(&data[0]);
	out->num_slots = data[4];
	out->sfn = beacon_read_be32(&data[5]);
	out->timestamp = beacon_read_be32(&data[9]);
	out->flags = flags;
	out->rx_chains = data[14];
	out->setup_window = (uint16_t)(((uint16_t)data[15] << 8) | data[16]);
	out->occupied_time = (uint16_t)(((uint16_t)data[17] << 8) | data[18]);
	out->guard = data[19];
	out->channel_mask = beacon_read_be32(&data[20]);
	return 0;
}

int lichen_beacon_serialize_header(const struct lichen_beacon_header *header,
				   uint8_t *out)
{
	if (header == NULL || out == NULL) {
		return LICHEN_BEACON_ERR_SHORT;
	}
	if (header->flags & LICHEN_BEACON_FLAG_RESERVED_MASK) {
		return LICHEN_BEACON_ERR_RESERVED;
	}

	memset(out, 0, LICHEN_BEACON_HEADER_SIZE);
	out[0] = (uint8_t)(header->epoch >> 24);
	out[1] = (uint8_t)(header->epoch >> 16);
	out[2] = (uint8_t)(header->epoch >> 8);
	out[3] = (uint8_t)header->epoch;
	out[4] = header->num_slots;
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
	return (int)LICHEN_BEACON_HEADER_SIZE;
}

const uint8_t *lichen_beacon_signature_bytes(const uint8_t *beacon, size_t len)
{
	if (beacon == NULL || len < LICHEN_BEACON_MIN_SIZE) {
		return NULL;
	}
	return &beacon[len - LICHEN_BEACON_SIG_SIZE];
}

const uint8_t *lichen_beacon_signed_data(const uint8_t *beacon, size_t len)
{
	if (beacon == NULL || len < LICHEN_BEACON_MIN_SIZE) {
		return NULL;
	}
	/* The signature covers bytes 0..E-48, i.e. everything before the
	 * trailing signature. */
	return beacon;
}
