/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rpl_sf_assignment.h>

#include <lichen/link.h>

void lichen_rpl_sf_assignment_init(struct lichen_rpl_sf_assignment *s)
{
	if (s == NULL) {
		return;
	}
	s->assigned_sf_dio = 0;
	s->joined = false;
}

bool lichen_rpl_sf_is_valid(uint8_t sf)
{
	return sf >= LICHEN_SF_MIN && sf <= LICHEN_SF_MAX;
}

bool lichen_rpl_sf_assignment_make(uint8_t sf, uint8_t out[3])
{
	if (out == NULL || !lichen_rpl_sf_is_valid(sf)) {
		return false;
	}
	out[0] = LICHEN_DIO_OPTION_ASSIGNED_SF;
	out[1] = 1;
	out[2] = sf;
	return true;
}

uint8_t lichen_rpl_sf_assignment_parse(const uint8_t *data, size_t len)
{
	if (data == NULL || len < 3 || data[0] != LICHEN_DIO_OPTION_ASSIGNED_SF ||
	    data[1] != 1) {
		return 0;
	}
	return lichen_rpl_sf_is_valid(data[2]) ? data[2] : 0;
}

uint8_t lichen_rpl_sf_effective(const struct lichen_rpl_sf_assignment *s,
				const uint8_t iid[8])
{
	if (s != NULL && lichen_rpl_sf_is_valid(s->assigned_sf_dio)) {
		return s->assigned_sf_dio;
	}
	if (s == NULL || !s->joined) {
		return 10;
	}
	return (uint8_t)(7 + (lichen_hash_32(iid, 8) % 6));
}
