/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/sf_assignment.h>
#include <lichen/link.h>

#include <string.h>

bool lichen_sf_assignment_parse_option(const uint8_t *data, size_t len,
				       uint8_t *sf)
{
	if (data == NULL || sf == NULL || len < 3) {
		return false;
	}
	if (data[0] != LICHEN_RPL_OPT_ASSIGNED_SF || data[1] != 1) {
		return false;
	}
	if (data[2] < LICHEN_SF_MIN || data[2] > LICHEN_SF_MAX) {
		return false;
	}
	*sf = data[2];
	return true;
}

uint8_t lichen_sf_assignment_effective(uint8_t assigned_sf, bool joined,
				       const uint8_t iid[8])
{
	if (assigned_sf >= LICHEN_SF_MIN && assigned_sf <= LICHEN_SF_MAX) {
		return assigned_sf;
	}
	if (!joined) {
		return 10;
	}
	return (uint8_t)(7 + (lichen_hash_32(iid, 8) % 6));
}
