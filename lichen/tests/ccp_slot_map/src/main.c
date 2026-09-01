/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/link.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Test vectors mirrored from test/vectors/ccp_slot_map_validation.json
 * (spec 02a 2a.2 / R-02a-008 family: slot_map must be strictly ascending
 * and every entry within [0, num_slots); empty map is valid). */
struct slot_map_case {
	const char *name;
	uint8_t num_slots;
	uint8_t slots[8];
	size_t len;
	bool expected;
};

static const struct slot_map_case CASES[] = {
	{ "slot_out_of_bounds", 8, { 0, 3, 8, 12 }, 4, false },
	{ "slot_unsorted", 16, { 3, 1, 5, 2 }, 4, false },
	{ "slot_boundary_valid", 8, { 0, 1, 7 }, 3, true },
	{ "slot_boundary_invalid", 8, { 0, 1, 8 }, 3, false },
	{ "slot_empty", 8, { 0 }, 0, true },
	{ "slot_duplicate", 8, { 1, 1, 3 }, 3, false },
	{ "slot_single_max_valid", 255, { 254 }, 1, true },
	{ "slot_single_at_limit", 255, { 255 }, 1, false },
	{ "slot_all_valid", 8, { 0, 1, 2, 3, 4, 5, 6, 7 }, 8, true },
	{ "slot_single_zero", 1, { 0 }, 1, true },
	{ "slot_zero_num_slots", 0, { 0 }, 1, false },
	{ "slot_descending", 8, { 7, 5, 3, 1 }, 4, false },
	{ "slot_partial_sorted", 8, { 1, 2, 2, 3 }, 4, false },
	{ "slot_gap_valid", 8, { 0, 3, 7 }, 3, true },
	{ "slot_first_invalid", 8, { 10 }, 1, false },
};

int main(void)
{
	size_t failures = 0;

	for (size_t i = 0; i < sizeof(CASES) / sizeof(CASES[0]); i++) {
		const struct slot_map_case *c = &CASES[i];
		bool valid = lichen_slot_map_validate(c->slots, c->len,
						      c->num_slots);
		if (valid != c->expected) {
			fprintf(stderr, "FAIL %s: got %d expected %d\n",
				c->name, valid, c->expected);
			failures++;
		}
	}

	/* Empty map with NULL array pointer is still valid (len 0). */
	if (lichen_slot_map_validate(NULL, 0, 8) != true) {
		fprintf(stderr, "FAIL null-empty: expected valid\n");
		failures++;
	}

	if (failures > 0) {
		fprintf(stderr, "ccp_slot_map tests: %zu failure(s)\n",
			failures);
		return 1;
	}
	printf("ccp_slot_map tests passed\n");
	return 0;
}
