/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include "forwarding_policy.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

struct policy_vector {
	uint8_t source[16];
	uint8_t destination[16];
	bool allowed;
};

static int run_vector(const struct policy_vector *vector)
{
	uint8_t header[40] = {0};

	memcpy(&header[8], vector->source, 16U);
	memcpy(&header[24], vector->destination, 16U);
	if (lichen_forwarding_ipv6_policy_allows(header) != vector->allowed) {
		return 1;
	}
	return 0;
}

static int check_vector(const uint8_t source[16], const uint8_t destination[16],
			bool allowed)
{
	struct policy_vector vector = {0};

	memcpy(vector.source, source, 16U);
	memcpy(vector.destination, destination, 16U);
	vector.allowed = allowed;
	return run_vector(&vector);
}

int main(void)
{
	static const uint8_t valid_source[16] = {0x02, 0x00, [15] = 1};
	static const uint8_t valid_destination[16] = {0x03, 0x00, [15] = 2};
	static const uint8_t unspecified[16] = {0};
	static const uint8_t loopback[16] = {[15] = 1};
	static const uint8_t mapped[16] = {
		[10] = 0xff, [11] = 0xff, [15] = 1,
	};

	static const uint8_t source_multicast[16] = {0xff, 0x02};
	const struct {
		const uint8_t *source;
		const uint8_t *destination;
	} fixed[] = {
		{unspecified, valid_destination},
		{loopback, valid_destination},
		{mapped, valid_destination},
		{source_multicast, valid_destination},
		{valid_source, unspecified},
		{valid_source, loopback},
		{valid_source, mapped},
	};

	for (uint8_t scope = 0; scope < 16U; scope++) {
		uint8_t multicast[16] = {0xff, scope};
		bool allowed = scope >= 2U && scope <= 14U;

		if (check_vector(valid_source, multicast, allowed) != 0) {
			fprintf(stderr, "multicast scope %u mismatch\n", scope);
			return 1;
		}
	}

	for (size_t i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
		if (check_vector(fixed[i].source, fixed[i].destination, false) != 0) {
			fprintf(stderr, "policy vector %zu mismatch\n", i);
			return 1;
		}
	}

	return 0;
}
