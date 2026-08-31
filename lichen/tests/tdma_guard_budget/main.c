/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/link.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* tdma.c also contains slot selection; the guard-budget test does not depend
 * on a particular hash result, but the translation unit requires the symbol. */
uint32_t lichen_hash_32(const uint8_t *data, size_t len)
{
	(void)data;
	(void)len;
	return 0U;
}


/* Desync recovery FSM (spec/09 14.7 R-09-133) — behavioral oracle:
 * python/tests/timing/test_sfn.py:284-297 (DesyncFSM). */
static void test_desync_fsm(void)
{
	struct lichen_tdma_ctx tdma;
	struct lichen_link_ctx link_ctx;

	/* NULL ctx guard on init. */
	assert(lichen_tdma_init(&tdma, NULL) == -EINVAL);
	memset(&link_ctx, 0, sizeof(link_ctx));
	assert(lichen_tdma_init(&tdma, &link_ctx) == 0);
	assert(lichen_desync_on_sfn_wrap(&tdma, true) ==
	       LICHEN_DESYNC_SYNCED);
	assert(lichen_desync_on_sfn_wrap(&tdma, false) ==
	       LICHEN_DESYNC_DESYNCED);

	/* First valid beacon in DESYNCED -> RECOVERING (count 1). */
	assert(lichen_desync_on_beacon(&tdma, true) ==
	       LICHEN_DESYNC_RECOVERING);
	assert(tdma.desync_consecutive_valid == 1U);

	/* Invalid beacon in RECOVERING -> back to DESYNCED, counters reset. */
	assert(lichen_desync_on_beacon(&tdma, false) ==
	       LICHEN_DESYNC_DESYNCED);
	assert(tdma.desync_consecutive_valid == 0U);

	/* Three consecutive valid beacons recover to SYNCED. */
	assert(lichen_desync_on_beacon(&tdma, true) ==
	       LICHEN_DESYNC_RECOVERING);
	assert(lichen_desync_on_beacon(&tdma, true) ==
	       LICHEN_DESYNC_RECOVERING);
	assert(tdma.desync_consecutive_valid == 2U);
	assert(lichen_desync_on_beacon(&tdma, true) == LICHEN_DESYNC_SYNCED);
	assert(tdma.desync_consecutive_valid == 0U);

	/* NULL guards on every entry point. */
	assert(lichen_desync_on_sfn_wrap(NULL, false) ==
	       LICHEN_DESYNC_DESYNCED);
	assert(lichen_desync_on_beacon(NULL, true) ==
	       LICHEN_DESYNC_DESYNCED);
	assert(lichen_desync_on_missed_superframe(NULL) ==
	       LICHEN_DESYNC_DESYNCED);

	/* SFN wrap with a valid provider is a no-op in DESYNCED. */
	assert(lichen_desync_on_sfn_wrap(&tdma, true) ==
	       LICHEN_DESYNC_DESYNCED);
	assert(lichen_desync_on_beacon(&tdma, true) ==
	       LICHEN_DESYNC_RECOVERING);

	/* sfn.py:115-116: a valid beacon in RECOVERING resets the missed
	 * superframes count while preserving the consecutive-valid count. */
	assert(lichen_desync_on_missed_superframe(&tdma) ==
	       LICHEN_DESYNC_RECOVERING);
	assert(tdma.desync_missed_superframes == 1U);
	assert(lichen_desync_on_beacon(&tdma, true) ==
	       LICHEN_DESYNC_RECOVERING);
	assert(tdma.desync_consecutive_valid == 2U);
	assert(tdma.desync_missed_superframes == 0U);

	/* Bounded RECOVERING timeout: 3 missed superframes -> DESYNCED. */
	assert(lichen_desync_on_missed_superframe(&tdma) ==
	       LICHEN_DESYNC_RECOVERING);
	assert(lichen_desync_on_missed_superframe(&tdma) ==
	       LICHEN_DESYNC_RECOVERING);
	assert(lichen_desync_on_missed_superframe(&tdma) ==
	       LICHEN_DESYNC_DESYNCED);

	/* Missed superframes are a no-op outside RECOVERING. */
	assert(lichen_desync_on_missed_superframe(&tdma) ==
	       LICHEN_DESYNC_DESYNCED);
}

int main(void)
{
	/* Canonical ccp7_holdover.json cases, in milliseconds. */
	assert(lichen_tdma_guard_budget_sufficient(50U, 10U, 10U, 5U, 5U,
						   5U, 5U));
	assert(lichen_tdma_guard_budget_sufficient(50U, 10U, 10U, 10U, 10U,
						   5U, 5U));
	assert(!lichen_tdma_guard_budget_sufficient(50U, 20U, 20U, 5U, 5U,
						    5U, 5U));

	/* The mandatory 50 ms SF10 guard covers the canonical target budget. */
	assert(lichen_tdma_guard_budget_sufficient(50U, 10U, 10U, 10U, 10U,
						   5U, 5U));
	assert(!lichen_tdma_guard_budget_sufficient(49U, 10U, 10U, 10U, 10U,
						    5U, 5U));

	/* Equality and the all-zero mathematical budget are valid. */
	assert(lichen_tdma_guard_budget_sufficient(1U, 1U, 0U, 0U, 0U,
						   0U, 0U));
	assert(lichen_tdma_guard_budget_sufficient(0U, 0U, 0U, 0U, 0U,
						   0U, 0U));

	/* Overflow must never wrap the required budget into an approval. */
	assert(!lichen_tdma_guard_budget_sufficient(UINT64_MAX, UINT64_MAX, 1U,
						    0U, 0U, 0U, 0U));
	assert(!lichen_tdma_guard_budget_sufficient(UINT64_MAX, UINT64_MAX - 4U,
						    1U, 1U, 1U, 1U, 1U));

	test_desync_fsm();

	return 0;
}
