/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/sos_origin_table.h>

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void addr_fill(uint8_t addr[16], uint8_t seed)
{
	for (int i = 0; i < 16; i++) {
		addr[i] = (uint8_t)(seed + i);
	}
}

/* Two origins interleave: each keeps an independent sequence gate, so a
 * stale sequence from A is rejected while B's higher sequence advances. */
static void test_per_origin_seq_gate(void)
{
	struct sos_origin_table t;
	uint8_t a[16], b[16];

	addr_fill(a, 0x10);
	addr_fill(b, 0x20);
	sos_origin_table_init(&t);

	struct sos_origin_entry *ea = sos_origin_table_lookup(&t, a);
	struct sos_origin_entry *eb = sos_origin_table_lookup(&t, b);
	assert(ea != NULL && eb != NULL && ea != eb);

	/* First sequences always advance (accepted starts false). */
	assert(sos_origin_seq_advance(ea, 5));
	ea->last_seq = 5;
	ea->accepted = true;
	assert(sos_origin_seq_advance(eb, 100));
	eb->last_seq = 100;
	eb->accepted = true;

	/* Stale/equal sequence from A rejected; A's gate untouched by B. */
	assert(!sos_origin_seq_advance(ea, 5));
	assert(!sos_origin_seq_advance(ea, 4));
	assert(sos_origin_seq_advance(ea, 6));
	/* B's gate is independent: 100 accepted-so-far, 99 stale. */
	assert(!sos_origin_seq_advance(eb, 99));
	assert(sos_origin_seq_advance(eb, 101));

	/* Lookup returns the SAME entry (gate state persists). */
	assert(sos_origin_table_lookup(&t, a) == ea);
	assert(ea->last_seq == 5);
}

/* spec 18.4.1: after accepting seq 0 the highest accepted IS 0, so a
 * replay of seq 0 must be rejected (regression: last_seq==0 alone cannot
 * distinguish "no prior" from "accepted seq 0"; the accepted flag does). */
static void test_seq_zero_not_replayable(void)
{
	struct sos_origin_table t;
	uint8_t a[16];

	addr_fill(a, 0x50);
	sos_origin_table_init(&t);
	struct sos_origin_entry *e = sos_origin_table_lookup(&t, a);
	assert(e != NULL);

	/* First seq-0 message advances (nothing accepted yet). */
	assert(sos_origin_seq_advance(e, 0));
	e->last_seq = 0;
	e->accepted = true;
	/* Replay of seq 0 is now rejected. */
	assert(!sos_origin_seq_advance(e, 0));
	/* A genuine advance still works. */
	assert(sos_origin_seq_advance(e, 1));
}

/* Rate-limit state is per-origin: recording A's alerts never appears in
 * B's freshly-allocated rate-limit state. */
static void test_per_origin_rate_limit(void)
{
	struct sos_origin_table t;
	struct sos_ratelimit_config cfg;
	uint8_t a[16], b[16];

	addr_fill(a, 0x30);
	addr_fill(b, 0x40);
	sos_origin_table_init(&t);
	sos_ratelimit_config_init(&cfg);

	struct sos_origin_entry *ea = sos_origin_table_lookup(&t, a);
	struct sos_origin_entry *eb = sos_origin_table_lookup(&t, b);

	/* Exhaust A's hourly budget (default 3/hour). */
	for (int i = 0; i < 3; i++) {
		assert(sos_ratelimit_check(&ea->rl, 1000 + i * 700000,
					   &cfg, NULL) == SOS_RATELIMIT_ALLOWED);
		sos_ratelimit_record(&ea->rl, 1000 + i * 700000);
	}
	/* A is now hourly-limited. */
	assert(sos_ratelimit_check(&ea->rl, 1000 + 3 * 700000, &cfg, NULL) ==
	       SOS_RATELIMIT_HOURLY_EXCEEDED);
	/* B is unaffected: A's budget exhaustion does not leak. */
	assert(sos_ratelimit_check(&eb->rl, 1000 + 3 * 700000, &cfg, NULL) ==
	       SOS_RATELIMIT_ALLOWED);
}

/* Table bounds at SOS_ORIGIN_TABLE_MAX; a new origin evicts the
 * least-recently-ACTIVE origin (oldest accepted-alert timestamp), not a
 * random slot and not the lowest sequence counter. */
static void test_lru_eviction(void)
{
	struct sos_origin_table t;
	uint8_t addr[16];

	sos_origin_table_init(&t);
	/* Fill the table; entry 0 is least-recently-active (oldest alert). */
	for (size_t i = 0; i < SOS_ORIGIN_TABLE_MAX; i++) {
		addr_fill(addr, (uint8_t)i);
		struct sos_origin_entry *e = sos_origin_table_lookup(&t, addr);
		assert(e != NULL);
		/* Alert times strictly increase with slot index. */
		sos_ratelimit_record(&e->rl, 1000 + (int64_t)i * 1000);
	}
	/* A new origin must evict slot 0 (oldest alert), not the
	 * most-recently-updated one. */
	uint8_t victim[16], newcomer[16];
	addr_fill(victim, 0x00);
	addr_fill(newcomer, 0xEE);
	struct sos_origin_entry *ev = sos_origin_table_lookup(&t, victim);
	assert(ev != NULL && ev->rl.alert_count == 1U);
	struct sos_origin_entry *en = sos_origin_table_lookup(&t, newcomer);
	assert(en != NULL);
	assert(en == ev); /* reused the evicted slot */
	assert(en->last_seq == 0 && !en->accepted); /* reset on eviction */
	assert(en->rl.alert_count == 0U); /* rate-limit state reset */
	assert(sos_origin_seq_advance(en, 1)); /* fresh gate */
	/* Origin index 1 (second-oldest alert) survived. */
	uint8_t survivor[16];
	addr_fill(survivor, 0x01);
	assert(sos_origin_table_lookup(&t, survivor)->rl.alert_count == 1U);
}

static void test_null_safety(void)
{
	struct sos_origin_table t;

	sos_origin_table_init(&t);
	sos_origin_table_init(NULL);
	assert(sos_origin_table_lookup(NULL, (const uint8_t *)"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0") == NULL);
	assert(sos_origin_table_lookup(&t, NULL) == NULL);
	assert(!sos_origin_seq_advance(NULL, 1));
}

int main(void)
{
	test_per_origin_seq_gate();
	test_seq_zero_not_replayable();
	test_per_origin_rate_limit();
	test_lru_eviction();
	test_null_safety();
	printf("sos_origin_table: all tests passed\n");
	return 0;
}
