/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/coap_slot_coord.h>
#include <zephyr/settings/settings.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

void lichen_slot_claim_seq_test_reset(void);

#define ROOT "lichen/slot_claim"
#define ENTRY_MAX 16U

struct stored_entry {
	char name[64];
	uint8_t value[4];
	size_t len;
};

static struct stored_entry store[ENTRY_MAX];
static size_t store_count;
static int save_error;
static int load_error;
static int init_error;

static test_settings_set_handler_t get_handler(void)
{
	assert(test_settings_set_handler != NULL);
	return test_settings_set_handler;
}

static ssize_t read_entry(void *cb_arg, void *data, size_t len)
{
	const struct stored_entry *e = cb_arg;
	size_t count = e->len < len ? e->len : len;

	memcpy(data, e->value, count);
	return (ssize_t)count;
}

int settings_subsys_init(void)
{
	return init_error;
}

int settings_load_subtree(const char *subtree)
{
	size_t prefix_len = strlen(subtree) + 1U;

	assert(strcmp(subtree, ROOT) == 0);
	if (load_error != 0) {
		return load_error;
	}
	for (size_t i = 0; i < store_count; i++) {
		(void)get_handler()(&store[i].name[prefix_len],
				    store[i].len, read_entry, &store[i]);
	}
	return 0;
}

int settings_delete(const char *name)
{
	if (save_error != 0) {
		return save_error;
	}
	for (size_t i = 0; i < store_count; i++) {
		if (strcmp(store[i].name, name) == 0) {
			store[i] = store[store_count - 1];
			store_count--;
			return 0;
		}
	}
	return -ENOENT;
}

int settings_save_one(const char *name, const void *value, size_t len)
{
	if (save_error != 0) {
		return save_error;
	}
	assert(len <= sizeof(store[0].value));
	for (size_t i = 0; i < store_count; i++) {
		if (strcmp(store[i].name, name) == 0) {
			memcpy(store[i].value, value, len);
			store[i].len = len;
			return 0;
		}
	}
	assert(store_count < ENTRY_MAX);
	assert(strlen(name) < sizeof(store[0].name));
	strcpy(store[store_count].name, name);
	memcpy(store[store_count].value, value, len);
	store[store_count].len = len;
	store_count++;
	return 0;
}

static void reset_all(void)
{
	memset(store, 0, sizeof(store));
	store_count = 0U;
	save_error = 0;
	load_error = 0;
	init_error = 0;
	lichen_slot_claim_seq_test_reset();
}

static uint32_t stored_seq_of(const char *hex_name)
{
	size_t root_len = strlen(ROOT);

	for (size_t i = 0; i < store_count; i++) {
		if (strncmp(store[i].name, ROOT "/", root_len + 1U) != 0) {
			continue;
		}
		if (strcmp(&store[i].name[root_len + 1U], hex_name) == 0) {
			return (uint32_t)store[i].value[0] |
			       ((uint32_t)store[i].value[1] << 8) |
			       ((uint32_t)store[i].value[2] << 16) |
			       ((uint32_t)store[i].value[3] << 24);
		}
	}
	assert(0 && "entry not found in simulated store");
	return 0;
}

static void test_first_claim_has_no_floor(void)
{
	uint8_t iid[8] = {0xA0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t seq = 0U;

	reset_all();
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == -ENOENT);
}

static void test_roundtrip_and_persist_order(void)
{
	uint8_t iid[8] = {0xA1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t seq = 0U;

	reset_all();
	assert(lichen_slot_claim_seq_commit(iid, 42U) == 0);
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == 0);
	assert(seq == 42U);
	/* Persist-first contract: the NV copy exists immediately */
	assert(stored_seq_of("a101020304050607") == 42U);
}

static void test_monotonic_commit(void)
{
	uint8_t iid[8] = {0xA2, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t seq = 0U;

	reset_all();
	assert(lichen_slot_claim_seq_commit(iid, 5U) == 0);
	/* Stale commit must never regress the floor */
	assert(lichen_slot_claim_seq_commit(iid, 3U) == 0);
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == 0);
	assert(seq == 5U);
	assert(stored_seq_of("a201020304050607") == 5U);
	assert(lichen_slot_claim_seq_commit(iid, 7U) == 0);
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == 0);
	assert(seq == 7U);
	/* Advancing commit also persists immediately (persist-first) */
	assert(stored_seq_of("a201020304050607") == 7U);
}

static void test_reboot_persistence(void)
{
	uint8_t iid_a[8] = {0xA3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint8_t iid_b[8] = {0xB3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t seq = 0U;

	reset_all();
	assert(lichen_slot_claim_seq_commit(iid_a, 9U) == 0);
	assert(lichen_slot_claim_seq_commit(iid_b, 3U) == 0);

	/* Simulated reboot: RAM cache lost, NV store intact */
	lichen_slot_claim_seq_test_reset();
	assert(lichen_slot_claim_seq_lookup(iid_a, &seq) == 0);
	assert(seq == 9U);
	assert(lichen_slot_claim_seq_lookup(iid_b, &seq) == 0);
	assert(seq == 3U);
	assert(lichen_slot_claim_seq_lookup(iid_a, &seq) == 0);
	assert(seq == 9U);
}

static void seed_store_entry(const char *hex_name, uint32_t seq, size_t len)
{
	assert(store_count < ENTRY_MAX);
	strcpy(store[store_count].name, ROOT "/");
	strcat(store[store_count].name, hex_name);
	store[store_count].value[0] = (uint8_t)(seq & 0xFFU);
	store[store_count].value[1] = (uint8_t)((seq >> 8) & 0xFFU);
	store[store_count].value[2] = (uint8_t)((seq >> 16) & 0xFFU);
	store[store_count].value[3] = (uint8_t)((seq >> 24) & 0xFFU);
	store[store_count].len = len;
	store_count++;
}

static void test_cache_overflow_drops_excess(void)
{
	uint32_t seq = 0U;

	reset_all();
	/* Seed more stored gateways than the cache holds (MAX_GATEWAYS=8) */
	for (uint8_t i = 0; i < 10U; i++) {
		char hex[17];

		snprintf(hex, sizeof(hex), "c0%02x000000000000", i);
		seed_store_entry(hex, 100U + i, 4U);
	}

	lichen_slot_claim_seq_test_reset();
	/* First eight (load order) are cached... */
	uint8_t iid0[8] = {0xC0, 0, 0, 0, 0, 0, 0, 0};

	assert(lichen_slot_claim_seq_lookup(iid0, &seq) == 0);
	assert(seq == 100U);
	/* ...overflow entries are not; their gate fail-opens (lookup
	 * -ENOENT) until the persist cache frees capacity. Fail-closed
	 * commit protection below bounds the damage. */
	uint8_t iid9[8] = {0xC0, 9, 0, 0, 0, 0, 0, 0};

	assert(lichen_slot_claim_seq_lookup(iid9, &seq) == -ENOENT);
	/* Commit for an uncached IID must FAIL CLOSED: without a cached
	 * floor monotonicity cannot be enforced, and the write could
	 * regress the persisted floor (e.g. iid9's NV copy of 109). The
	 * NV store must be untouched. */
	uint8_t iid_new[8] = {0xDD, 1, 0, 0, 0, 0, 0, 0};

	assert(lichen_slot_claim_seq_commit(iid_new, 7U) == -ENOBUFS);
	assert(lichen_slot_claim_seq_lookup(iid_new, &seq) == -ENOENT);
	assert(stored_seq_of("c009000000000000") == 109U);
	/* Stale commit for the same uncached (overflow) gateway must also
	 * refuse to write, never regressing its persisted floor. */
	uint8_t iid_stale[8] = {0xC0, 8, 0, 0, 0, 0, 0, 0};

	assert(lichen_slot_claim_seq_commit(iid_stale, 5U) == -ENOBUFS);
	assert(stored_seq_of("c008000000000000") == 108U);
}

static void test_corrupt_names_skipped(void)
{
	uint8_t iid[8] = {0xE0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t seq = 0U;

	reset_all();
	/* Non-hex and wrong-length entry names are ignored at load */
	seed_store_entry("zz", 1U, 4U);
	seed_store_entry("e001020304050607", 77U, 4U);

	lichen_slot_claim_seq_test_reset();
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == 0);
	assert(seq == 77U);
}

static void test_wrong_value_len_rejected(void)
{
	uint8_t iid[8] = {0xF0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t seq = 0U;

	reset_all();
	seed_store_entry("f001020304050607", 5U, 3U); /* corrupt: not uint32 */

	lichen_slot_claim_seq_test_reset();
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == -ENOENT);
}

static void test_save_failure_propagates(void)
{
	uint8_t iid[8] = {0xF1, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t seq = 0U;

	reset_all();
	save_error = -ENOSPC;
	/* Persist-first: a failed NV write must not report success */
	assert(lichen_slot_claim_seq_commit(iid, 11U) == -ENOSPC);
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == -ENOENT);
}

static void test_load_failure_propagates(void)
{
	uint8_t iid[8] = {0xF2, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t seq = 0U;

	reset_all();
	load_error = -EIO;
	/* Defensive contract: if the settings layer ever reports a load
	 * error, both operations fail closed (no floor, no write). Note
	 * real Zephyr's settings_load_subtree swallows per-entry backend
	 * errors and returns 0; only settings_subsys_init failures are
	 * reliably reported on hardware. */
	assert(lichen_slot_claim_seq_commit(iid, 11U) == -EIO);
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == -EIO);
}

static void test_subsys_init_failure_propagates(void)
{
	uint8_t iid[8] = {0xF3, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
	uint32_t seq = 0U;

	reset_all();
	init_error = -EIO;
	/* settings_subsys_init failure (e.g. missing NVS partition) is the
	 * one load error genuinely reachable on hardware: both paths must
	 * fail closed, and state must recover once init succeeds. */
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == -EIO);
	assert(lichen_slot_claim_seq_commit(iid, 11U) == -EIO);
	init_error = 0;
	assert(lichen_slot_claim_seq_commit(iid, 11U) == 0);
	assert(lichen_slot_claim_seq_lookup(iid, &seq) == 0);
	assert(seq == 11U);
}

int main(void)
{
	test_first_claim_has_no_floor();
	test_roundtrip_and_persist_order();
	test_monotonic_commit();
	test_reboot_persistence();
	test_cache_overflow_drops_excess();
	test_corrupt_names_skipped();
	test_wrong_value_len_rejected();
	test_save_failure_propagates();
	test_load_failure_propagates();
	test_subsys_init_failure_propagates();
	printf("slot_claim_settings: all tests passed\n");
	return 0;
}
