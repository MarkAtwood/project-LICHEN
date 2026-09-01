/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Two-slot redundant-record storage primitive (spec 09 14.2 persistence
 * foundation). C port of rust/lichen-hal/src/storage.rs
 * provision_redundant/open_redundant/update_redundant. Keys and magic are
 * caller-owned: this suite uses "rpl.tx.a"/"rpl.tx.b" and magic "DTX2" as
 * representative caller values. */

#include <lichen/hal_storage_redundant.h>

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define KEY_A "rpl.tx.a"
#define KEY_B "rpl.tx.b"
#define MAGIC "DTX2"
#define RECORD_CAP (LICHEN_REDUNDANT_SLOT_OVERHEAD + 64)
#define SLOT_CAP 128

/* Test-side IEEE CRC32 (same algorithm as the module under test). */
static uint32_t test_crc32(const uint8_t *data, size_t len)
{
	uint32_t crc = UINT32_MAX;
	for (size_t i = 0; i < len; i++) {
		crc ^= (uint32_t)data[i];
		for (int bit = 0; bit < 8; bit++) {
			uint32_t mask = 0U - (crc & 1U);
			crc = (crc >> 1) ^ (0xEDB88320U & mask);
		}
	}
	return ~crc;
}

/* Test-side slot encoder (same layout as the module under test), used to
 * seed storage with arbitrary generations for wrap/exhaustion fixtures. */
static size_t test_encode_slot(uint8_t *record, const uint8_t magic[4],
			       uint64_t generation, const uint8_t *payload,
			       size_t payload_len)
{
	record[0] = magic[0];
	record[1] = magic[1];
	record[2] = magic[2];
	record[3] = magic[3];
	record[4] = 1;
	memset(&record[5], 0, 3);
	for (int i = 0; i < 8; i++) {
		record[8 + i] = (uint8_t)(generation >> (56 - 8 * i));
	}
	uint32_t len_be = (uint32_t)payload_len;
	record[16] = (uint8_t)(len_be >> 24);
	record[17] = (uint8_t)(len_be >> 16);
	record[18] = (uint8_t)(len_be >> 8);
	record[19] = (uint8_t)len_be;
	memcpy(&record[20], payload, payload_len);
	uint32_t checksum = test_crc32(record, 20 + payload_len);
	uint8_t *trailer = &record[20 + payload_len];
	trailer[0] = (uint8_t)(checksum >> 24);
	trailer[1] = (uint8_t)(checksum >> 16);
	trailer[2] = (uint8_t)(checksum >> 8);
	trailer[3] = (uint8_t)checksum;
	return 20 + payload_len + 4;
}

/* In-memory key/value storage double with write-failure injection. */
struct mem_store {
	uint8_t data[2][SLOT_CAP];
	size_t len[2];
	bool present[2];
	bool fail_next_write;
};

static struct mem_store s_store;

static void mem_reset(void)
{
	memset(&s_store, 0, sizeof(s_store));
}

static int mem_read(void *user, const char *key, uint8_t *out, size_t cap,
		    size_t *len)
{
	(void)user;
	int idx = (strcmp(key, KEY_B) == 0) ? 1 : 0;
	if (!s_store.present[idx]) {
		return 1;
	}
	size_t n = s_store.len[idx] < cap ? s_store.len[idx] : cap;
	memcpy(out, s_store.data[idx], n);
	*len = s_store.len[idx]; /* full stored length per the ops contract */
	return 0;
}

static int mem_write(void *user, const char *key, const uint8_t *value,
		     size_t len)
{
	(void)user;
	if (s_store.fail_next_write) {
		s_store.fail_next_write = false;
		return -5; /* -EIO */
	}
	int idx = (strcmp(key, KEY_B) == 0) ? 1 : 0;
	assert(len <= SLOT_CAP);
	memcpy(s_store.data[idx], value, len);
	s_store.len[idx] = len;
	s_store.present[idx] = true;
	return 0;
}

static const struct lichen_hal_redundant_ops s_ops = {
	.read = mem_read,
	.write = mem_write,
};

static const char *s_keys[2] = { KEY_A, KEY_B };

static void test_open_missing(void)
{
	mem_reset();
	uint8_t slot_a[SLOT_CAP];
	uint8_t slot_b[SLOT_CAP];
	uint8_t out[64];
	struct lichen_hal_redundant_value value;

	assert(lichen_hal_redundant_open(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       slot_a, slot_b, sizeof(slot_a), out, sizeof(out),
		       &value) == LICHEN_HAL_REDUNDANT_OPEN_MISSING);
}

static void test_provision_and_open(void)
{
	mem_reset();
	uint8_t record[RECORD_CAP];
	const uint8_t payload[] = { 1, 2, 3 };

	assert(lichen_hal_redundant_provision(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       payload, sizeof(payload), record, sizeof(record)) ==
	       LICHEN_HAL_REDUNDANT_PROVISION_OK);

	/* Provision again -> Exists. */
	assert(lichen_hal_redundant_provision(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       payload, sizeof(payload), record, sizeof(record)) ==
	       LICHEN_HAL_REDUNDANT_PROVISION_EXISTS);

	uint8_t slot_a[SLOT_CAP];
	uint8_t slot_b[SLOT_CAP];
	uint8_t out[64];
	struct lichen_hal_redundant_value value;
	assert(lichen_hal_redundant_open(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       slot_a, slot_b, sizeof(slot_a), out, sizeof(out),
		       &value) == LICHEN_HAL_REDUNDANT_OPEN_OK);
	assert(value.generation == 1);
	assert(value.slot == 0);
	assert(value.len == sizeof(payload));
	assert(out[0] == 1 && out[1] == 2 && out[2] == 3);
}

static void test_update_alternation_and_stale(void)
{
	mem_reset();
	uint8_t record[RECORD_CAP];
	uint8_t slot_a[SLOT_CAP];
	uint8_t slot_b[SLOT_CAP];
	uint8_t out[64];
	struct lichen_hal_redundant_value value;

	const uint8_t p1[] = { 10 };
	assert(lichen_hal_redundant_provision(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC, p1,
		       sizeof(p1), record, sizeof(record)) ==
	       LICHEN_HAL_REDUNDANT_PROVISION_OK);
	struct lichen_hal_redundant_value current = {
		.generation = 1, .slot = 0, .len = sizeof(p1)
	};

	/* Update 1: writes slot B, generation 2. */
	const uint8_t p2[] = { 20 };
	struct lichen_hal_redundant_value next;
	assert(lichen_hal_redundant_update(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       &current, p2, sizeof(p2), record, sizeof(record),
		       &next) == LICHEN_HAL_REDUNDANT_UPDATE_OK);
	assert(next.generation == 2 && next.slot == 1);
	current = next;

	/* Update 2: writes slot A, generation 3 (alternation a/b/a). */
	const uint8_t p3[] = { 30 };
	assert(lichen_hal_redundant_update(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       &current, p3, sizeof(p3), record, sizeof(record),
		       &next) == LICHEN_HAL_REDUNDANT_UPDATE_OK);
	assert(next.generation == 3 && next.slot == 0);
	current = next;

	/* Open returns generation 3 payload. */
	assert(lichen_hal_redundant_open(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       slot_a, slot_b, sizeof(slot_a), out, sizeof(out),
		       &value) == LICHEN_HAL_REDUNDANT_OPEN_OK);
	assert(value.generation == 3 && out[0] == 30);

	/* Stale: caller claims generation 1/slot 0 while storage is at 3. */
	struct lichen_hal_redundant_value stale = {
		.generation = 1, .slot = 0, .len = 1
	};
	const uint8_t p4[] = { 40 };
	assert(lichen_hal_redundant_update(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       &stale, p4, sizeof(p4), record, sizeof(record),
		       &next) == LICHEN_HAL_REDUNDANT_UPDATE_STALE);
}

static void test_generation_exhausted(void)
{
	/* Drive storage to generation UINT64_MAX with a hand-encoded valid
	 * slot, then update: generation+1 overflows -> EXHAUSTED (no wrap
	 * to generation 0). */
	mem_reset();
	uint8_t raw[SLOT_CAP];
	const uint8_t magic[4] = { 'D', 'T', 'X', '2' };
	const uint8_t p[] = { 1 };
	size_t len = test_encode_slot(raw, magic, UINT64_MAX, p, sizeof(p));
	s_store.len[0] = len;
	s_store.present[0] = true;
	memcpy(s_store.data[0], raw, len);

	struct lichen_hal_redundant_value current = {
		.generation = UINT64_MAX, .slot = 0, .len = sizeof(p)
	};
	uint8_t record[RECORD_CAP];
	struct lichen_hal_redundant_value next;
	assert(lichen_hal_redundant_update(
		       &s_store, &s_ops, s_keys, magic, &current, p, sizeof(p),
		       record, sizeof(record), &next) ==
	       LICHEN_HAL_REDUNDANT_UPDATE_EXHAUSTED);
}

static void test_corrupt_reported(void)
{
	/* A present slot with a broken checksum opens as CORRUPT (not
	 * MISSING), preserving the Rust taxonomy. */
	mem_reset();
	uint8_t raw[SLOT_CAP];
	const uint8_t magic[4] = { 'D', 'T', 'X', '2' };
	const uint8_t p[] = { 1 };
	size_t len = test_encode_slot(raw, magic, 1, p, sizeof(p));
	s_store.len[0] = len;
	s_store.present[0] = true;
	memcpy(s_store.data[0], raw, len);
	s_store.data[0][22] ^= 0xff; /* corrupt payload byte */

	uint8_t slot_a[SLOT_CAP];
	uint8_t slot_b[SLOT_CAP];
	uint8_t out[64];
	struct lichen_hal_redundant_value value;
	assert(lichen_hal_redundant_open(
		       &s_store, &s_ops, s_keys, magic, slot_a, slot_b,
		       sizeof(slot_a), out, sizeof(out), &value) ==
	       LICHEN_HAL_REDUNDANT_OPEN_CORRUPT);
}

static void test_write_failure_keeps_old_slot(void)
{
	/* Rust semantics: write failure -> Storage error, old slot intact
	 * (no explicit rollback; the alternating-slot design preserves the
	 * previous generation by construction). */
	mem_reset();
	uint8_t record[RECORD_CAP];
	const uint8_t p1[] = { 10 };
	assert(lichen_hal_redundant_provision(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC, p1,
		       sizeof(p1), record, sizeof(record)) ==
	       LICHEN_HAL_REDUNDANT_PROVISION_OK);
	struct lichen_hal_redundant_value current = {
		.generation = 1, .slot = 0, .len = sizeof(p1)
	};

	const uint8_t p2[] = { 20 };
	s_store.fail_next_write = true;
	struct lichen_hal_redundant_value next;
	assert(lichen_hal_redundant_update(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       &current, p2, sizeof(p2), record, sizeof(record),
		       &next) == LICHEN_HAL_REDUNDANT_UPDATE_STORAGE);

	/* Old generation still opens intact. */
	uint8_t slot_a[SLOT_CAP];
	uint8_t slot_b[SLOT_CAP];
	uint8_t out[64];
	struct lichen_hal_redundant_value value;
	assert(lichen_hal_redundant_open(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC,
		       slot_a, slot_b, sizeof(slot_a), out, sizeof(out),
		       &value) == LICHEN_HAL_REDUNDANT_OPEN_OK);
	assert(value.generation == 1 && value.slot == 0 && out[0] == 10);
}

static void test_record_buffer_too_small(void)
{
	mem_reset();
	const uint8_t p[] = { 1, 2, 3 };
	uint8_t tiny[LICHEN_REDUNDANT_SLOT_OVERHEAD + 1];
	assert(lichen_hal_redundant_provision(
		       &s_store, &s_ops, s_keys, (const uint8_t *)MAGIC, p,
		       sizeof(p), tiny, sizeof(tiny)) ==
	       LICHEN_HAL_REDUNDANT_PROVISION_ENCODE);
}

int main(void)
{
	test_open_missing();
	test_provision_and_open();
	test_update_alternation_and_stale();
	test_generation_exhausted();
	test_corrupt_reported();
	test_write_failure_keeps_old_slot();
	test_record_buffer_too_small();
	printf("hal_storage_redundant tests passed\n");
	return 0;
}
