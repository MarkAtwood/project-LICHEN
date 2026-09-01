/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/redundant_slot.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define KEY_A "rpl.tx.a"
#define KEY_B "rpl.tx.b"
#define RECORD_CAP 64

static const char *KEYS[2] = {KEY_A, KEY_B};
static const uint8_t MAGIC[4] = {'D', 'T', 'X', '2'};
static const uint8_t PAYLOAD_9[] = {'1', '2', '3', '4', '5',
				    '6', '7', '8', '9'};
static const uint8_t PAYLOAD_2[] = {0xAA, 0xBB};

/* In-memory two-slot fake with injectable write failures. */
struct fake {
	uint8_t a[64];
	int a_len;
	uint8_t b[64];
	int b_len;
	int fail_writes; /* countdown: next N writes fail -EIO */
};

static struct fake g_fake;

static int fake_read(void *user, const char *key, uint8_t *out, size_t cap)
{
	(void)user;
	struct fake *f = &g_fake;
	const uint8_t *src = NULL;
	int len = 0;

	if (strcmp(key, KEY_A) == 0) {
		src = f->a;
		len = f->a_len;
	} else if (strcmp(key, KEY_B) == 0) {
		src = f->b;
		len = f->b_len;
	}
	if (len <= 0) {
		return 0; /* absent */
	}
	size_t n = (size_t)len < cap ? (size_t)len : cap;
	memcpy(out, src, n);
	return (int)n;
}

static int fake_write(void *user, const char *key, const uint8_t *data,
		      size_t len)
{
	(void)user;
	struct fake *f = &g_fake;
	if (f->fail_writes > 0) {
		f->fail_writes--;
		return -EIO;
	}
	if (strcmp(key, KEY_A) == 0) {
		memcpy(f->a, data, len);
		f->a_len = (int)len;
	} else if (strcmp(key, KEY_B) == 0) {
		memcpy(f->b, data, len);
		f->b_len = (int)len;
	} else {
		return -EINVAL;
	}
	return 0;
}

static const struct lichen_redundant_io g_io = {fake_read, fake_write, NULL};

/* CRC32 is bit-exact with the Rust lichen-hal storage.rs crc32
 * (CRC-32/ISO-HDLC): crc32("123456789") = 0xCBF43926. Provision a record
 * with that payload and pin the trailer bytes. */
static void test_crc32_bit_exact_with_rust(void)
{
	uint8_t record[RECORD_CAP];

	memset(&g_fake, 0, sizeof(g_fake));
	assert(lichen_redundant_provision(&g_io, KEYS, MAGIC, PAYLOAD_9,
					  sizeof(PAYLOAD_9), record,
					  sizeof(record)) == 0);
	/* Record: 20-byte header + 9-byte payload + 4-byte trailer = 33. */
	uint32_t trailer = ((uint32_t)record[29] << 24) |
			   ((uint32_t)record[30] << 16) |
			   ((uint32_t)record[31] << 8) | (uint32_t)record[32];
	assert(trailer == 0xBD88FA92U);
}

static void test_empty_open_is_missing(void)
{
	memset(&g_fake, 0, sizeof(g_fake));
	struct lichen_redundant_value v = {0};
	uint8_t record[RECORD_CAP];

	int ret = lichen_redundant_open(&g_io, KEYS, MAGIC, record,
					sizeof(record), record, sizeof(record),
					record, sizeof(record), &v);
	assert(ret == -ENOENT);
}

static void test_provision_then_exists(void)
{
	memset(&g_fake, 0, sizeof(g_fake));
	uint8_t record[RECORD_CAP];
	struct lichen_redundant_value v = {0};

	assert(lichen_redundant_provision(&g_io, KEYS, MAGIC, PAYLOAD_9,
					  sizeof(PAYLOAD_9), record,
					  sizeof(record)) == 0);
	assert(lichen_redundant_provision(&g_io, KEYS, MAGIC, PAYLOAD_9,
					  sizeof(PAYLOAD_9), record,
					  sizeof(record)) == -EEXIST);
	uint8_t read_a[RECORD_CAP];
	uint8_t read_b[RECORD_CAP];
	assert(lichen_redundant_open(&g_io, KEYS, MAGIC, read_a,
				     sizeof(read_a), read_b, sizeof(read_b),
				     record, sizeof(record), &v) == 0);
	assert(v.generation == 1 && v.slot == 0 && v.len == 9);
}

static void test_update_alternation(void)
{
	memset(&g_fake, 0, sizeof(g_fake));
	uint8_t record[RECORD_CAP];
	struct lichen_redundant_value v = {0};

	assert(lichen_redundant_provision(&g_io, KEYS, MAGIC, PAYLOAD_9,
					  sizeof(PAYLOAD_9), record,
					  sizeof(record)) == 0);
	/* Open fills v with the provisioned generation/slot. */
	uint8_t read_a[RECORD_CAP];
	uint8_t read_b[RECORD_CAP];
	assert(lichen_redundant_open(&g_io, KEYS, MAGIC, read_a,
				     sizeof(read_a), read_b, sizeof(read_b),
				     record, sizeof(record), &v) == 0);
	/* gen 2 -> opposite slot (1) */
	assert(lichen_redundant_update(&g_io, KEYS, MAGIC, &v, PAYLOAD_2,
				       sizeof(PAYLOAD_2), record,
				       sizeof(record), &v) == 0);
	assert(v.generation == 2 && v.slot == 1 && v.len == sizeof(PAYLOAD_2));
	/* gen 3 -> back to slot 0 */
	assert(lichen_redundant_update(&g_io, KEYS, MAGIC, &v, PAYLOAD_9,
				       sizeof(PAYLOAD_9), record,
				       sizeof(record), &v) == 0);
	assert(v.generation == 3 && v.slot == 0);
}

static void test_corrupt_current_is_stale(void)
{
	memset(&g_fake, 0, sizeof(g_fake));
	uint8_t record[RECORD_CAP];
	struct lichen_redundant_value v = {0};

	assert(lichen_redundant_provision(&g_io, KEYS, MAGIC, PAYLOAD_9,
					  sizeof(PAYLOAD_9), record,
					  sizeof(record)) == 0);
	uint8_t read_a[RECORD_CAP];
	uint8_t read_b[RECORD_CAP];
	assert(lichen_redundant_open(&g_io, KEYS, MAGIC, read_a,
				     sizeof(read_a), read_b, sizeof(read_b),
				     record, sizeof(record), &v) == 0);
	uint8_t p2[] = {0xAA};
	assert(lichen_redundant_update(&g_io, KEYS, MAGIC, &v, p2, sizeof(p2),
				       record, sizeof(record), &v) == 0);
	/* gen 2 lives in slot 1; corrupt its payload -> slot 0 (gen 1) is
	 * the newest valid slot: != current -> Stale. */
	g_fake.b[20] ^= 0xFF;
	int ret = lichen_redundant_update(&g_io, KEYS, MAGIC, &v, p2,
					  sizeof(p2), record, sizeof(record),
					  &v);
	assert(ret == -ESTALE);
}

static void test_corrupt_both_is_corrupt(void)
{
	memset(&g_fake, 0, sizeof(g_fake));
	uint8_t record[RECORD_CAP];
	struct lichen_redundant_value v = {0};

	assert(lichen_redundant_provision(&g_io, KEYS, MAGIC, PAYLOAD_9,
					  sizeof(PAYLOAD_9), record,
					  sizeof(record)) == 0);
	uint8_t read_a[RECORD_CAP];
	uint8_t read_b[RECORD_CAP];
	assert(lichen_redundant_open(&g_io, KEYS, MAGIC, read_a,
				     sizeof(read_a), read_b, sizeof(read_b),
				     record, sizeof(record), &v) == 0);
	assert(lichen_redundant_update(&g_io, KEYS, MAGIC, &v, PAYLOAD_2,
				       sizeof(PAYLOAD_2), record,
				       sizeof(record), &v) == 0);
	/* Corrupt payload byte in BOTH slots -> Corrupt (-EIO). */
	g_fake.a[20] ^= 0xFF;
	g_fake.b[20] ^= 0xFF;
	int ret = lichen_redundant_update(&g_io, KEYS, MAGIC, &v, PAYLOAD_2,
					  sizeof(PAYLOAD_2), record,
					  sizeof(record), &v);
	assert(ret == -EIO);
}

static void test_stale_via_slot_drop(void)
{
	memset(&g_fake, 0, sizeof(g_fake));
	uint8_t record[RECORD_CAP];
	struct lichen_redundant_value v = {0};

	assert(lichen_redundant_provision(&g_io, KEYS, MAGIC, PAYLOAD_9,
					  sizeof(PAYLOAD_9), record,
					  sizeof(record)) == 0);
	uint8_t read_a[RECORD_CAP];
	uint8_t read_b[RECORD_CAP];
	assert(lichen_redundant_open(&g_io, KEYS, MAGIC, read_a,
				     sizeof(read_a), read_b, sizeof(read_b),
				     record, sizeof(record), &v) == 0);
	uint8_t p2[] = {0xAA};
	assert(lichen_redundant_update(&g_io, KEYS, MAGIC, &v, p2, sizeof(p2),
				       record, sizeof(record), &v) == 0);
	/* gen 2 lives in slot 1; drop slot 1 (the CURRENT slot) -> newest is
	 * slot 0 (gen 1) != current(gen 2, slot 1) -> Stale. */
	g_fake.b_len = 0;
	int ret = lichen_redundant_update(&g_io, KEYS, MAGIC, &v, p2,
					  sizeof(p2), record, sizeof(record),
					  &v);
	assert(ret == -ESTALE);
}

static void test_generation_wrap_is_exhausted(void)
{
	memset(&g_fake, 0, sizeof(g_fake));
	uint8_t record[RECORD_CAP];
	struct lichen_redundant_value v = {0};

	/* Hand-build the max-generation record (u64 generation, 1-byte
	 * payload); trailer CRC pinned from the Rust crc32 probe. */
	uint8_t rec[25];
	rec[0] = 'D';
	rec[1] = 'T';
	rec[2] = 'X';
	rec[3] = '2';
	rec[4] = 1;
	rec[5] = 0;
	rec[6] = 0;
	rec[7] = 0;
	for (int i = 0; i < 8; i++) {
		rec[8 + i] = 0xFF;
	}
	rec[16] = 0;
	rec[17] = 0;
	rec[18] = 0;
	rec[19] = 1;
	rec[20] = 0x42;
	uint32_t crc = 0xF207A135U; /* crc32 over rec[0..20] (Rust probed) */
	rec[21] = (uint8_t)(crc >> 24);
	rec[22] = (uint8_t)(crc >> 16);
	rec[23] = (uint8_t)(crc >> 8);
	rec[24] = (uint8_t)crc;
	memcpy(g_fake.a, rec, sizeof(rec));
	g_fake.a_len = (int)sizeof(rec);

	struct lichen_redundant_value current = {
		.generation = UINT64_MAX,
		.slot = 0,
		.len = 1,
	};
	int ret = lichen_redundant_update(&g_io, KEYS, MAGIC, &current,
					  PAYLOAD_9, sizeof(PAYLOAD_9), record,
					  sizeof(record), &v);
	assert(ret == -EOVERFLOW);
}

static void test_rollback_on_write_failure(void)
{
	memset(&g_fake, 0, sizeof(g_fake));
	uint8_t record[RECORD_CAP];
	struct lichen_redundant_value v = {0};

	assert(lichen_redundant_provision(&g_io, KEYS, MAGIC, PAYLOAD_9,
					  sizeof(PAYLOAD_9), record,
					  sizeof(record)) == 0);
	assert(lichen_redundant_open(&g_io, KEYS, MAGIC, record,
				     sizeof(record), record, sizeof(record),
				     record, sizeof(record), &v) == 0);
	/* gen 2 -> slot 1 succeeds; gen 3 -> slot 0 write fails -EIO. */
	assert(lichen_redundant_update(&g_io, KEYS, MAGIC, &v, PAYLOAD_2,
				       sizeof(PAYLOAD_2), record,
				       sizeof(record), &v) == 0);
	g_fake.fail_writes = 1;
	assert(lichen_redundant_update(&g_io, KEYS, MAGIC, &v, PAYLOAD_2,
				       sizeof(PAYLOAD_2), record,
				       sizeof(record), &v) == -EIO);
	/* Storage state unchanged: newest is still gen 2 slot 1. */
	uint8_t read_a[RECORD_CAP];
	uint8_t read_b[RECORD_CAP];
	assert(lichen_redundant_open(&g_io, KEYS, MAGIC, read_a,
				     sizeof(read_a), read_b, sizeof(read_b),
				     record, sizeof(record), &v) == 0);
	assert(v.generation == 2 && v.slot == 1 && v.len == sizeof(PAYLOAD_2));
}

int main(void)
{
	test_crc32_bit_exact_with_rust();
	test_empty_open_is_missing();
	test_provision_then_exists();
	test_update_alternation();
	test_corrupt_current_is_stale();
	test_corrupt_both_is_corrupt();
	test_stale_via_slot_drop();
	test_generation_wrap_is_exhausted();
	test_rollback_on_write_failure();
	printf("redundant_slot tests passed\n");
	return 0;
}
