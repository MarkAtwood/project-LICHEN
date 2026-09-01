/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/hal_storage_redundant.h>

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("FAIL: %s\n", msg);                             \
			failures++;                                            \
		}                                                              \
	} while (0)

static void test_storage_layer(void);
/* beads-worker-2 wrapper-API suite below (merged into this runner). */
static void run_wrapper_tests(void);

int main(void)
{
	const uint8_t magic[4] = { 'D', 'T', 'X', '2' };

	/* CRC-32 oracle vectors computed independently with zlib (CRC-32/ISO-HDLC,
	 * the identical reflected 0xEDB88320 algorithm the Rust crc32 implements).
	 */
	const uint8_t range20[20] = { 0, 1, 2,  3,  4,  5,  6,  7,  8,  9,
				      10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
	CHECK(lichen_hal_storage_crc32(range20, sizeof(range20)) == 0x3bddffa4u,
	      "crc32 of bytes 0..19 matches independent oracle");
	const uint8_t hdr[8] = { 'D', 'T', 'X', '2', 1, 0, 0, 0 };
	CHECK(lichen_hal_storage_crc32(hdr, sizeof(hdr)) == 0x9cefd8c3u,
	      "crc32 of DTX2 version header matches independent oracle");
	CHECK(lichen_hal_storage_crc32((const uint8_t *)"", 0) == 0x00000000u,
	      "crc32 of empty input is 0");

	/* Encode/parse roundtrip. */
	const uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef, 0x42 };
	uint8_t record[64];
	size_t len = lichen_hal_storage_encode_slot(magic, 7, payload,
						    sizeof(payload), record,
						    sizeof(record));
	CHECK(len == 20 + sizeof(payload) + 4, "encoded length is 24+payload");
	CHECK(memcmp(record, magic, 4) == 0, "magic at offset 0");
	CHECK(record[4] == 1, "version 1");
	CHECK(record[5] == 0 && record[6] == 0 && record[7] == 0, "reserved zero");
	CHECK(record[8] == 0 && record[15] == 7, "generation BE u64 = 7");
	CHECK(record[16] == 0 && record[19] == sizeof(payload),
	      "payload len BE u32");

	uint64_t generation = 0;
	const uint8_t *parsed = NULL;
	size_t parsed_len = 0;
	CHECK(lichen_hal_storage_parse_slot(record, len, magic, &generation,
					    &parsed, &parsed_len),
	      "roundtrip parses");
	CHECK(generation == 7 && parsed_len == sizeof(payload) &&
		      memcmp(parsed, payload, sizeof(payload)) == 0,
	      "roundtrip payload intact");

	/* CRC32 field must equal the C crc32 of the record prefix. */
	uint32_t stored_crc = ((uint32_t)record[len - 4] << 24) |
			      ((uint32_t)record[len - 3] << 16) |
			      ((uint32_t)record[len - 2] << 8) |
			      (uint32_t)record[len - 1];
	CHECK(stored_crc == lichen_hal_storage_crc32(record, len - 4),
	      "stored trailer is crc32 of prefix");

	/* Corruption: flip a payload bit -> parse rejects. */
	record[len - 6] ^= 0x01;
	CHECK(!lichen_hal_storage_parse_slot(record, len, magic, &generation,
					     &parsed, &parsed_len),
	      "bit-flipped payload rejected");
	record[len - 6] ^= 0x01;

	/* Wrong magic. */
	const uint8_t other_magic[4] = { 'X', 'T', 'X', '2' };
	CHECK(!lichen_hal_storage_parse_slot(record, len, other_magic,
					     &generation, &parsed, &parsed_len),
	      "wrong magic rejected");

	/* Truncated record. */
	CHECK(!lichen_hal_storage_parse_slot(record, len - 1, magic, &generation,
					     &parsed, &parsed_len),
	      "truncated record rejected");

	/* NULL pointers are rejected (documented contract). */
	CHECK(lichen_hal_storage_encode_slot(magic, 1, NULL, 0, record,
					     sizeof(record)) == 0,
	      "NULL payload rejected");
	CHECK(lichen_hal_storage_parse_slot(NULL, 0, magic, &generation,
					    &parsed, &parsed_len) == false,
	      "NULL raw rejected");

	/* Empty-payload roundtrip (minimum-size record). */
	uint8_t empty_rec[LICHEN_STORAGE_SLOT_HEADER_LEN +
			  LICHEN_STORAGE_SLOT_TRAILER_LEN];
	size_t empty_len = lichen_hal_storage_encode_slot(magic, 1, payload, 0,
							  empty_rec,
							  sizeof(empty_rec));
	CHECK(empty_len == sizeof(empty_rec), "empty payload encodes");
	uint8_t empty_probe[1];
	const uint8_t *empty_parsed = empty_probe;
	size_t empty_parsed_len = 1;
	CHECK(lichen_hal_storage_parse_slot(empty_rec, empty_len, magic,
					    &generation, &empty_parsed,
					    &empty_parsed_len),
	      "empty payload parses");
	CHECK(empty_parsed_len == 0, "empty payload length is 0");

	/* Version mismatch. */
	uint8_t bad_version[64];
	memcpy(bad_version, record, len);
	bad_version[4] = 2;
	CHECK(!lichen_hal_storage_parse_slot(bad_version, len, magic,
					     &generation, &parsed, &parsed_len),
	      "version != 1 rejected");

	/* Reserved bytes nonzero. */
	uint8_t bad_reserved[64];
	memcpy(bad_reserved, record, len);
	bad_reserved[6] = 0x01;
	CHECK(!lichen_hal_storage_parse_slot(bad_reserved, len, magic,
					     &generation, &parsed, &parsed_len),
	      "nonzero reserved rejected");

	/* Trailing garbage beyond the record (exact-length gate). */
	uint8_t padded[80];
	memcpy(padded, record, len);
	memset(&padded[len], 0xAA, sizeof(padded) - len);
	CHECK(!lichen_hal_storage_parse_slot(padded, sizeof(padded), magic,
					     &generation, &parsed, &parsed_len),
	      "trailing garbage rejected");

	/* Length-field mismatch (declared len lies). */
	uint8_t lying[64];
	memcpy(lying, record, len);
	lying[19] = 0xFF;
	CHECK(!lichen_hal_storage_parse_slot(lying, len, magic, &generation,
					     &parsed, &parsed_len),
	      "length-field mismatch rejected");

	/* Generation 0 is invalid on both encode and parse. */
	CHECK(lichen_hal_storage_encode_slot(magic, 0, payload, sizeof(payload),
					     record, sizeof(record)) == 0,
	      "generation 0 encode rejected");
	uint8_t zero_gen[64];
	size_t zero_len = lichen_hal_storage_encode_slot(
		magic, 1, payload, sizeof(payload), zero_gen, sizeof(zero_gen));
	memset(&zero_gen[8], 0, 8);
	CHECK(!lichen_hal_storage_parse_slot(zero_gen, zero_len, magic,
					     &generation, &parsed, &parsed_len),
	      "generation 0 parse rejected");

	/* Buffer too small. */
	uint8_t tiny[20];
	CHECK(lichen_hal_storage_encode_slot(magic, 1, payload, sizeof(payload),
					     tiny, sizeof(tiny)) == 0,
	      "small output buffer rejected");

	test_storage_layer();
	run_wrapper_tests();

	if (failures == 0) {
		printf("PASS: hal_storage_redundant slot codec\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
/* ------------------------------------------------------------------ */
/* Two-slot storage layer tests over an in-memory fake store.          */
/* ------------------------------------------------------------------ */

#include <errno.h>

#define NSLOTS 2
#define STORE_CAP 128

struct store {
	bool present[NSLOTS];
	uint8_t data[NSLOTS][STORE_CAP];
	size_t len[NSLOTS];
	bool fail_write_slot[NSLOTS];
};

static int store_read(void *user, const char *key, uint8_t *out,
		      size_t capacity, size_t *length)
{
	struct store *s = user;
	unsigned int idx = key[7] - 'a';

	if (idx >= NSLOTS || !s->present[idx]) {
		return 1;
	}
	size_t n = s->len[idx] < capacity ? s->len[idx] : capacity;
	memcpy(out, s->data[idx], n);
	*length = n;
	return 0;
}

static int store_write(void *user, const char *key, const uint8_t *value,
		       size_t length)
{
	struct store *s = user;
	unsigned int idx = key[7] - 'a';

	if (idx >= NSLOTS) {
		return -EINVAL;
	}
	if (s->fail_write_slot[idx]) {
		return -EIO;
	}
	if (length > STORE_CAP) {
		return -ENOSPC;
	}
	s->present[idx] = true;
	memcpy(s->data[idx], value, length);
	s->len[idx] = length;
	return 0;
}

static const struct lichen_hal_storage_ops store_ops = {
	.read = store_read,
	.write = store_write,
};

static const char *const keys[2] = { "rpl.tx.a", "rpl.tx.b" };

static void test_storage_layer(void)
{
	static const uint8_t magic[4] = { 'D', 'T', 'X', '2' };
	struct store s;
	uint8_t record[64];
	uint8_t scratch_a[64];
	uint8_t scratch_b[64];
	uint8_t out[64];
	size_t out_len = sizeof(out);
	struct lichen_hal_storage_value value;
	const uint8_t gen1[] = { 0x01, 0x01 };
	const uint8_t gen2[] = { 0x02, 0x02, 0x02 };
	const uint8_t gen3[] = { 0x03 };

	/* Empty store -> Missing. */
	memset(&s, 0, sizeof(s));
	CHECK(lichen_hal_storage_open_redundant(&store_ops, &s, keys, magic,
						scratch_a, sizeof(scratch_a),
						scratch_b, sizeof(scratch_b),
						out, &out_len,
						&value) ==
		      LICHEN_STORAGE_OPEN_MISSING,
	      "empty store opens as Missing");

	/* Provision at generation 1 into slot A. */
	CHECK(lichen_hal_storage_provision_redundant(
		      &store_ops, &s, keys, magic, gen1, sizeof(gen1), record,
		      sizeof(record)) == LICHEN_STORAGE_PROVISION_OK,
	      "provision succeeds");
	CHECK(s.present[0] && !s.present[1], "provision writes slot A only");

	/* Re-provision -> Exists, existing state untouched. */
	CHECK(lichen_hal_storage_provision_redundant(
		      &store_ops, &s, keys, magic, gen1, sizeof(gen1), record,
		      sizeof(record)) == LICHEN_STORAGE_PROVISION_EXISTS,
	      "re-provision is Exists");

	/* Open finds generation 1 in slot A. */
	CHECK(lichen_hal_storage_open_redundant(&store_ops, &s, keys, magic,
						scratch_a, sizeof(scratch_a),
						scratch_b, sizeof(scratch_b),
						out, &out_len,
						&value) == LICHEN_STORAGE_OPEN_OK,
	      "open after provision");
	CHECK(value.generation == 1 &&
		      value.slot == LICHEN_STORAGE_SLOT_A &&
		      value.len == sizeof(gen1) &&
		      memcmp(out, gen1, sizeof(gen1)) == 0,
	      "open returns generation 1 payload");

	/* Update alternation: B at gen 2, A at gen 3. */
	CHECK(lichen_hal_storage_update_redundant(&store_ops, &s, keys, magic,
						  &value, gen2, sizeof(gen2),
						  record, sizeof(record),
						  &value) ==
		      LICHEN_STORAGE_UPDATE_OK,
	      "update 1 -> 2 succeeds");
	CHECK(value.generation == 2 && value.slot == LICHEN_STORAGE_SLOT_B,
	      "update lands in slot B at gen 2");
	CHECK(lichen_hal_storage_update_redundant(&store_ops, &s, keys, magic,
						  &value, gen3, sizeof(gen3),
						  record, sizeof(record),
						  &value) ==
		      LICHEN_STORAGE_UPDATE_OK,
	      "update 2 -> 3 succeeds");
	CHECK(value.generation == 3 && value.slot == LICHEN_STORAGE_SLOT_A,
	      "update lands back in slot A at gen 3");

	/* Newest wins after alternation. */
	CHECK(lichen_hal_storage_open_redundant(&store_ops, &s, keys, magic,
						scratch_a, sizeof(scratch_a),
						scratch_b, sizeof(scratch_b),
						out, &out_len,
						&value) == LICHEN_STORAGE_OPEN_OK,
	      "open after alternation");
	CHECK(value.generation == 3 && value.slot == LICHEN_STORAGE_SLOT_A &&
		      value.len == sizeof(gen3),
	      "newest generation wins");

	/* Stale detection: replay an old (generation, slot). */
	struct lichen_hal_storage_value stale = { .generation = 1,
						  .slot =
							  LICHEN_STORAGE_SLOT_A };
	CHECK(lichen_hal_storage_update_redundant(&store_ops, &s, keys, magic,
						  &stale, gen1, sizeof(gen1),
						  record, sizeof(record),
						  &value) ==
		      LICHEN_STORAGE_UPDATE_STALE,
	      "stale generation rejected");

	/* Write failure surfaces as STORAGE_ERROR and leaves the previous
	 * slot intact (same as the Rust reference: no rollback, caller
	 * retries with the unchanged current value).
	 */
	s.fail_write_slot[1] = true;
	CHECK(lichen_hal_storage_update_redundant(&store_ops, &s, keys, magic,
						  &value, gen2, sizeof(gen2),
						  record, sizeof(record),
						  &value) ==
		      LICHEN_STORAGE_UPDATE_STORAGE_ERROR,
	      "write failure is STORAGE_ERROR");
	s.fail_write_slot[1] = false;
	CHECK(lichen_hal_storage_update_redundant(&store_ops, &s, keys, magic,
						  &value, gen2, sizeof(gen2),
						  record, sizeof(record),
						  &value) ==
		      LICHEN_STORAGE_UPDATE_OK,
	      "retry after write failure succeeds");
	CHECK(value.generation == 4 && value.slot == LICHEN_STORAGE_SLOT_B,
	      "retry wrote gen 4 to slot B");

	/* Corrupt store: present but unparseable -> Corrupt on open. */
	memset(&s, 0, sizeof(s));
	s.present[0] = true;
	memset(s.data[0], 0xEE, 24);
	s.len[0] = 24;
	CHECK(lichen_hal_storage_open_redundant(&store_ops, &s, keys, magic,
						scratch_a, sizeof(scratch_a),
						scratch_b, sizeof(scratch_b),
						out, &out_len,
						&value) ==
		      LICHEN_STORAGE_OPEN_CORRUPT,
	      "corrupt-only store is Corrupt");

	/* Corrupt on update: present but invalid -> Corrupt. */
	CHECK(lichen_hal_storage_update_redundant(
		      &store_ops, &s, keys, magic,
		      &(struct lichen_hal_storage_value){
			      .generation = 1,
			      .slot = LICHEN_STORAGE_SLOT_A },
		      gen1, sizeof(gen1), record, sizeof(record),
		      &value) == LICHEN_STORAGE_UPDATE_CORRUPT,
	      "corrupt store update is Corrupt");

	/* Generation exhaustion at u64 max (no wrap). */
	memset(&s, 0, sizeof(s));
	out_len = sizeof(out);
	uint8_t max_rec[64];
	size_t max_len = lichen_hal_storage_encode_slot(
		magic, UINT64_MAX, gen1, sizeof(gen1), max_rec, sizeof(max_rec));
	(void)max_len;
	/* Write the max-generation record directly as slot B. */
	s.present[1] = true;
	memcpy(s.data[1], max_rec, 24 + sizeof(gen1));
	s.len[1] = 24 + sizeof(gen1);
	int open_status = lichen_hal_storage_open_redundant(
		&store_ops, &s, keys, magic, scratch_a, sizeof(scratch_a),
		scratch_b, sizeof(scratch_b), out, &out_len, &value);
	CHECK(open_status == LICHEN_STORAGE_OPEN_OK,
	      "max generation opens");
	CHECK(value.generation == UINT64_MAX &&
		      value.slot == LICHEN_STORAGE_SLOT_B,
	      "max generation in slot B");
	CHECK(lichen_hal_storage_update_redundant(&store_ops, &s, keys, magic,
						  &value, gen2, sizeof(gen2),
						  record, sizeof(record),
						  &value) ==
		      LICHEN_STORAGE_UPDATE_EXHAUSTED,
	      "u64 generation max is Exhausted (no wrap)");

	/* Buffer-too-small on open. */
	memset(&s, 0, sizeof(s));
	lichen_hal_storage_provision_redundant(&store_ops, &s, keys, magic,
					       gen2, sizeof(gen2), record,
					       sizeof(record));
	uint8_t tiny[1];
	size_t tiny_len = sizeof(tiny);
	CHECK(lichen_hal_storage_open_redundant(&store_ops, &s, keys, magic,
						scratch_a, sizeof(scratch_a),
						scratch_b, sizeof(scratch_b),
						tiny, &tiny_len,
						&value) ==
		      LICHEN_STORAGE_OPEN_BUFFER_TOO_SMALL,
	      "small out buffer is BUFFER_TOO_SMALL");
}
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

/* Merge note: this was beads-worker-2's main(); the merged file keeps a
 * single entry point (the codec/storage main above), so the wrapper-API
 * suite runs as a callee. */
static void run_wrapper_tests(void)
{
	test_open_missing();
	test_provision_and_open();
	test_update_alternation_and_stale();
	test_generation_exhausted();
	test_corrupt_reported();
	test_write_failure_keeps_old_slot();
	test_record_buffer_too_small();
	printf("hal_storage_redundant tests passed\n");
}
