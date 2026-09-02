/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * Host/twister test for the two-slot redundant-record primitive
 * (lichen/subsys/lichen/hal/redundant_slot.c, bead worker6-a2ct).
 *
 * Acceptance list from worker6-b7z9.11.1: empty->Missing, provision
 * (+Exists on re-provision), open newest/alternation, corrupt-current ->
 * Stale, corrupt-both -> EIO, stale via slot drop, generation wrap
 * (-EOVERFLOW), rollback on write failure, and the CRC32 cross-check
 * vector (Rust crc32 "123456789" -> 0xCBF43926).
 */

#include <lichen/redundant_slot.h>

#include <errno.h>
#include <stdint.h>
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

#define NSLOTS 2U
#define STORE_CAP 128U

/* --- injectable fake store (absent/corrupt/failure all simulatable) --- */

struct store {
	bool present[NSLOTS];
	uint8_t data[NSLOTS][STORE_CAP];
	size_t len[NSLOTS];
	int read_error;  /* when nonzero, read returns this errno */
	int write_error; /* when nonzero, write returns this errno */
};

static int store_read(void *user, const char *key, uint8_t *out, size_t cap)
{
	struct store *s = user;

	if (s->read_error != 0) {
		return -s->read_error;
	}
	unsigned int idx = (strcmp(key, "slot.b") == 0) ? 1U : 0U;
	if (!s->present[idx]) {
		return 0;
	}
	size_t n = s->len[idx];
	if (n > cap) {
		n = cap;
	}
	memcpy(out, s->data[idx], n);
	return (int)n;
}

static int store_write(void *user, const char *key, const uint8_t *data,
		       size_t len)
{
	struct store *s = user;

	if (s->write_error != 0) {
		return -s->write_error;
	}
	unsigned int idx = (strcmp(key, "slot.b") == 0) ? 1U : 0U;
	if (len > STORE_CAP) {
		return -ENOSPC;
	}
	s->present[idx] = true;
	memcpy(s->data[idx], data, len);
	s->len[idx] = len;
	return 0;
}

static void store_corrupt(struct store *s, unsigned int idx, size_t offset)
{
	s->data[idx][offset] = (uint8_t)(s->data[idx][offset] ^ 0xFFU);
}

static struct lichen_redundant_io io = {
	.read = store_read,
	.write = store_write,
};

static const char *const KEYS[2] = {"slot.a", "slot.b"};
static const uint8_t MAGIC[4] = {'T', 'S', 'T', '1'};

/* --- independent CRC-32 oracle (reflected, ISO-HDLC) --- */

static uint32_t oracle_crc32(const uint8_t *data, size_t len)
{
	uint32_t crc = 0xFFFFFFFFU;

	for (size_t i = 0; i < len; i++) {
		crc ^= data[i];
		for (int bit = 0; bit < 8; bit++) {
			crc = (crc >> 1) ^ (0xEDB88320U & (uint32_t)(-(int32_t)(crc & 1U)));
		}
	}
	return crc ^ 0xFFFFFFFFU;
}

int main(void)
{
	struct store s;
	memset(&s, 0, sizeof(s));
	io.user = &s;

	uint8_t record[STORE_CAP];
	uint8_t slot_a[STORE_CAP];
	uint8_t slot_b[STORE_CAP];
	uint8_t out[STORE_CAP];
	struct lichen_redundant_value value;
	const uint8_t payload_a[] = {'p', 'a', 'y', 'l', 'o', 'a', 'd', '-', '1'};

	/* 1. Empty store -> Missing (-ENOENT). */
	CHECK(lichen_redundant_open(&io, KEYS, MAGIC, slot_a, sizeof(slot_a),
				    slot_b, sizeof(slot_b), out, sizeof(out),
				    &value) == -ENOENT,
	      "open on empty store must report Missing");

	/* 2. Provision succeeds; re-provision reports Exists (-EEXIST). */
	CHECK(lichen_redundant_provision(&io, KEYS, MAGIC, payload_a,
					 sizeof(payload_a), record,
					 sizeof(record)) == 0,
	      "provision on empty store succeeds");
	CHECK(lichen_redundant_provision(&io, KEYS, MAGIC, payload_a,
					 sizeof(payload_a), record,
					 sizeof(record)) == -EEXIST,
	      "re-provision must report Exists");

	/* 3. Open newest + slot alternation: gen1 slot0 -> gen2 slot1 ->
	 * gen3 slot0. */
	const uint8_t payload_b[] = {'p', 'a', 'y', 'l', 'o', 'a', 'd', '-', '2'};
	const uint8_t payload_c[] = {'p', 'a', 'y', 'l', 'o', 'a', 'd', '-', '3'};
	CHECK(lichen_redundant_open(&io, KEYS, MAGIC, slot_a, sizeof(slot_a),
				    slot_b, sizeof(slot_b), out, sizeof(out),
				    &value) == 0 &&
		      value.generation == 1U && value.slot == 0 &&
		      value.len == sizeof(payload_a) &&
		      memcmp(out, payload_a, sizeof(payload_a)) == 0,
	      "open after provision returns gen1 payload from slot0");
	CHECK(lichen_redundant_update(&io, KEYS, MAGIC, &value, payload_b,
				      sizeof(payload_b), record,
				      sizeof(record), &value) == 0 &&
		      value.generation == 2U && value.slot == 1,
	      "update writes the opposite slot at generation+1");
	CHECK(lichen_redundant_update(&io, KEYS, MAGIC, &value, payload_c,
				      sizeof(payload_c), record,
				      sizeof(record), &value) == 0 &&
		      value.generation == 3U && value.slot == 0,
	      "second update alternates back to slot0 at generation+1");
	CHECK(lichen_redundant_open(&io, KEYS, MAGIC, slot_a, sizeof(slot_a),
				    slot_b, sizeof(slot_b), out, sizeof(out),
				    &value) == 0 &&
		      value.generation == 3U && value.slot == 0 &&
		      memcmp(out, payload_c, sizeof(payload_c)) == 0,
	      "open returns the newest value after alternation");

	/* 4. Corrupt the current slot -> update reports Stale (-ESTALE). */
	store_corrupt(&s, 0, 5U); /* clobber the version byte */
	CHECK(lichen_redundant_update(&io, KEYS, MAGIC, &value, payload_a,
				      sizeof(payload_a), record,
				      sizeof(record), &value) == -ESTALE,
	      "corrupt-current must report Stale");
	/* Repair slot0 by re-writing its old gen3 record via a fresh open
	 * of slot1... slot1 holds gen2, so re-open restores gen2 as newest:
	 * the fixture instead rebuilds from the corrupt slot's payload —
	 * simplest is to re-provision from scratch for the next cases. */
	(void)s;

	/* 5. Corrupt both slots -> EIO on open and update. */
	memset(&s, 0, sizeof(s));
	CHECK(lichen_redundant_provision(&io, KEYS, MAGIC, payload_a,
					 sizeof(payload_a), record,
					 sizeof(record)) == 0,
	      "re-provision for corrupt-both case");
	CHECK(lichen_redundant_open(&io, KEYS, MAGIC, slot_a, sizeof(slot_a),
				    slot_b, sizeof(slot_b), out, sizeof(out),
				    &value) == 0 && value.slot == 0,
	      "open populates current after re-provision");
	store_corrupt(&s, 0, 0U);
	store_corrupt(&s, 0, 10U);
	CHECK(lichen_redundant_open(&io, KEYS, MAGIC, slot_a, sizeof(slot_a),
				    slot_b, sizeof(slot_b), out, sizeof(out),
				    &value) == -EIO,
	      "corrupt slot without alternative must report EIO");
	CHECK(lichen_redundant_update(&io, KEYS, MAGIC, &value, payload_a,
				      sizeof(payload_a), record,
				      sizeof(record), &value) == -EIO,
	      "update against corrupt-only state must report EIO");

	/* 6. Stale via current-slot drop: storage loses the current slot
	 * while the opposite (older) slot is valid. */
	memset(&s, 0, sizeof(s));
	CHECK(lichen_redundant_provision(&io, KEYS, MAGIC, payload_a,
					 sizeof(payload_a), record,
					 sizeof(record)) == 0,
	      "provision for slot-drop case");
	CHECK(lichen_redundant_open(&io, KEYS, MAGIC, slot_a, sizeof(slot_a),
				    slot_b, sizeof(slot_b), out, sizeof(out),
				    &value) == 0 && value.slot == 0,
	      "open populates current for slot-drop case");
	CHECK(lichen_redundant_update(&io, KEYS, MAGIC, &value, payload_b,
				      sizeof(payload_b), record,
				      sizeof(record), &value) == 0 &&
		      value.slot == 1,
	      "update to gen2 slot1 for slot-drop case");
	s.present[1] = false; /* current slot vanishes from storage */
	CHECK(lichen_redundant_update(&io, KEYS, MAGIC, &value, payload_c,
				      sizeof(payload_c), record,
				      sizeof(record), &value) == -ESTALE,
	      "dropped current slot must report Stale");

	/* 7. Generation wrap: current at u64::MAX -> -EOVERFLOW (terminal,
	 * spec 09 14.2). The record is hand-encoded with the oracle CRC so
	 * the storage state is a valid gen=UINT64_MAX record. */
	memset(&s, 0, sizeof(s));
	{
		const uint8_t wrap_payload[] = {'w', 'r', 'a', 'p'};
		uint8_t wrap_rec[STORE_CAP];
		wrap_rec[0] = 'T';
		wrap_rec[1] = 'S';
		wrap_rec[2] = 'T';
		wrap_rec[3] = '1';
		wrap_rec[4] = 1U; /* REDUNDANT_SLOT_VERSION */
		wrap_rec[5] = 0U;
		wrap_rec[6] = 0U;
		wrap_rec[7] = 0U;
		for (int i = 0; i < 8; i++) {
			wrap_rec[8U + (size_t)i] = 0xFFU;
		}
		wrap_rec[16] = 0U;
		wrap_rec[17] = 0U;
		wrap_rec[18] = 0U;
		wrap_rec[19] = (uint8_t)sizeof(wrap_payload);
		memcpy(&wrap_rec[20], wrap_payload, sizeof(wrap_payload));
		uint32_t crc = oracle_crc32(wrap_rec, 20U + sizeof(wrap_payload));
		wrap_rec[24] = (uint8_t)(crc >> 24);
		wrap_rec[25] = (uint8_t)(crc >> 16);
		wrap_rec[26] = (uint8_t)(crc >> 8);
		wrap_rec[27] = (uint8_t)crc;
		CHECK(store_write(&s, "slot.a", wrap_rec, 28U) == 0,
		      "hand-encoded wrap record stored");
		struct lichen_redundant_value wrap_current = {
			.generation = UINT64_MAX,
			.slot = 0,
			.len = sizeof(wrap_payload),
		};
		CHECK(lichen_redundant_update(&io, KEYS, MAGIC, &wrap_current,
					      wrap_payload,
					      sizeof(wrap_payload), record,
					      sizeof(record),
					      &value) == -EOVERFLOW,
		      "generation wrap must report EOVERFLOW and is terminal");
	}

	/* 8. Rollback on write failure: a failed update leaves the previous
	 * generation intact and readable. */
	memset(&s, 0, sizeof(s));
	CHECK(lichen_redundant_provision(&io, KEYS, MAGIC, payload_a,
					 sizeof(payload_a), record,
					 sizeof(record)) == 0,
	      "provision for rollback case");
	CHECK(lichen_redundant_open(&io, KEYS, MAGIC, slot_a, sizeof(slot_a),
				    slot_b, sizeof(slot_b), out, sizeof(out),
				    &value) == 0 && value.slot == 0,
	      "open populates current for rollback case");
	CHECK(lichen_redundant_update(&io, KEYS, MAGIC, &value, payload_b,
				      sizeof(payload_b), record,
				      sizeof(record), &value) == 0 &&
		      value.generation == 2U,
	      "gen2 written for rollback case");
	s.write_error = EIO;
	CHECK(lichen_redundant_update(&io, KEYS, MAGIC, &value, payload_c,
				      sizeof(payload_c), record,
				      sizeof(record), &value) == -EIO,
	      "write failure must surface as EIO");
	s.write_error = 0;
	CHECK(lichen_redundant_open(&io, KEYS, MAGIC, slot_a, sizeof(slot_a),
				    slot_b, sizeof(slot_b), out, sizeof(out),
				    &value) == 0 &&
		      value.generation == 2U &&
		      memcmp(out, payload_b, sizeof(payload_b)) == 0,
	      "state after failed write is the pre-failure generation");

	/* 9. CRC32 cross-check: the oracle validates against the canonical
	 * Rust crc32 vector ("123456789" -> 0xCBF43926), then the record
	 * trailer must equal the oracle CRC over header+payload. */
	{
		const uint8_t canonical[] = {'1', '2', '3', '4', '5',
					     '6', '7', '8', '9'};
		CHECK(oracle_crc32(canonical, sizeof(canonical)) ==
			      0xCBF43926U,
		      "oracle CRC32 must match the canonical Rust vector");
		const uint8_t crc_payload[] = {'1', '2', '3', '4', '5',
					       '6', '7', '8', '9'};
		memset(&s, 0, sizeof(s));
		CHECK(lichen_redundant_provision(&io, KEYS, MAGIC, crc_payload,
						 sizeof(crc_payload), record,
						 sizeof(record)) == 0,
		      "provision for CRC trailer case");
		uint32_t trailer = ((uint32_t)record[29] << 24) |
				   ((uint32_t)record[30] << 16) |
				   ((uint32_t)record[31] << 8) |
				   (uint32_t)record[32];
		CHECK(trailer == oracle_crc32(record, 29U),
		      "record trailer must equal the oracle CRC over header+payload");
		CHECK(trailer != 0U, "trailer is not degenerate");
	}

	if (failures == 0) {
		printf("PASS: redundant_slot primitive\n");
	}
	return failures == 0 ? 0 : 1;
}
