/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rpl_dao_tx_persist.h>

#include <errno.h>
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

/* --- DAO TX state open/provision over a fake store (bead b7z9.11.2) --- */

#define NSLOTS 2
#define STORE_CAP 340

struct store {
	bool present[NSLOTS];
	uint8_t data[NSLOTS][STORE_CAP];
	size_t len[NSLOTS];
	int read_error;
};

static int store_read(void *user, const char *key, uint8_t *out,
		      size_t capacity, size_t *length)
{
	struct store *s = user;
	unsigned int idx = key[7] - 'a';

	if (s->read_error != 0) {
		return s->read_error;
	}
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

	if (idx >= NSLOTS || length > STORE_CAP) {
		return -EINVAL;
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

static void test_dao_tx_state(void)
{
	static const uint8_t key[32] = { 1 };
	static const uint8_t origin[16] = { 2 };
	static const uint8_t dodag[16] = { 3 };
	static const uint8_t other_key[32] = { 9 };
	struct store s;
	struct lichen_rpl_dao_tx_state state;
	uint8_t record[LICHEN_DAO_TX_HEADER_LEN +
		       LICHEN_DAO_TX_MAX_SIGNED_LEN];
	size_t payload_len;

	/* Empty store: open is Missing; provision succeeds at sequence 0. */
	memset(&s, 0, sizeof(s));
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7, dodag,
				     &state) == LICHEN_DAO_TX_OPEN_MISSING,
	      "tx open on empty store is Missing");
	CHECK(lichen_rpl_dao_tx_provision(&store_ops, &s, key, origin, 7,
					  dodag, &state) ==
		      LICHEN_DAO_TX_PROVISION_OK,
	      "tx provision succeeds");
	CHECK(state.current.generation == 1 && state.last_reserved == 0U &&
		      state.last_signed_dao_len == 0U,
	      "tx provision state: gen 1, seq 0, no signed bytes");
	CHECK(s.present[0] && !s.present[1], "tx provision wrote slot A");

	/* Re-open roundtrips the scope. */
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7, dodag,
				     &state) == LICHEN_DAO_TX_OPEN_OK,
	      "tx re-open OK");

	/* Provision again -> Already. */
	CHECK(lichen_rpl_dao_tx_provision(&store_ops, &s, key, origin, 7,
					  dodag, &state) ==
		      LICHEN_DAO_TX_PROVISION_ALREADY,
	      "tx re-provision is Already");

	/* Key mismatch. */
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, other_key, origin, 7,
				     dodag,
				     &state) == LICHEN_DAO_TX_OPEN_KEY_MISMATCH,
	      "tx open key mismatch");

	/* Scope mismatch (instance). */
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 9, dodag,
				     &state) ==
		      LICHEN_DAO_TX_OPEN_SCOPE_MISMATCH,
	      "tx open scope mismatch");

	/* Corrupt record: provision is Corrupt, not Already (Exists->Corrupt
	 * mapping matches the Rust reference). */
	memset(&s, 0, sizeof(s));
	s.present[0] = true;
	memset(s.data[0], 0xEE, 24);
	s.len[0] = 24;
	CHECK(lichen_rpl_dao_tx_provision(&store_ops, &s, key, origin, 7,
					  dodag, &state) ==
		      LICHEN_DAO_TX_PROVISION_CORRUPT,
	      "tx provision over corrupt is Corrupt");
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7, dodag,
				     &state) == LICHEN_DAO_TX_OPEN_CORRUPT,
	      "tx open corrupt is Corrupt");

	/* Trailing-garbage record (exact-length gate on open). */
	memset(&s, 0, sizeof(s));
	payload_len = lichen_rpl_dao_tx_encode(key, origin, 7, dodag, 5, NULL,
					       0, record, sizeof(record));
	CHECK(payload_len == LICHEN_DAO_TX_HEADER_LEN, "seq-0 encode");
	s.present[0] = true;
	memcpy(s.data[0], record, payload_len);
	s.len[0] = payload_len + 3;
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7, dodag,
				     &state) == LICHEN_DAO_TX_OPEN_CORRUPT,
	      "tx open rejects trailing garbage");

	/* Storage read failure surfaces as STORAGE_ERROR. */
	memset(&s, 0, sizeof(s));
	s.read_error = -EIO;
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7, dodag,
				     &state) ==
		      LICHEN_DAO_TX_OPEN_STORAGE_ERROR,
	      "tx open storage error");

	/* NULL guard. */
	memset(&s, 0, sizeof(s));
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, NULL, origin, 7, dodag,
				     &state) ==
		      LICHEN_DAO_TX_OPEN_STORAGE_ERROR,
	      "tx open NULL key rejected");
}

/* reserve_next / clear_transmitted (rust persistence.rs :246-358). */
static void test_dao_tx_reserve_clear(void)
{
	static const uint8_t key[32] = { 1 };
	static const uint8_t origin[16] = { 2 };
	static const uint8_t dodag[16] = { 3 };
	struct store s;
	struct lichen_rpl_dao_tx_state state;
	uint8_t record[LICHEN_DAO_TX_HEADER_LEN + LICHEN_DAO_TX_MAX_SIGNED_LEN + 24];
	uint64_t next;

	memset(&s, 0, sizeof(s));
	CHECK(lichen_rpl_dao_tx_provision(&store_ops, &s, key, origin, 7,
					  dodag, &state) ==
		      LICHEN_DAO_TX_PROVISION_OK,
	      "reserve: provision");

	/* Reserve 1: persists gen 2 carrying sequence 1 BEFORE TX. */
	CHECK(lichen_rpl_dao_tx_reserve_next(&store_ops, &s, &state, record,
					     sizeof(record),
					     &next) == LICHEN_DAO_TX_TX_OK,
	      "reserve: first reserve OK");
	CHECK(next == 1U && state.last_reserved == 1U,
	      "reserve: sequence 1 reserved");
	CHECK(state.current.generation == 2 &&
		      state.current.slot == LICHEN_STORAGE_SLOT_B,
	      "reserve: opposite slot at gen 2");

	/* Re-open sees the reserved sequence durably. */
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7, dodag,
				     &state) == LICHEN_DAO_TX_OPEN_OK,
	      "reserve: re-open");
	CHECK(state.last_reserved == 1U, "reserve: sequence durable");

	/* clear_transmitted without pending signed bytes -> INVALID_STATE. */
	CHECK(lichen_rpl_dao_tx_clear_transmitted(
		      &store_ops, &s, &state, record,
		      sizeof(record)) == LICHEN_DAO_TX_TX_INVALID_STATE,
	      "clear: nothing pending -> INVALID_STATE");

	/* Alternation continues: reserve 2 lands back in slot A. */
	CHECK(lichen_rpl_dao_tx_reserve_next(&store_ops, &s, &state, record,
					     sizeof(record),
					     &next) == LICHEN_DAO_TX_TX_OK,
	      "reserve: second reserve OK");
	CHECK(next == 2U && state.current.slot == LICHEN_STORAGE_SLOT_A,
	      "reserve: alternation continues");

	/* Signed bytes carry: open a hand-crafted record with signed bytes,
	 * reserve keeps them in the reserved payload. */
	memset(&s, 0, sizeof(s));
	{
		uint8_t sig_bytes[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
		uint8_t payload2[LICHEN_DAO_TX_HEADER_LEN +
				 LICHEN_DAO_TX_MAX_SIGNED_LEN];
		size_t plen = lichen_rpl_dao_tx_encode(
			key, origin, 7, dodag, 41, sig_bytes, sizeof(sig_bytes),
			payload2, sizeof(payload2));
		uint8_t rec2[24 + LICHEN_DAO_TX_HEADER_LEN +
			     LICHEN_DAO_TX_MAX_SIGNED_LEN];
		size_t rlen = lichen_hal_storage_encode_slot(
			(const uint8_t *)"DTX2", 1, payload2, plen, rec2,
			sizeof(rec2));
		(void)rlen;
		s.present[0] = true;
		memcpy(s.data[0], rec2, 24 + plen);
		s.len[0] = 24 + plen;
		CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7,
					     dodag,
					     &state) == LICHEN_DAO_TX_OPEN_OK,
		      "carry: signed-bytes record opens");
		CHECK(state.last_signed_dao_len == 4U &&
			      memcmp(state.last_signed_dao, sig_bytes, 4) == 0,
		      "carry: signed bytes loaded");
		CHECK(lichen_rpl_dao_tx_reserve_next(
			      &store_ops, &s, &state, record,
			      sizeof(record), &next) == LICHEN_DAO_TX_TX_OK,
		      "carry: reserve with carried bytes OK");
		CHECK(next == 42U, "carry: sequence 42 reserved");
		/* The durable record still carries the signed bytes. */
		CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7,
					     dodag,
					     &state) == LICHEN_DAO_TX_OPEN_OK,
		      "carry: re-open");
		CHECK(state.last_reserved == 42U &&
			      state.last_signed_dao_len == 4U,
		      "carry: prior signed bytes re-carried");

		/* Clear success: same sequence, empty signed bytes persisted
		 * and in-memory bytes zeroed. */
		CHECK(lichen_rpl_dao_tx_clear_transmitted(
			      &store_ops, &s, &state, record,
			      sizeof(record)) == LICHEN_DAO_TX_TX_OK,
		      "clear: success path");
		CHECK(state.last_signed_dao_len == 0U,
		      "clear: in-memory bytes zeroed");
		CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7,
					     dodag,
					     &state) == LICHEN_DAO_TX_OPEN_OK,
		      "clear: re-open");
		CHECK(state.last_reserved == 42U &&
			      state.last_signed_dao_len == 0U,
		      "clear: durable record has empty signed bytes");
	}

	/* Exhaustion at u64 max (no wrap): hand-craft a max-sequence slot. */
	memset(&s, 0, sizeof(s));
	uint8_t payload[LICHEN_DAO_TX_HEADER_LEN + LICHEN_DAO_TX_MAX_SIGNED_LEN];
	size_t payload_len = lichen_rpl_dao_tx_encode(
		key, origin, 7, dodag, UINT64_MAX, NULL, 0, payload,
		sizeof(payload));
	CHECK(payload_len == LICHEN_DAO_TX_HEADER_LEN,
	      "reserve: max sequence encodes");
	uint8_t max_rec[24 + LICHEN_DAO_TX_HEADER_LEN + LICHEN_DAO_TX_MAX_SIGNED_LEN];
	size_t max_len = lichen_hal_storage_encode_slot(
		(const uint8_t *)"DTX2", 1, payload, payload_len, max_rec,
		sizeof(max_rec));
	(void)max_len;
	s.present[0] = true;
	memcpy(s.data[0], max_rec, 24 + payload_len);
	s.len[0] = 24 + payload_len;
	CHECK(lichen_rpl_dao_tx_open(&store_ops, &s, key, origin, 7, dodag,
				     &state) == LICHEN_DAO_TX_OPEN_OK,
	      "reserve: max sequence opens");
	CHECK(state.last_reserved == UINT64_MAX, "reserve: u64 max loaded");
	CHECK(lichen_rpl_dao_tx_reserve_next(&store_ops, &s, &state, record,
					     sizeof(record),
					     &next) ==
		      LICHEN_DAO_TX_TX_EXHAUSTED,
	      "reserve: u64 max is Exhausted (no wrap)");

	/* NULL guards. */
	CHECK(lichen_rpl_dao_tx_reserve_next(&store_ops, &s, NULL, record,
					     sizeof(record),
					     &next) ==
		      LICHEN_DAO_TX_TX_STORAGE_ERROR,
	      "reserve: NULL state rejected");
}

int main(void)
{
	/* Fixed vectors assembled by hand from the documented layout
	 * (independent oracle; cross-checked against the Rust
	 * encode_tx_state byte concatenation, bead cvi7).
	 */
	const uint8_t pubkey[32] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				     0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
				     0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
				     0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
				     0x1c, 0x1d, 0x1e, 0x1f };
	const uint8_t origin[16] = { 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
				     0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
				     0xAA, 0xAA };
	const uint8_t dodag[16] = { 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
				    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
				    0xBB, 0xBB };
	const uint8_t signed_dao[2] = { 0xCC, 0xDD };
	static const char *const expected_hex =
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa07bbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		"bb01020304050607080002ccdd";

	uint8_t out[LICHEN_DAO_TX_HEADER_LEN + 255];
	size_t len = lichen_rpl_dao_tx_encode(pubkey, origin, 7, dodag,
					      0x0102030405060708ULL, signed_dao,
					      sizeof(signed_dao), out,
					      sizeof(out));
	CHECK(len == 77, "encoded length is 75 + 2");
	CHECK(len == strlen(expected_hex) / 2, "length matches oracle vector");

	char hex[2 * sizeof(out) + 1];
	for (size_t i = 0; i < len; i++) {
		snprintf(&hex[2 * i], 3, "%02x", out[i]);
	}
	hex[2 * len] = '\0';
	CHECK(strcmp(hex, expected_hex) == 0,
	      "encoded bytes match independent oracle vector");

	/* Roundtrip parse. */
	struct lichen_rpl_dao_tx_header header;
	CHECK(lichen_rpl_dao_tx_parse(out, len, &header), "parse succeeds");
	CHECK(header.public_key == &out[0] &&
		      memcmp(header.public_key, pubkey, 32) == 0,
	      "pubkey roundtrip");
	CHECK(memcmp(header.local_origin, origin, 16) == 0, "origin roundtrip");
	CHECK(header.rpl_instance_id == 7, "instance roundtrip");
	CHECK(memcmp(header.dodag_id, dodag, 16) == 0, "dodag roundtrip");
	CHECK(header.sequence == 0x0102030405060708ULL, "sequence roundtrip");
	CHECK(header.signed_dao_len == 2 &&
		      memcmp(header.signed_dao, signed_dao, 2) == 0,
	      "signed dao roundtrip");

	/* Empty signed DAO. */
	len = lichen_rpl_dao_tx_encode(pubkey, origin, 7, dodag, 1, NULL, 0,
				       out, sizeof(out));
	/* NULL signed_dao with len 0 is allowed (Rust empty-slice parity). */
	size_t null_len = lichen_rpl_dao_tx_encode(pubkey, origin, 7, dodag, 1,
						   NULL, 0, out, sizeof(out));
	CHECK(null_len == LICHEN_DAO_TX_HEADER_LEN, "NULL signed_dao accepted");
	len = lichen_rpl_dao_tx_encode(pubkey, origin, 7, dodag, 1, signed_dao,
				       0, out, sizeof(out));
	CHECK(len == LICHEN_DAO_TX_HEADER_LEN, "empty signed dao encodes");
	CHECK(lichen_rpl_dao_tx_parse(out, len, &header) &&
		      header.sequence == 1 && header.signed_dao_len == 0,
	      "empty signed dao parses");

	/* Oversized signed DAO. */
	CHECK(lichen_rpl_dao_tx_encode(pubkey, origin, 7, dodag, 1, signed_dao,
				       LICHEN_DAO_TX_MAX_SIGNED_LEN + 1, out,
				       sizeof(out)) == 0,
	      "oversized signed dao rejected");

	/* Too-small out buffer. */
	uint8_t tiny[10];
	CHECK(lichen_rpl_dao_tx_encode(pubkey, origin, 7, dodag, 1, signed_dao,
				       sizeof(signed_dao), tiny,
				       sizeof(tiny)) == 0,
	      "small out buffer rejected");

	/* Undersized payload on parse. */
	CHECK(!lichen_rpl_dao_tx_parse(out, LICHEN_DAO_TX_HEADER_LEN - 1,
				       &header),
	      "undersized payload rejected");

	/* Declared signed_len extends past the payload -> OOB guard. */
	uint8_t oob[77];
	memset(oob, 0, sizeof(oob));
	memcpy(oob, pubkey, 32);
	oob[73] = 0;
	oob[74] = 200;
	CHECK(!lichen_rpl_dao_tx_parse(oob, sizeof(oob), &header),
	      "signed_len past payload rejected");

	/* Trailing garbage after the declared signed DAO (exact-length gate). */
	uint8_t trailing[80];
	memcpy(trailing, out, 77);
	trailing[73] = 0;
	trailing[74] = 2;
	CHECK(lichen_rpl_dao_tx_parse(trailing, 77, &header),
	      "exact-length record parses");
	CHECK(!lichen_rpl_dao_tx_parse(trailing, 80, &header),
	      "trailing garbage rejected");

	/* Declared signed_len over the max on parse. */
	uint8_t bad_len[80];
	memset(bad_len, 0, sizeof(bad_len));
	memcpy(bad_len, pubkey, 32);
	bad_len[73] = 0xFF;
	bad_len[74] = 0xFF;
	CHECK(!lichen_rpl_dao_tx_parse(bad_len, sizeof(bad_len), &header),
	      "oversized declared signed_len rejected");

	/* Max-size signed DAO boundary encodes and parses. */
	uint8_t big[512];
	memset(big, 0x5A, sizeof(big));
	len = lichen_rpl_dao_tx_encode(pubkey, origin, 7, dodag, 42, big,
				       LICHEN_DAO_TX_MAX_SIGNED_LEN, out,
				       sizeof(out));
	CHECK(len == LICHEN_DAO_TX_HEADER_LEN + LICHEN_DAO_TX_MAX_SIGNED_LEN,
	      "max signed dao encodes");
	CHECK(lichen_rpl_dao_tx_parse(out, len, &header) &&
		      header.signed_dao_len == LICHEN_DAO_TX_MAX_SIGNED_LEN &&
		      header.signed_dao[0] == 0x5A,
	      "max signed dao parses");

	test_dao_tx_state();
	test_dao_tx_reserve_clear();

	if (failures == 0) {
		printf("PASS: rpl_dao_tx_persist codec\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
