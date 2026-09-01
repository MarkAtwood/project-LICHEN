/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/rpl_dao_tx_persist.h>

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

	if (failures == 0) {
		printf("PASS: rpl_dao_tx_persist codec\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
