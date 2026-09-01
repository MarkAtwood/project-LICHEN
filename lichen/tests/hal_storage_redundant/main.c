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

	if (failures == 0) {
		printf("PASS: hal_storage_redundant slot codec\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
