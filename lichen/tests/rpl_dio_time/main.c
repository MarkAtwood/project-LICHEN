/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief DIO Time Option codec tests (bd project-LICHEN-worker6-ndk7).
 *
 * Expected bytes are the independent vector literals from
 * test/vectors/packets-timing.json "dio_time_option"
 * (encoded_hex 150603006553f100, no_sync_encoded_hex 1506000000000000)
 * and are NOT derived from the C implementation under test. Validation
 * rules mirror python DioTimeOption.decode and rust
 * DioTimeOption::from_option_data / write_to.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <lichen/rpl_messages.h>

/* Failure diagnostics: name the check and its location. */
#define CHECK(cond)                                                          \
	do {                                                                 \
		if (!(cond)) {                                               \
			printf("    check failed: %s (%s:%d)\n", #cond,     \
			       __FILE__, __LINE__);                          \
			return 1;                                            \
		}                                                            \
	} while (0)

static int test_canonical_write_matches_vector(void)
{
	/* packets-timing.json dio_time_option: stratum 3, ts 1700000000. */
	static const uint8_t expected[] = { 0x15, 0x06, 0x03, 0x00,
					    0x65, 0x53, 0xf1, 0x00 };
	const struct lichen_rpl_dio_time dt = { .stratum = 3U,
						.timestamp = 1700000000U };
	uint8_t buf[16] = { 0 };

	CHECK(lichen_rpl_dio_time_write(&dt, buf, sizeof(buf)) ==
	      (int)sizeof(expected));
	CHECK(memcmp(buf, expected, sizeof(expected)) == 0);
	return 0;
}

static int test_canonical_parse_roundtrip(void)
{
	/* Same vector bytes, parsed back. */
	static const uint8_t wire[] = { 0x15, 0x06, 0x03, 0x00,
					0x65, 0x53, 0xf1, 0x00 };
	struct lichen_rpl_dio_time dt = { 0 };

	CHECK(lichen_rpl_dio_time_parse(&dt, wire + 2U, sizeof(wire) - 2U) ==
	      LICHEN_RPL_OK);
	CHECK(dt.stratum == 3U);
	CHECK(dt.timestamp == 1700000000U);
	return 0;
}

static int test_no_sync_carries_zero_timestamp(void)
{
	/* packets-timing.json dio_time_option no_sync_encoded_hex. */
	static const uint8_t expected[] = { 0x15, 0x06, 0x00, 0x00,
					    0x00, 0x00, 0x00, 0x00 };
	const struct lichen_rpl_dio_time dt = { .stratum = 0U, .timestamp = 0U };
	struct lichen_rpl_dio_time parsed = { 0 };
	uint8_t buf[16] = { 0 };

	CHECK(lichen_rpl_dio_time_write(&dt, buf, sizeof(buf)) ==
	      (int)sizeof(expected));
	CHECK(memcmp(buf, expected, sizeof(expected)) == 0);
	CHECK(lichen_rpl_dio_time_parse(&parsed, buf + 2U, 6U) ==
	      LICHEN_RPL_OK);
	CHECK(parsed.stratum == 0U);
	CHECK(parsed.timestamp == 0U);
	return 0;
}

static int test_parse_rejects_malformed(void)
{
	/* payload-only vectors mirroring test/vectors/dio_time_option_malformed.json
	 * (type/length bytes are consumed by the option iterator). */
	static const uint8_t reserved_nonzero[] = { 0x03, 0x01, 0x65,
						    0x53, 0xf1, 0x00 };
	static const uint8_t stratum_five[] = { 0x05, 0x00, 0x65,
						0x53, 0xf1, 0x00 };
	static const uint8_t no_sync_nonzero_ts[] = { 0x00, 0x00, 0x00,
						      0x00, 0x00, 0x01 };
	static const uint8_t trailing[] = { 0x03, 0x00, 0x65,
					    0x53, 0xf1, 0x00, 0xaa };
	static const uint8_t short_payload[] = { 0x03, 0x00, 0x65, 0x53, 0xf1 };
	struct lichen_rpl_dio_time dt = { 0 };

	CHECK(lichen_rpl_dio_time_parse(&dt, reserved_nonzero,
					sizeof(reserved_nonzero)) ==
	      LICHEN_RPL_ERR_BAD_OPT);
	CHECK(lichen_rpl_dio_time_parse(&dt, stratum_five,
					sizeof(stratum_five)) ==
	      LICHEN_RPL_ERR_BAD_OPT);
	CHECK(lichen_rpl_dio_time_parse(&dt, no_sync_nonzero_ts,
					sizeof(no_sync_nonzero_ts)) ==
	      LICHEN_RPL_ERR_BAD_OPT);
	CHECK(lichen_rpl_dio_time_parse(&dt, trailing, sizeof(trailing)) ==
	      LICHEN_RPL_ERR_BAD_OPT);
	CHECK(lichen_rpl_dio_time_parse(&dt, short_payload,
					sizeof(short_payload)) ==
	      LICHEN_RPL_ERR_TOO_SHORT);
	/* Atomic on error: a rejected payload must not write the output. */
	{
		static const uint8_t no_sync_nonzero[] = { 0x00, 0x00, 0x00,
							   0x00, 0x00, 0x01 };
		struct lichen_rpl_dio_time untouched = { .stratum = 9U,
							 .timestamp = 1U };
		struct lichen_rpl_dio_time probe = untouched;
		CHECK(lichen_rpl_dio_time_parse(&probe, no_sync_nonzero,
						sizeof(no_sync_nonzero)) ==
		      LICHEN_RPL_ERR_BAD_OPT);
		CHECK(probe.stratum == 9U);
		CHECK(probe.timestamp == 1U);
	}
	return 0;
}

static int test_write_rejects_invalid(void)
{
	const struct lichen_rpl_dio_time stratum_five = { .stratum = 5U,
							  .timestamp = 7U };
	const struct lichen_rpl_dio_time no_sync_nonzero = { .stratum = 0U,
							     .timestamp = 9U };
	uint8_t buf[16] = { 0 };

	/* Value validity is checked before buffer capacity (sibling
	 * convention), and BAD_OPT mirrors rust InvalidOption. */
	CHECK(lichen_rpl_dio_time_write(&stratum_five, buf, sizeof(buf)) ==
	      LICHEN_RPL_ERR_BAD_OPT);
	CHECK(lichen_rpl_dio_time_write(&no_sync_nonzero, buf, sizeof(buf)) ==
	      LICHEN_RPL_ERR_BAD_OPT);
	CHECK(lichen_rpl_dio_time_write(&stratum_five, buf, 1U) ==
	      LICHEN_RPL_ERR_BAD_OPT);
	{
		const struct lichen_rpl_dio_time valid = { .stratum = 3U,
							   .timestamp = 1700000000U };
		CHECK(lichen_rpl_dio_time_write(&valid, buf, 2U) ==
		      LICHEN_RPL_ERR_BUF_SMALL);
	}
	return 0;
}

static int test_pad1_is_single_byte_in_option_walk(void)
{
	/* RFC 6550: option type 0x00 is Pad1 — one octet, no length field.
	 * The historical 0x00-prefixed DIO time encoding must walk as Pad1
	 * followed by a type-0x06 (Transit Info) option, never as a time
	 * option; and a real 0x15 time option in a mixed list round-trips. */
	static const uint8_t old_colliding[] = { 0x00, 0x06, 0x03, 0x00,
						 0x65, 0x53, 0xf1, 0x00 };
	static const uint8_t mixed[] = { 0x00,				      /* Pad1 */
					 0x15, 0x06, 0x03, 0x00,
					 0x65, 0x53, 0xf1, 0x00,	      /* time */
					 0x01, 0x02, 0x00, 0x00,	      /* PadN */
					 0x99, 0x01, 0x77 };		      /* unknown */
	static const uint8_t truncated_padn[] = { 0x15, 0x06, 0x03, 0x00,
						  0x65, 0x53, 0xf1, 0x00,
						  0x01, 0x05, 0x00 };
	static const uint8_t pad1_last[] = { 0x15, 0x06, 0x03, 0x00,
					     0x65, 0x53, 0xf1, 0x00, 0x00 };
	static const uint8_t type_without_length[] = { 0x15, 0x06, 0x03, 0x00,
						       0x65, 0x53, 0xf1, 0x00,
						       0x15 };
	struct lichen_rpl_opt_iter it;
	struct lichen_rpl_raw_opt opt;
	struct lichen_rpl_dio_time dt = { 0 };
	int time_options = 0;
	int ret;

	/* The old colliding bytes contain no DIO Time option at all. */
	lichen_rpl_opt_iter_init(&it, old_colliding, sizeof(old_colliding));
	while ((ret = lichen_rpl_opt_iter_next(&it, &opt)) == LICHEN_RPL_OK) {
		CHECK(opt.opt_type != LICHEN_RPL_OPT_DIO_TIME);
	}
	CHECK(ret == 1); /* clean exhaustion */

	lichen_rpl_opt_iter_init(&it, mixed, sizeof(mixed));
	while ((ret = lichen_rpl_opt_iter_next(&it, &opt)) == LICHEN_RPL_OK) {
		if (opt.opt_type == LICHEN_RPL_OPT_DIO_TIME) {
			time_options++;
			CHECK(opt.data_len == 6U);
			CHECK(lichen_rpl_dio_time_parse(&dt, opt.data,
							opt.data_len) ==
			      LICHEN_RPL_OK);
			CHECK(dt.stratum == 3U);
			CHECK(dt.timestamp == 1700000000U);
		}
	}
	CHECK(ret == 1); /* walk ends cleanly after the unknown option */
	CHECK(time_options == 1);

	/* Malformed-walk edges: truncated PadN overrun; Pad1 as the final
	 * byte exhausts cleanly; a type octet without a length is too short. */
	lichen_rpl_opt_iter_init(&it, truncated_padn, sizeof(truncated_padn));
	CHECK(lichen_rpl_opt_iter_next(&it, &opt) == LICHEN_RPL_OK);
	CHECK(lichen_rpl_opt_iter_next(&it, &opt) == LICHEN_RPL_ERR_OVERRUN);

	lichen_rpl_opt_iter_init(&it, pad1_last, sizeof(pad1_last));
	CHECK(lichen_rpl_opt_iter_next(&it, &opt) == LICHEN_RPL_OK);
	CHECK(lichen_rpl_opt_iter_next(&it, &opt) == 1);

	lichen_rpl_opt_iter_init(&it, type_without_length,
				 sizeof(type_without_length));
	CHECK(lichen_rpl_opt_iter_next(&it, &opt) == LICHEN_RPL_OK);
	CHECK(lichen_rpl_opt_iter_next(&it, &opt) == LICHEN_RPL_ERR_TOO_SHORT);
	return 0;
}

int main(void)
{
	static const struct {
		const char *name;
		int (*fn)(void);
	} tests[] = {
		{ "canonical write matches packets-timing vector",
		  test_canonical_write_matches_vector },
		{ "canonical parse roundtrip",
		  test_canonical_parse_roundtrip },
		{ "no_sync carries zero timestamp",
		  test_no_sync_carries_zero_timestamp },
		{ "parse rejects malformed payloads",
		  test_parse_rejects_malformed },
		{ "write rejects invalid stratum and no_sync timestamp",
		  test_write_rejects_invalid },
		{ "pad1 is single byte in mixed option walk",
		  test_pad1_is_single_byte_in_option_walk },
	};
	size_t passed = 0U;

	printf("DIO Time Option codec (type 0x15)\n");
	for (size_t i = 0U; i < sizeof(tests) / sizeof(tests[0]); i++) {
		const int rc = tests[i].fn();
		printf("  %s: %s\n", tests[i].name, rc == 0 ? "PASS" : "FAIL");
		if (rc == 0) {
			passed++;
		}
	}

	printf("%zu/%zu tests passed\n", passed,
	       (size_t)(sizeof(tests) / sizeof(tests[0])));
	return (passed == sizeof(tests) / sizeof(tests[0])) ? 0 : 1;
}
