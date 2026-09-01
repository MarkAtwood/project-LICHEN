/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */
/* Root DIO Signature option wire-format test (spec/06-security.md 8.10.1).
 *
 * Fixtures from test/vectors/root_dio_signature.json (external oracle):
 * root_dio_signature_valid_basic. The COSE_Sign1 blob is carried
 * byte-transparently; COSE decode/verify is receiver-side.
 */

#include <stdio.h>
#include <string.h>

#include <lichen/rpl_messages.h>

static int tests_run;
static int tests_passed;

#define ASSERT_EQ(a, b, msg) do { \
	if ((a) != (b)) { \
		printf("  FAIL: %s (got %d, expected %d)\n", \
		       msg, (int)(a), (int)(b)); \
		return 0; \
	} \
} while (0)

/* test/vectors/root_dio_signature.json :: root_dio_signature_valid_basic */
static const uint8_t vector_cose_sign1[] = {
	0xd2, 0x84, 0x47, 0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0xa1, 0x04,
	0x48, 0x20, 0x3d, 0xf4, 0x66, 0x2a, 0xb8, 0x1f, 0x5a, 0x58, 0x25, 0xa7,
	0x01, 0x50, 0x02, 0x20, 0x3d, 0xf4, 0x66, 0x2a, 0xb8, 0x1f, 0x20, 0x3d,
	0xf4, 0x66, 0x2a, 0xb8, 0x1f, 0x5a, 0x02, 0x00, 0x03, 0x01, 0x04, 0x19,
	0x01, 0x00, 0x05, 0x1a, 0x67, 0x74, 0x85, 0x80, 0x06, 0x01, 0x07, 0x02,
	0x58, 0x30, 0x4f, 0x9a, 0x6d, 0x75, 0x54, 0xed, 0xca, 0xf7, 0x03, 0x01,
	0x63, 0x5b, 0xdd, 0xb2, 0x61, 0x8a, 0x5e, 0x71, 0x65, 0xbb, 0x02, 0xe9,
	0xff, 0x1e, 0xc8, 0x6f, 0x27, 0xbc, 0xff, 0xf3, 0x56, 0xba, 0x61, 0x17,
	0x1e, 0x0c, 0xef, 0x78, 0x61, 0xce, 0x3a, 0x6b, 0xe7, 0x6c, 0x7d, 0x7f,
	0xd0, 0x0a,
};

static size_t run_test(int (*fn)(void))
{
	tests_run++;
	if (fn()) {
		tests_passed++;
		printf("PASS: %p\n", (void *)fn);
	}
	return 0;
}

static int test_option_constants_in_sync_with_spec(void)
{
	ASSERT_EQ(LICHEN_RPL_OPT_ROOT_DIO_SIGNATURE, 0x17, "option type 0x17");
	ASSERT_EQ(LICHEN_RPL_ROOT_DIO_SIGNATURE_MIN_LEN, 64, "min len");
	ASSERT_EQ(LICHEN_RPL_ROOT_DIO_SIGNATURE_MAX_LEN, 255, "max len");
	return 1;
}

static int test_dio_parse_accepts_vector_option(void)
{
	struct lichen_rpl_dio dio = {0};
	dio.rpl_instance_id = 0;
	dio.version = 1;
	dio.rank = 256;
	dio.mode_of_operation = 2;
	for (int i = 0; i < 16; i++) {
		dio.dodag_id[i] = (uint8_t)(0x20 + i);
	}
	uint8_t buf[2 + sizeof(vector_cose_sign1) + 32];
	size_t pos = 0;

	/* Option: type + len + blob */
	uint8_t opt[2 + sizeof(vector_cose_sign1)];
	opt[0] = LICHEN_RPL_OPT_ROOT_DIO_SIGNATURE;
	opt[1] = (uint8_t)sizeof(vector_cose_sign1);
	for (size_t i = 0; i < sizeof(vector_cose_sign1); i++) {
		opt[2 + i] = vector_cose_sign1[i];
	}

	uint8_t options[2 + sizeof(vector_cose_sign1)];
	options[0] = LICHEN_RPL_OPT_ROOT_DIO_SIGNATURE;
	options[1] = (uint8_t)sizeof(vector_cose_sign1);
	for (size_t i = 0; i < sizeof(vector_cose_sign1); i++) {
		options[2 + i] = vector_cose_sign1[i];
	}
	int n = lichen_rpl_dio_write_with_options(&dio, options,
						  sizeof(options), buf, sizeof(buf));
	ASSERT_EQ(n, 24 + (int)sizeof(options), "base+option write");
	pos = (size_t)n;

	struct lichen_rpl_dio dio_out;
	ASSERT_EQ(lichen_rpl_dio_parse(&dio_out, buf, pos), 0, "parse with root-sig option");

	/* Option chain is retrievable for receiver-side verification. */
	const uint8_t *chain = lichen_rpl_dio_options(buf, pos);
	ASSERT_EQ(chain == NULL, 0, "options present");
	ASSERT_EQ(lichen_rpl_dio_options_len(pos), 2 + sizeof(vector_cose_sign1),
		  "options len");
	/* First option byte is the type, second is the blob length. */
	ASSERT_EQ(chain[0], LICHEN_RPL_OPT_ROOT_DIO_SIGNATURE, "type byte");
	ASSERT_EQ(chain[1], sizeof(vector_cose_sign1), "blob length byte");
	for (size_t i = 0; i < sizeof(vector_cose_sign1); i++) {
		ASSERT_EQ(chain[2 + i], vector_cose_sign1[i], "blob byte");
	}
	return 1;
}

static int test_dio_parse_rejects_duplicate_root_sig(void)
{
	uint8_t buf[300];
	size_t pos = 0;
	{
		struct lichen_rpl_dio dio = {0};
		dio.rpl_instance_id = 0;
		dio.version = 1;
		dio.rank = 256;
		dio.mode_of_operation = 2;
		for (int i = 0; i < 16; i++) {
			dio.dodag_id[i] = (uint8_t)(0x20 + i);
		}
		ASSERT_EQ(lichen_rpl_dio_write(&dio, buf, sizeof(buf)), 24, "base write");
	}

	/* Two singleton root-sig options (short 64-byte blobs). */
	for (int copy = 0; copy < 2; copy++) {
		buf[pos++] = LICHEN_RPL_OPT_ROOT_DIO_SIGNATURE;
		buf[pos++] = (uint8_t)LICHEN_RPL_ROOT_DIO_SIGNATURE_MIN_LEN;
		for (int i = 0; i < LICHEN_RPL_ROOT_DIO_SIGNATURE_MIN_LEN; i++) {
			buf[pos++] = (uint8_t)i;
		}
	}

	struct lichen_rpl_dio dio_out;
	ASSERT_EQ(lichen_rpl_dio_parse(&dio_out, buf, pos), LICHEN_RPL_ERR_BAD_OPT,
		  "duplicate root-sig rejected");
	return 1;
}

static int test_dio_parse_rejects_too_short_blob(void)
{
	uint8_t buf[256];
	size_t pos = 0;
	{
		struct lichen_rpl_dio dio = {0};
		dio.rpl_instance_id = 0;
		dio.version = 1;
		dio.rank = 256;
		dio.mode_of_operation = 2;
		for (int i = 0; i < 16; i++) {
			dio.dodag_id[i] = (uint8_t)(0x20 + i);
		}
		ASSERT_EQ(lichen_rpl_dio_write(&dio, buf, sizeof(buf)), 24, "base write");
	}
	pos = 24;

	buf[pos++] = LICHEN_RPL_OPT_ROOT_DIO_SIGNATURE;
	buf[pos++] = (uint8_t)(LICHEN_RPL_ROOT_DIO_SIGNATURE_MIN_LEN - 1);
	for (int i = 0; i < LICHEN_RPL_ROOT_DIO_SIGNATURE_MIN_LEN - 1; i++) {
		buf[pos++] = 0;
	}

	struct lichen_rpl_dio dio_out;
	ASSERT_EQ(lichen_rpl_dio_parse(&dio_out, buf, pos), LICHEN_RPL_ERR_BAD_OPT,
		  "short blob rejected");
	return 1;
}

static int test_dio_parse_accepts_max_len_blob(void)
{
	uint8_t buf[24 + 2 + LICHEN_RPL_ROOT_DIO_SIGNATURE_MAX_LEN + 8];
	size_t pos = 0;
	{
		struct lichen_rpl_dio dio = {0};
		dio.rpl_instance_id = 0;
		dio.version = 1;
		dio.rank = 256;
		dio.mode_of_operation = 2;
		for (int i = 0; i < 16; i++) {
			dio.dodag_id[i] = (uint8_t)(0x20 + i);
		}
		ASSERT_EQ(lichen_rpl_dio_write(&dio, buf, sizeof(buf)), 24, "base write");
	}
	pos = 24;

	buf[pos++] = LICHEN_RPL_OPT_ROOT_DIO_SIGNATURE;
	buf[pos++] = (uint8_t)LICHEN_RPL_ROOT_DIO_SIGNATURE_MAX_LEN;
	for (size_t i = 0; i < LICHEN_RPL_ROOT_DIO_SIGNATURE_MAX_LEN; i++) {
		buf[pos++] = (uint8_t)(i & 0xff);
	}

	struct lichen_rpl_dio dio_out;
	ASSERT_EQ(lichen_rpl_dio_parse(&dio_out, buf, pos), 0, "max blob accepted");
	return 1;
}

static int test_dio_parse_without_option_unaffected(void)
{
	/* L679: DIOs without the option parse normally. */
	uint8_t buf[24];
	struct lichen_rpl_dio dio = {0};
	dio.rpl_instance_id = 0;
	dio.version = 1;
	dio.rank = 256;
	dio.grounded = true;
	dio.mode_of_operation = 2;
	dio.preference = 0;
	dio.dtsn = 0;
	dio.flags = 0;
	for (int i = 0; i < 16; i++) {
		dio.dodag_id[i] = (uint8_t)(0x20 + i);
	}

	ASSERT_EQ(lichen_rpl_dio_write(&dio, buf, sizeof(buf)), 24, "base write");
	struct lichen_rpl_dio out;
	ASSERT_EQ(lichen_rpl_dio_parse(&out, buf, 24), 0, "option-less parse ok");
	ASSERT_EQ(out.dodag_id[0], 0x20, "dodag preserved");
	return 1;
}

int main(void)
{
	run_test(test_option_constants_in_sync_with_spec);
	run_test(test_dio_parse_accepts_vector_option);
	run_test(test_dio_parse_rejects_duplicate_root_sig);
	run_test(test_dio_parse_rejects_too_short_blob);
	run_test(test_dio_parse_accepts_max_len_blob);
	run_test(test_dio_parse_without_option_unaffected);

	printf("%d/%d passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
