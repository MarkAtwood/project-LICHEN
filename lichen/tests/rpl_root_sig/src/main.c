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
#include <lichen/rpl_root_dio_sig.h>
#include <lichen/root_dio_replay.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>

static int test_sha256(const uint8_t *input, size_t len, uint8_t out[32])
{
	struct tc_sha256_state_struct s;
	if (tc_sha256_init(&s) != TC_CRYPTO_SUCCESS) return -1;
	if (tc_sha256_update(&s, input, len) != TC_CRYPTO_SUCCESS) return -1;
	return tc_sha256_final(out, &s) == TC_CRYPTO_SUCCESS ? 0 : -1;
}

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
	0xff, 0x1e, 0xc8, 0x6f, 0x27, 0x6b, 0xcf, 0xff, 0x35, 0x6b, 0xa6, 0x11,
	0x71, 0xe0, 0xce, 0xf7, 0x86, 0x1c, 0xe3, 0xa6, 0xbe, 0x76, 0xc6, 0xd7,
	0xfd, 0x00,
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
	pos = 24;

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

/* Signer pubkey from the committed vector (hex decoded). */
static const uint8_t vector_pubkey[32] = {
	0xe7, 0xa9, 0x6e, 0xf0, 0x7e, 0x66, 0xea, 0x92, 0x37, 0xf0, 0x3a, 0x46,
	0x74, 0xbb, 0xf4, 0x3a, 0x8c, 0x1c, 0x9e, 0xb2, 0x7e, 0xdd, 0x23, 0x9f,
	0xb5, 0xac, 0x09, 0x87, 0x35, 0xaf, 0xb0, 0xdf,
};

static int test_root_sig_decode_valid_vector(void)
{
	struct root_dio_sig sig;
	int ret = root_dio_sig_decode(vector_cose_sign1, sizeof(vector_cose_sign1), &sig);
	uint8_t expected_kid[8] = { 0x20, 0x3d, 0xf4, 0x66, 0x2a, 0xb8, 0x1f, 0x5a };

	ASSERT_EQ(ret, ROOT_SIG_OK, "decode valid vector");
	ASSERT_EQ(memcmp(sig.root_iid, expected_kid, 8), 0, "kid");
	ASSERT_EQ(sig.payload.instance, 0, "instance");
	ASSERT_EQ(sig.payload.version, 1, "version");
	ASSERT_EQ(sig.payload.rank, 256, "rank");
	ASSERT_EQ(sig.payload.expiry, 1735689600U, "expiry");
	ASSERT_EQ(sig.payload.root_seq, 1, "root_seq");
	ASSERT_EQ(sig.payload.mop, 2, "mop");
	return 1;
}

static int test_root_sig_structural_ok_and_expiry(void)
{
	struct root_dio_sig sig;
	int ret = root_dio_sig_decode(vector_cose_sign1, sizeof(vector_cose_sign1), &sig);
	uint8_t dio_dodag[16];

	memcpy(dio_dodag, sig.payload.dodag_id, 16);
	ASSERT_EQ(ret, ROOT_SIG_OK, "decode");

	ret = root_dio_sig_verify_structural(&sig, vector_pubkey, 32,
					     1735689600U - 1U, dio_dodag, 0, 1, 256, 2);
	ASSERT_EQ(ret, ROOT_SIG_OK, "structural ok pre-expiry");

	ret = root_dio_sig_verify_structural(&sig, vector_pubkey, 32,
					     1735689600U, dio_dodag, 0, 1, 256, 2);
	ASSERT_EQ(ret, ROOT_SIG_ERR_EXPIRED, "expired at boundary");
	return 1;
}

static int test_root_sig_structural_rejects_mismatches(void)
{
	struct root_dio_sig sig;
	uint8_t other_dodag[16];
	int ret = root_dio_sig_decode(vector_cose_sign1, sizeof(vector_cose_sign1), &sig);
	uint8_t dio_dodag[16];

	memcpy(dio_dodag, sig.payload.dodag_id, 16);
	for (int i = 0; i < 16; i++) {
		other_dodag[i] = (uint8_t)(0x30 + i);
	}

	/* DIO header cross-checks. */
	ret = root_dio_sig_verify_structural(&sig, vector_pubkey, 32,
					     1735689600U - 1U, other_dodag, 0, 1, 256, 2);
	ASSERT_EQ(ret, ROOT_SIG_ERR_DODAGID_MISMATCH, "dodag cross-check");
	ret = root_dio_sig_verify_structural(&sig, vector_pubkey, 32,
					     1735689600U - 1U, dio_dodag, 1, 1, 256, 2);
	ASSERT_EQ(ret, ROOT_SIG_ERR_INSTANCE_MISMATCH, "instance cross-check");
	ret = root_dio_sig_verify_structural(&sig, vector_pubkey, 32,
					     1735689600U - 1U, dio_dodag, 0, 2, 256, 2);
	ASSERT_EQ(ret, ROOT_SIG_ERR_VERSION_MISMATCH, "version cross-check");
	ret = root_dio_sig_verify_structural(&sig, vector_pubkey, 32,
					     1735689600U - 1U, dio_dodag, 0, 1, 512, 2);
	ASSERT_EQ(ret, ROOT_SIG_ERR_RANK_MISMATCH, "rank cross-check");
	ret = root_dio_sig_verify_structural(&sig, vector_pubkey, 32,
					     1735689600U - 1U, dio_dodag, 0, 1, 256, 3);
	ASSERT_EQ(ret, ROOT_SIG_ERR_MOP_MISMATCH, "mop cross-check");
	return 1;
}

static int test_root_sig_decode_rejects_garbage(void)
{
	struct root_dio_sig sig;
	ASSERT_EQ(root_dio_sig_decode(NULL, 0, &sig), -ROOT_SIG_ERR_DECODE, "null");
	for (size_t len = 0; len < 64; len++) {
		ASSERT_EQ(root_dio_sig_decode(vector_cose_sign1, len, &sig),
			  -ROOT_SIG_ERR_DECODE, "truncated");
	}
	return 1;
}



static const uint8_t cache_dodag_a[16] = { 0x20, 0x30, 0x31, 0x32, 0x33, 0x34,
					   0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
					   0x3b, 0x3c, 0x3d, 0x3e };
static const uint8_t cache_dodag_b[16] = { 0x21, 0x30, 0x31, 0x32, 0x33, 0x34,
					   0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
					   0x3b, 0x3c, 0x3d, 0x3e };

static int test_replay_cache_first_observation_admitted(void)
{
	struct root_dio_replay_cache cache;
	root_dio_replay_cache_init(&cache);
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, cache_dodag_a, 0, 7),
		  ROOT_SIG_OK, "first admitted");
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, cache_dodag_a, 0, 9),
		  ROOT_SIG_OK, "higher admitted");
	return 1;
}

static int test_replay_cache_rejects_equal_and_lower(void)
{
	struct root_dio_replay_cache cache;
	root_dio_replay_cache_init(&cache);
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, cache_dodag_a, 0, 9),
		  ROOT_SIG_OK, "admit 9");
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, cache_dodag_a, 0, 9),
		  -ROOT_SIG_ERR_REPLAY_DETECTED, "equal replay");
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, cache_dodag_a, 0, 8),
		  -ROOT_SIG_ERR_REPLAY_DETECTED, "lower replay");
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, cache_dodag_a, 0, 1),
		  -ROOT_SIG_ERR_REPLAY_DETECTED, "post-wrap rejected");
	return 1;
}

static int test_replay_cache_keys_isolated(void)
{
	struct root_dio_replay_cache cache;
	root_dio_replay_cache_init(&cache);
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, cache_dodag_a, 0, 5),
		  ROOT_SIG_OK, "A/0");
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, cache_dodag_b, 0, 5),
		  ROOT_SIG_OK, "B/0 first");
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, cache_dodag_a, 1, 5),
		  ROOT_SIG_OK, "A/1 first");
	return 1;
}

static int test_replay_cache_full_table_fails_closed(void)
{
	struct root_dio_replay_cache cache;
	uint8_t dodag[16];

	root_dio_replay_cache_init(&cache);
	for (size_t i = 0; i < LICHEN_ROOT_DIO_REPLAY_MAX_KEYS; i++) {
		memset(dodag, (int)i, 16);
		ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, dodag, 0, 1),
			  ROOT_SIG_OK, "fill");
	}
	memset(dodag, (int)LICHEN_ROOT_DIO_REPLAY_MAX_KEYS, 16);
	ASSERT_EQ(root_dio_replay_cache_check_and_admit(&cache, dodag, 0, 1),
		  -ROOT_SIG_ERR_REPLAY_DETECTED, "full");
	return 1;
}



static int test_root_sig_verify_signature_valid_vector(void)
{
	struct root_dio_sig sig;
	int ret = root_dio_sig_decode(vector_cose_sign1, sizeof(vector_cose_sign1), &sig);
	ASSERT_EQ(ret, ROOT_SIG_OK, "decode");
	ret = root_dio_sig_verify_signature(&sig, vector_pubkey, test_sha256);
	ASSERT_EQ(ret, ROOT_SIG_OK, "valid signature verifies");
	return 1;
}

static int test_root_sig_verify_signature_rejects_tampered(void)
{
	uint8_t blob[sizeof(vector_cose_sign1)];
	struct root_dio_sig sig;
	memcpy(blob, vector_cose_sign1, sizeof(vector_cose_sign1));
	/* Flip one signature bit (vector root_dio_signature_tampered: byte 0 of
	 * the 48-byte signature, which starts at COSE offset 62). */
	blob[62] ^= 0x01;
	int ret = root_dio_sig_decode(blob, sizeof(blob), &sig);
	ASSERT_EQ(ret, ROOT_SIG_OK, "tampered still decodes");
	ret = root_dio_sig_verify_signature(&sig, vector_pubkey, test_sha256);
	ASSERT_EQ(ret, -ROOT_SIG_ERR_SIGNATURE, "tampered rejected");
	return 1;
}

static int test_root_sig_verify_signature_rejects_zero(void)
{
	uint8_t blob[sizeof(vector_cose_sign1)];
	struct root_dio_sig sig;
	memcpy(blob, vector_cose_sign1, sizeof(vector_cose_sign1));
	/* Zero the 48-byte signature (COSE offset 62..109). */
	memset(&blob[62], 0, 48);
	int ret = root_dio_sig_decode(blob, sizeof(blob), &sig);
	ASSERT_EQ(ret, ROOT_SIG_OK, "zero sig decodes");
	ret = root_dio_sig_verify_signature(&sig, vector_pubkey, test_sha256);
	ASSERT_EQ(ret, -ROOT_SIG_ERR_SIGNATURE, "zero sig rejected");
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
	run_test(test_root_sig_decode_valid_vector);
	run_test(test_root_sig_structural_ok_and_expiry);
	run_test(test_root_sig_structural_rejects_mismatches);
	run_test(test_root_sig_decode_rejects_garbage);
	run_test(test_root_sig_verify_signature_valid_vector);
	run_test(test_root_sig_verify_signature_rejects_tampered);
	run_test(test_root_sig_verify_signature_rejects_zero);
	run_test(test_replay_cache_first_observation_admitted);
	run_test(test_replay_cache_rejects_equal_and_lower);
	run_test(test_replay_cache_keys_isolated);
	run_test(test_replay_cache_full_table_fails_closed);

	printf("%d/%d passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
