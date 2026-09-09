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

/* Regenerated for upstream Yggdrasil addressing (i72x.1): DODAGID =
 * upstream AddrForKey(vector_pubkey) = 020030ad221f03322adb901f8b731688
 * (oracle: yggdrasil-go@422836ee address_test.go anchor, via an
 * independent port — never the C impl); signatures produced by Python's
 * schnorr48 create_root_dio_signature over that DODAGID (independent
 * crypto oracle). Mirrors the shape of
 * test/vectors/root_dio_signature.json :: root_dio_signature_valid_basic;
 * the shared JSON still encodes the rejected native profile and is
 * regenerated when Rust (i72x.2) and Python land their migrations. */
static const uint8_t vector_cose_sign1[] = {
	0xd2, 0x84, 0x47, 0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0xa1, 0x04,
	0x48, 0x20, 0x3d, 0xf4, 0x66, 0x2a, 0xb8, 0x1f, 0x5a, 0x58, 0x25, 0xa7,
	0x01, 0x50, 0x02, 0x00, 0x30, 0xad, 0x22, 0x1f, 0x03, 0x32, 0x2a, 0xdb,
	0x90, 0x1f, 0x8b, 0x73, 0x16, 0x88, 0x02, 0x00, 0x03, 0x01, 0x04, 0x19,
	0x01, 0x00, 0x05, 0x1a, 0x67, 0x74, 0x85, 0x80, 0x06, 0x01, 0x07, 0x02,
	0x58, 0x30, 0xc3, 0x78, 0xcb, 0x37, 0xff, 0xdb, 0x7f, 0xe3, 0x65, 0xe8,
	0x8a, 0x94, 0xf4, 0x0d, 0xcf, 0x34, 0xc4, 0x62, 0xa0, 0xd5, 0x5e, 0x15,
	0xf3, 0x10, 0xbe, 0xb2, 0x5b, 0x3b, 0xfd, 0x7e, 0x96, 0x55, 0x58, 0x57,
	0xdf, 0x9f, 0x33, 0xa5, 0x0c, 0x94, 0x9f, 0xa1, 0x20, 0x37, 0x84, 0x33,
	0x25, 0x02,
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

/* ── dodag-path admission (lichen_rpl_dodag_process_dio_bytes_root_sig,
 *    spec 06-security.md 8.10.1; mirrors the Rust receiver semantics) ──── */

#include <lichen/rpl_dodag.h>

/* dodag.c's ASSIGNED_SF push (extern declaration in dodag.c). */
static uint8_t lora_l2_last_assigned_sf;
void lora_l2_assign_sf(uint8_t sf) { lora_l2_last_assigned_sf = sf; }

/* Vector dodag_id: upstream AddrForKey(vector_pubkey) — regenerated for
 * i72x.1 (shape mirrors root_dio_signature_valid_basic.dodag_id; the
 * shared JSON's native-profile value 02203df4... regenerates with the
 * Rust/Python migrations). */
static const uint8_t vector_dodag_id[16] = {
	0x02, 0x00, 0x30, 0xad, 0x22, 0x1f, 0x03, 0x32,
	0x2a, 0xdb, 0x90, 0x1f, 0x8b, 0x73, 0x16, 0x88,
};

/* Impersonation vector attacker pubkey:
 * root_dio_signature_impersonation.attacker_pubkey (unchanged — key
 * material does not depend on the address profile). */
static const uint8_t attacker_pubkey[32] = {
	0x68, 0xae, 0x16, 0xcc, 0x01, 0xf1, 0xe7, 0x40, 0xb2, 0x57, 0x53, 0xba,
	0x11, 0x73, 0x6c, 0xfb, 0x65, 0x74, 0x84, 0x60, 0x65, 0x8e, 0x67, 0xd1,
	0x3b, 0x75, 0xed, 0xf5, 0xf2, 0xf5, 0x04, 0x87,
};

/* Attacker-signed claim over the VICTIM's upstream-derived DODAGID
 * (regenerated for i72x.1; expected.error = dodagid_mismatch — the
 * attacker's AddrForKey output does not equal the claimed DODAGID). */
static const uint8_t impersonation_cose_sign1[] = {
	0xd2, 0x84, 0x47, 0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0xa1, 0x04,
	0x48, 0xb0, 0xb6, 0x49, 0x8d, 0x1d, 0x36, 0x94, 0x86, 0x58, 0x25, 0xa7,
	0x01, 0x50, 0x02, 0x00, 0x30, 0xad, 0x22, 0x1f, 0x03, 0x32, 0x2a, 0xdb,
	0x90, 0x1f, 0x8b, 0x73, 0x16, 0x88, 0x02, 0x00, 0x03, 0x01, 0x04, 0x19,
	0x01, 0x00, 0x05, 0x1a, 0x67, 0x74, 0x85, 0x80, 0x06, 0x01, 0x07, 0x02,
	0x58, 0x30, 0x62, 0x5f, 0xc8, 0xe9, 0x0e, 0x45, 0xc2, 0x2d, 0x35, 0xd0,
	0x9b, 0x08, 0xae, 0xb7, 0x19, 0xcd, 0xa8, 0xd4, 0xb5, 0x86, 0xc1, 0xd7,
	0x7e, 0x12, 0xfa, 0xf2, 0xe7, 0xbb, 0xfd, 0x70, 0x5b, 0x2b, 0xbf, 0x28,
	0x55, 0xd8, 0xcc, 0xcd, 0xf0, 0x9d, 0x44, 0xac, 0x8d, 0x7c, 0x93, 0x9c,
	0x37, 0x0e,
};

/* Far-expiry variant (same key/upstream DODAGID as vector_cose_sign1,
 * expiry 4102444800; regenerated for i72x.1 — mirrors the shape of
 * root_dio_signature_valid_far_expiry). */
static const uint8_t far_expiry_cose_sign1[] = {
	0xd2, 0x84, 0x47, 0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0xa1, 0x04,
	0x48, 0x20, 0x3d, 0xf4, 0x66, 0x2a, 0xb8, 0x1f, 0x5a, 0x58, 0x25, 0xa7,
	0x01, 0x50, 0x02, 0x00, 0x30, 0xad, 0x22, 0x1f, 0x03, 0x32, 0x2a, 0xdb,
	0x90, 0x1f, 0x8b, 0x73, 0x16, 0x88, 0x02, 0x00, 0x03, 0x01, 0x04, 0x19,
	0x01, 0x00, 0x05, 0x1a, 0xf4, 0x86, 0x57, 0x00, 0x06, 0x01, 0x07, 0x02,
	0x58, 0x30, 0xf6, 0x9d, 0xe4, 0x23, 0x14, 0x4e, 0x37, 0x23, 0xb2, 0xdb,
	0xca, 0x53, 0x4b, 0x35, 0x79, 0x4a, 0x59, 0xcc, 0xee, 0x74, 0x3e, 0xae,
	0x94, 0xf3, 0x94, 0x3c, 0x8d, 0x43, 0xb9, 0xcc, 0x9b, 0x54, 0x4a, 0xc9,
	0x82, 0x05, 0x6f, 0x73, 0x90, 0xa4, 0xa3, 0xe3, 0xcd, 0x1c, 0xc8, 0x1b,
	0xcd, 0x0d,
};

#define DODAG_TEST_BASIC_EXPIRY 1735689600U
#define DODAG_TEST_FAR_EXPIRY 4102444800U

/* Build a DIO carrying the given COSE blob plus the mandatory SCHC Rule
 * Version option; rank_carrier allows a deliberately mismatched carrier. */
static size_t build_signed_dio(uint8_t *buf, size_t buflen,
			       const uint8_t *cose, size_t cose_len,
			       uint16_t rank_carrier)
{
	static const uint8_t schc_opt[3] = { LICHEN_RPL_OPT_SCHC_RULE_VERSION,
					     0x01,
					     LICHEN_SCHC_RULE_SET_VERSION };
	struct lichen_rpl_dio dio = { 0 };

	dio.rpl_instance_id = 0;
	dio.version = 1;
	dio.rank = rank_carrier;
	dio.grounded = true;
	dio.mode_of_operation = 2;
	memcpy(dio.dodag_id, vector_dodag_id, 16);

	uint8_t options[2 + LICHEN_RPL_ROOT_DIO_SIGNATURE_MAX_LEN + 3];
	size_t pos = 0;

	if (cose != NULL) {
		options[pos++] = LICHEN_RPL_OPT_ROOT_DIO_SIGNATURE;
		options[pos++] = (uint8_t)cose_len;
		memcpy(&options[pos], cose, cose_len);
		pos += cose_len;
	}
	memcpy(&options[pos], schc_opt, sizeof(schc_opt));
	pos += sizeof(schc_opt);

	int n = lichen_rpl_dio_write_with_options(&dio, options, pos, buf,
						  buflen);
	return (size_t)n;
}

static size_t build_plain_dio(uint8_t *buf, size_t buflen)
{
	return build_signed_dio(buf, buflen, NULL, 0, 256U);
}

/* Far-expiry vector always validates against the pinned root key. */
static int dodag_process_far_expiry(struct lichen_rpl_dodag *d,
				    struct root_dio_replay_cache *replay,
				    const uint8_t *root_pubkey,
				    uint8_t *buf, size_t buflen)
{
	size_t len = build_signed_dio(buf, buflen, far_expiry_cose_sign1,
				      sizeof(far_expiry_cose_sign1), 256U);
	return lichen_rpl_dodag_process_dio_bytes_root_sig(
		d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true, replay,
		root_pubkey, true, DODAG_TEST_FAR_EXPIRY - 1U, test_sha256);
}

static int test_dodag_absent_option_is_baseline(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	size_t len = build_plain_dio(buf, sizeof(buf));
	int ret = lichen_rpl_dodag_process_dio_bytes_root_sig(
		&d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true, &cache,
		vector_pubkey, true, DODAG_TEST_FAR_EXPIRY - 1U, test_sha256);
	/* L679: no option -> link-layer baseline; DIO still processes
	 * (returns without the root-sig reject code). */
	ASSERT_EQ(ret, 0, "absent option processed");
	ASSERT_EQ(root_dio_replay_cache_seen(&cache, vector_dodag_id, 0, 1),
		  false, "baseline does not touch cache");
	return 1;
}

static int test_dodag_verified_admits_seq(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	int ret = dodag_process_far_expiry(&d, &cache, vector_pubkey, buf, sizeof(buf));
	ASSERT_EQ(ret >= 0, 1, "verified DIO not rejected");
	ASSERT_EQ(root_dio_replay_cache_seen(&cache, vector_dodag_id, 0, 1),
		  true, "root_seq admitted after full validation");
	return 1;
}

static int test_dodag_tampered_rejects_without_cache_mutation(void)
{
	uint8_t buf[300];
	uint8_t blob[sizeof(vector_cose_sign1)];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	memcpy(blob, vector_cose_sign1, sizeof(blob));
	blob[62] ^= 0x01; /* signature bit flip (root_dio_signature_tampered) */

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	size_t len = build_signed_dio(buf, sizeof(buf), blob, sizeof(blob), 256U);
	int ret = lichen_rpl_dodag_process_dio_bytes_root_sig(
		&d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true, &cache,
		vector_pubkey, true, DODAG_TEST_BASIC_EXPIRY - 1U, test_sha256);
	ASSERT_EQ(ret, LICHEN_RPL_ERR_BAD_OPT, "tampered rejected");
	ASSERT_EQ(d.role, LICHEN_RPL_UNJOINED, "state unchanged on reject");
	ASSERT_EQ(root_dio_replay_cache_seen(&cache, vector_dodag_id, 0, 1),
		  false, "cache untouched on tamper");
	return 1;
}

static int test_dodag_impersonation_rejects(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	/* Pin the ATTACKER key: kid matches the pin, signature verifies, but
	 * the claimed DODAGID does not derive from the attacker key. */
	size_t len = build_signed_dio(buf, sizeof(buf), impersonation_cose_sign1,
				      sizeof(impersonation_cose_sign1), 256U);
	int ret = lichen_rpl_dodag_process_dio_bytes_root_sig(
		&d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true, &cache,
		attacker_pubkey, true, DODAG_TEST_BASIC_EXPIRY - 1U,
		test_sha256);
	ASSERT_EQ(ret, LICHEN_RPL_ERR_BAD_OPT, "impersonation rejected");
	ASSERT_EQ(root_dio_replay_cache_seen(&cache, vector_dodag_id, 0, 1),
		  false, "cache untouched on binding failure");
	return 1;
}

static int test_dodag_replay_rejected(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	ASSERT_EQ(dodag_process_far_expiry(&d, &cache, vector_pubkey, buf, sizeof(buf)) >= 0, 1,
		  "first admitted");
	int ret = dodag_process_far_expiry(&d, &cache, vector_pubkey, buf, sizeof(buf));
	ASSERT_EQ(ret, LICHEN_RPL_ERR_BAD_OPT, "same root_seq replayed");
	return 1;
}

static int test_dodag_expired_is_baseline(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	/* basic vector expiry 1735689600: at the boundary the signature is
	 * expired -> treat as unsigned, DIO still processes, seq NOT cached. */
	size_t len = build_signed_dio(buf, sizeof(buf), vector_cose_sign1,
				      sizeof(vector_cose_sign1), 256U);
	int ret = lichen_rpl_dodag_process_dio_bytes_root_sig(
		&d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true, &cache,
		vector_pubkey, true, DODAG_TEST_BASIC_EXPIRY, test_sha256);
	ASSERT_EQ(ret, 0, "expired processed on baseline");
	ASSERT_EQ(root_dio_replay_cache_seen(&cache, vector_dodag_id, 0, 1),
		  false, "baseline does not admit seq");
	return 1;
}

static int test_dodag_no_pin_is_baseline(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	ASSERT_EQ(dodag_process_far_expiry(&d, &cache, NULL, buf, sizeof(buf)) >=
			  0,
		  1, "no pin: baseline");
	ASSERT_EQ(root_dio_replay_cache_seen(&cache, vector_dodag_id, 0, 1),
		  false, "no pin: cache untouched");
	return 1;
}

static int test_dodag_foreign_pin_is_baseline(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	/* Pin held for a different identity: no pin for the claimed root
	 * (Rust pinned_pubkey_for(kid) -> None), so baseline, not reject. */
	size_t len = build_signed_dio(buf, sizeof(buf), far_expiry_cose_sign1,
				      sizeof(far_expiry_cose_sign1), 256U);
	int ret = lichen_rpl_dodag_process_dio_bytes_root_sig(
		&d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true, &cache,
		attacker_pubkey, true, DODAG_TEST_FAR_EXPIRY - 1U, test_sha256);
	ASSERT_EQ(ret >= 0, 1, "foreign pin: baseline");
	ASSERT_EQ(root_dio_replay_cache_seen(&cache, vector_dodag_id, 0, 1),
		  false, "foreign pin: cache untouched");
	return 1;
}

static int test_dodag_no_clock_is_baseline(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	/* have_clock=false: expiry unassessable (R-06-307). */
	size_t len = build_signed_dio(buf, sizeof(buf), far_expiry_cose_sign1,
				      sizeof(far_expiry_cose_sign1), 256U);
	int ret = lichen_rpl_dodag_process_dio_bytes_root_sig(
		&d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true, &cache,
		vector_pubkey, false, 0U, test_sha256);
	ASSERT_EQ(ret >= 0, 1, "no clock: baseline");
	ASSERT_EQ(root_dio_replay_cache_seen(&cache, vector_dodag_id, 0, 1),
		  false, "no clock: cache untouched");
	return 1;
}

static int test_dodag_carrier_mismatch_rejects(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);

	/* Valid far-expiry signature carried on a rank-mismatched DIO: the
	 * cross-check must reject and must NOT burn root_seq 1. */
	size_t len = build_signed_dio(buf, sizeof(buf), far_expiry_cose_sign1,
				      sizeof(far_expiry_cose_sign1), 512U);
	int ret = lichen_rpl_dodag_process_dio_bytes_root_sig(
		&d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true, &cache,
		vector_pubkey, true, DODAG_TEST_FAR_EXPIRY - 1U, test_sha256);
	ASSERT_EQ(ret, LICHEN_RPL_ERR_BAD_OPT, "carrier mismatch rejected");
	ASSERT_EQ(root_dio_replay_cache_seen(&cache, vector_dodag_id, 0, 1),
		  false, "cache untouched on carrier mismatch");
	return 1;
}

static int test_dodag_null_guards(void)
{
	uint8_t buf[300];
	struct lichen_rpl_dodag d;
	struct root_dio_replay_cache cache;

	ASSERT_EQ(lichen_rpl_dodag_init(&d, 0, vector_dodag_id, 1), 0, "init");
	root_dio_replay_cache_init(&cache);
	size_t len = build_plain_dio(buf, sizeof(buf));
	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes_root_sig(
			  NULL, buf, len, vector_dodag_id, 256U, 0U, 1000U,
			  true, &cache, vector_pubkey, true, 0U, test_sha256),
		  LICHEN_RPL_ERR_INVALID, "null dodag");
	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes_root_sig(
			  &d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true,
			  NULL, vector_pubkey, true, 0U, test_sha256),
		  LICHEN_RPL_ERR_INVALID, "null cache");
	ASSERT_EQ(lichen_rpl_dodag_process_dio_bytes_root_sig(
			  &d, buf, len, vector_dodag_id, 256U, 0U, 1000U, true,
			  &cache, vector_pubkey, true, 0U, NULL),
		  LICHEN_RPL_ERR_INVALID, "null sha256");
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
	run_test(test_dodag_absent_option_is_baseline);
	run_test(test_dodag_verified_admits_seq);
	run_test(test_dodag_tampered_rejects_without_cache_mutation);
	run_test(test_dodag_impersonation_rejects);
	run_test(test_dodag_replay_rejected);
	run_test(test_dodag_expired_is_baseline);
	run_test(test_dodag_no_pin_is_baseline);
	run_test(test_dodag_foreign_pin_is_baseline);
	run_test(test_dodag_no_clock_is_baseline);
	run_test(test_dodag_carrier_mismatch_rejects);
	run_test(test_dodag_null_guards);

	printf("%d/%d passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
