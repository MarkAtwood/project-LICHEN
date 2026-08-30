/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief Host tests for GCP-6.5 slot-claim COSE_Sign1 encode/decode/verify
 *
 * Covers lichen_slot_coord_sign_claim/decode_claim/process_claim against
 * spec/08-gateway-coordination.md GCP-6.5:
 * - valid claim round-trip and acceptance
 * - any payload/signature byte mutation fails verification (the parent
 *   bead's forgery regression: the slots array is covered by the signature)
 * - unknown signer, expiry, claim_seq replay, persist failure gates
 * - structural rejections: non-canonical protected header (-65536 decoy),
 *   kid/gateway_iid mismatch, truncated signature, unknown/duplicate/
 *   missing payload keys, trailing bytes
 *
 * Independent oracles: SHA-256 known-answer (FIPS 180-2), the spec's
 * protected-header hex literal h'47A1013A00010000', and schnorr48 itself
 * (validated against test/vectors/schnorr48.json by lichen/tests/schnorr48).
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>

#include <lichen/coap_slot_coord.h>
#include <lichen/coap_keys.h>
#include <lichen/schnorr48.h>

/* Reference identities: distinct seeds so no two gateways share a key. */
static const uint8_t SEED_A[32] = { 'A' }; /* zero-padded */
static const uint8_t SEED_B[32] = { 'B' };
static const uint8_t SEED_UNKNOWN[32] = { 'U' };

static uint8_t pubkey_a[32], pubkey_b[32], pubkey_unknown[32];
static uint8_t privkey_a[32], privkey_b[32], privkey_unknown[32];

/* Test identity table: one row per gateway key material. */
struct test_identity {
	const uint8_t iid[LICHEN_IID_LEN];
	const uint8_t *privkey;
	const uint8_t *pubkey;
};

static const struct test_identity IDENTITIES[] = {
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 },
	  privkey_a, pubkey_a },
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 },
	  privkey_b, pubkey_b },
	{ { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e },
	  privkey_unknown, pubkey_unknown },
};

#define IID_A (IDENTITIES[0].iid)
#define IID_B (IDENTITIES[1].iid)
#define IID_UNKNOWN (IDENTITIES[2].iid)

static const struct test_identity *identity_for(const uint8_t iid[LICHEN_IID_LEN])
{
	for (size_t i = 0; i < sizeof(IDENTITIES) / sizeof(IDENTITIES[0]); i++) {
		if (memcmp(iid, IDENTITIES[i].iid, LICHEN_IID_LEN) == 0) {
			return &IDENTITIES[i];
		}
	}
	return NULL;
}

/* --------------------------------------------------------------------------
 * Fake key store (production lives in coap_keys_store.c, not built on host)
 * -------------------------------------------------------------------------- */

int lichen_key_store_get(const uint8_t iid[LICHEN_KEY_IID_LEN],
			 struct lichen_key_entry *entry)
{
	/* The store knows the two peer gateways (A, B) only; the third
	 * identity signs the unknown-signer case and MUST resolve to
	 * -ENOENT. */
	for (size_t i = 0; i < 2; i++) {
		if (memcmp(iid, IDENTITIES[i].iid, LICHEN_IID_LEN) == 0) {
			memset(entry, 0, sizeof(*entry));
			memcpy(entry->iid, iid, LICHEN_IID_LEN);
			memcpy(entry->pubkey, IDENTITIES[i].pubkey, 32);
			entry->trust = LICHEN_KEY_TRUST_TOFU;
			entry->valid = true;
			return 0;
		}
	}
	return -ENOENT;
}

/* --------------------------------------------------------------------------
 * Strong overrides of the weak claim_seq hooks (interposition check)
 * -------------------------------------------------------------------------- */

struct seq_cache {
	bool present;
	uint32_t seq;
	bool commit_fails;
	int commit_calls;
};

static struct seq_cache seq_cache_a;
static struct seq_cache seq_cache_b;

static struct seq_cache *seq_cache_for(const uint8_t iid[LICHEN_IID_LEN])
{
	if (memcmp(iid, IID_A, LICHEN_IID_LEN) == 0) {
		return &seq_cache_a;
	}
	if (memcmp(iid, IID_B, LICHEN_IID_LEN) == 0) {
		return &seq_cache_b;
	}
	return NULL;
}

int lichen_slot_claim_seq_lookup(const uint8_t iid[LICHEN_IID_LEN],
				 uint32_t *cached)
{
	struct seq_cache *c = seq_cache_for(iid);

	if (c == NULL || !c->present) {
		return -ENOENT;
	}
	*cached = c->seq;
	return 0;
}

int lichen_slot_claim_seq_commit(const uint8_t iid[LICHEN_IID_LEN], uint32_t seq)
{
	struct seq_cache *c = seq_cache_for(iid);

	if (c == NULL) {
		return 0;
	}
	c->commit_calls++;
	if (c->commit_fails) {
		return -EIO;
	}
	c->present = true;
	c->seq = seq;
	return 0;
}

/* --------------------------------------------------------------------------
 * Minimal assertion harness
 * -------------------------------------------------------------------------- */

static int tests_run;
static int tests_failed;

#define CHECK(cond)                                                          \
	do {                                                                 \
		tests_run++;                                                 \
		if (!(cond)) {                                               \
			tests_failed++;                                      \
			printf("FAIL %s:%d: %s\n", __func__, __LINE__,       \
			       #cond);                                       \
		}                                                            \
	} while (0)

/* --------------------------------------------------------------------------
 * Helpers
 * -------------------------------------------------------------------------- */

/* FIPS 180-2 test vector: SHA-256("abc") */
static const uint8_t SHA256_ABC[TC_SHA256_DIGEST_SIZE] = {
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
	0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
	0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

static void test_sha256_known_answer(void)
{
	struct tc_sha256_state_struct sha;
	uint8_t digest[TC_SHA256_DIGEST_SIZE];

	CHECK(tc_sha256_init(&sha) == TC_CRYPTO_SUCCESS);
	CHECK(tc_sha256_update(&sha, (const uint8_t *)"abc", 3) ==
	      TC_CRYPTO_SUCCESS);
	CHECK(tc_sha256_final(digest, &sha) == TC_CRYPTO_SUCCESS);
	CHECK(memcmp(digest, SHA256_ABC, sizeof(digest)) == 0);
}

/* Spec/08 GCP-6.5 protected header: canonical {1: -65537}; the wire form
 * carries the 0x47 bstr length prefix (h'47A1013A00010000'). The
 * COSE_Sign1 array header (0x84) precedes it on the wire. */
static const uint8_t PROTECTED_WIRE[] = {
	0x47, 0xA1, 0x01, 0x3A, 0x00, 0x01, 0x00, 0x00
};

/* COSE kid key (RFC 9052 header parameter 4) */
#define COSE_KID_TEST 4

/* Test-local cap mirroring the production CLAIM_PAYLOAD_MAX */
#define CLAIM_PAYLOAD_TEST_MAX 255

/* Offset of the kid inside a produced COSE_Sign1: array header (1 byte)
 * + protected bstr (8 bytes) + canonical unprotected map a1 04 48
 * (3 bytes) = 12. */
#define KID_OFFSET 12

/* Fresh per-gateway hook state so replay/persist gates are exercised in
 * isolation per test. */
static void reset_seq_hooks(void)
{
	memset(&seq_cache_a, 0, sizeof(seq_cache_a));
	memset(&seq_cache_b, 0, sizeof(seq_cache_b));
}

static void fill_claim(struct lichen_slot_claim *claim,
		       const uint8_t iid[LICHEN_IID_LEN],
		       uint8_t ordinal, uint32_t seq, uint32_t expiry,
		       uint8_t mode)
{
	static const uint8_t slots[] = { 3, 11, 19, 27 };

	memset(claim, 0, sizeof(*claim));
	memcpy(claim->gateway_iid, iid, LICHEN_IID_LEN);
	claim->slot_count = 4;
	memcpy(claim->slots, slots, sizeof(slots));
	claim->superframe_id = 4242;
	claim->ordinal = ordinal;
	claim->mode = mode;
	claim->expiry = expiry;
	claim->claim_seq = seq;
}

static int sign_into(const uint8_t iid[LICHEN_IID_LEN], uint8_t ordinal,
		     uint32_t seq, uint32_t expiry, uint8_t mode,
		     uint8_t *buf, size_t buf_len)
{
	const struct test_identity *id = identity_for(iid);

	if (id == NULL) {
		return -ENOENT;
	}

	struct lichen_slot_claim claim;

	fill_claim(&claim, iid, ordinal, seq, expiry, mode);
	return lichen_slot_coord_sign_claim(id->privkey, id->pubkey, &claim,
					    buf, buf_len);
}

/* Test-local CBOR writer for malformed-envelope cases the production
 * signer must never emit. */
struct tb {
	uint8_t buf[512];
	size_t len;
	bool overflow;
};

static void tb_u8(struct tb *t, uint8_t b)
{
	if (t->len < sizeof(t->buf)) {
		t->buf[t->len++] = b;
	} else {
		t->overflow = true;
	}
}

static void tb_bytes(struct tb *t, const void *data, size_t n)
{
	const uint8_t *p = data;

	for (size_t i = 0; i < n; i++) {
		tb_u8(t, p[i]);
	}
}

static void tb_head(struct tb *t, uint8_t major, uint64_t val)
{
	if (val < 24) {
		tb_u8(t, (uint8_t)((major << 5) | val));
	} else if (val <= UINT8_MAX) {
		tb_u8(t, (uint8_t)((major << 5) | 24));
		tb_u8(t, (uint8_t)val);
	} else {
		tb_u8(t, (uint8_t)((major << 5) | 26));
		tb_u8(t, (uint8_t)(val >> 24));
		tb_u8(t, (uint8_t)(val >> 16));
		tb_u8(t, (uint8_t)(val >> 8));
		tb_u8(t, (uint8_t)val);
	}
}

static void tb_bstr(struct tb *t, const void *data, size_t len)
{
	tb_head(t, 2, len);
	tb_bytes(t, data, len);
}

static void tb_uint(struct tb *t, uint64_t v)
{
	tb_head(t, 0, v);
}

/* Assemble [protected, {4: kid}, payload, sig] from parts. */
static void tb_cose(struct tb *t, const void *protected, size_t prot_len,
		    const uint8_t *kid, const void *payload, size_t payload_len,
		    const void *sig, size_t sig_len, size_t extra_elems,
		    const void *trailer, size_t trailer_len)
{
	tb_head(t, 4, 4 + extra_elems);
	tb_bstr(t, protected, prot_len);
	tb_head(t, 5, 1);
	tb_head(t, 0, COSE_KID_TEST);
	tb_bstr(t, kid, LICHEN_IID_LEN);
	tb_bstr(t, payload, payload_len);
	tb_bstr(t, sig, sig_len);
	tb_bytes(t, trailer, trailer_len);
}

/* Build the claim payload map (integer keys 1-7) test-side. With
 * with_key_mask, keys whose bit (1<<key) is clear is omitted; with
 * extra_key, key 8 is appended. */
static void tb_payload(struct tb *t, const struct lichen_slot_claim *claim,
		       unsigned with_key_mask, bool extra_key,
		       bool duplicate_key1)
{
	unsigned pair_count = 7;

	if (extra_key) {
		pair_count++;
	}
	if (duplicate_key1) {
		pair_count++;
	}
	tb_head(t, 5, pair_count);

	if (with_key_mask & (1u << 1u)) {
		tb_uint(t, 1);
		tb_head(t, 4, claim->slot_count);
		for (uint8_t i = 0; i < claim->slot_count; i++) {
			tb_uint(t, claim->slots[i]);
		}
		if (duplicate_key1) {
			tb_uint(t, 1);
			tb_head(t, 4, claim->slot_count);
			for (uint8_t i = 0; i < claim->slot_count; i++) {
				tb_uint(t, claim->slots[i]);
			}
		}
	}
	if (with_key_mask & (1u << 2u)) {
		tb_uint(t, 2);
		tb_uint(t, claim->superframe_id);
	}
	if (with_key_mask & (1u << 3u)) {
		tb_uint(t, 3);
		tb_uint(t, claim->mode);
	}
	if (with_key_mask & (1u << 4u)) {
		tb_uint(t, 4);
		tb_uint(t, claim->expiry);
	}
	if (with_key_mask & (1u << 5u)) {
		tb_uint(t, 5);
		tb_bstr(t, claim->gateway_iid, LICHEN_IID_LEN);
	}
	if (with_key_mask & (1u << 6u)) {
		tb_uint(t, 6);
		tb_uint(t, claim->claim_seq);
	}
	if (with_key_mask & (1u << 7u)) {
		tb_uint(t, 7);
		tb_uint(t, claim->ordinal);
	}
	if (extra_key) {
		tb_uint(t, 8);
		tb_uint(t, 0);
	}
}

#define PROCESS_OK(ctx_, cose_, len_, now_, want_)                          \
	process_claim_check((ctx_), (cose_), (len_), (now_), true, (want_), \
			    __func__)
#define PROCESS_NO_CLOCK(ctx_, cose_, len_, want_)                          \
	process_claim_check((ctx_), (cose_), (len_), 0, false, (want_),     \
			    __func__)

static void process_claim_check(struct lichen_slot_coord_ctx *ctx,
				const uint8_t *cose, size_t cose_len,
				uint64_t now, bool clock_valid,
				enum lichen_claim_result want,
				const char *caller)
{
	struct lichen_slot_claim claim;
	struct lichen_slot_grant grant;
	enum lichen_claim_result got;

	tests_run++;
	if (lichen_slot_coord_decode_claim(cose, cose_len, &claim) != 0) {
		tests_failed++;
		printf("FAIL %s (from %s): decode\n", caller, __func__);
		return;
	}
	got = lichen_slot_coord_process_claim(ctx, &claim, now, clock_valid,
					      &grant, NULL, NULL);
	if (got != want) {
		tests_failed++;
		printf("FAIL %s (from %s): result %d want %d\n", caller,
		       __func__, (int)got, (int)want);
	}
}

/* --------------------------------------------------------------------------
 * Tests
 * -------------------------------------------------------------------------- */

static void test_roundtrip_and_accept(void)
{
	static uint8_t cose[LICHEN_SLOT_CLAIM_COSE_MAX];
	static uint8_t reenc[CLAIM_PAYLOAD_TEST_MAX];
	struct lichen_slot_claim claim;
	struct lichen_slot_coord_ctx ctx;
	struct lichen_slot_grant grant;
	int ret;

	ret = sign_into(IID_A, 2, 1, 3000, LICHEN_SLOT_ALLOC_INTERLEAVED,
			cose, sizeof(cose));
	CHECK(ret > 0);
	size_t cose_len = (size_t)ret;

	/* Wire form: COSE array header, then the spec's protected header
	 * hex literal */
	CHECK(cose[0] == 0x84);
	CHECK(memcmp(&cose[1], PROTECTED_WIRE, sizeof(PROTECTED_WIRE)) == 0);
	/* Unprotected map a1 04 48 then the kid */
	CHECK(cose[9] == 0xa1 && cose[10] == 0x04 && cose[11] == 0x48);
	CHECK(memcmp(&cose[KID_OFFSET], IID_A, LICHEN_IID_LEN) == 0);

	ret = lichen_slot_coord_decode_claim(cose, cose_len, &claim);
	CHECK(ret == 0);
	CHECK(claim.slot_count == 4);
	CHECK(claim.slots[0] == 3 && claim.slots[1] == 11 &&
	      claim.slots[2] == 19 && claim.slots[3] == 27);
	CHECK(claim.superframe_id == 4242);
	CHECK(claim.ordinal == 2);
	CHECK(claim.mode == LICHEN_SLOT_ALLOC_INTERLEAVED);
	CHECK(claim.expiry == 3000);
	CHECK(claim.claim_seq == 1);
	CHECK(memcmp(claim.gateway_iid, IID_A, LICHEN_IID_LEN) == 0);
	CHECK(claim.cose_payload != NULL && claim.cose_payload_len > 0);
	CHECK(claim.cose_signature != NULL);

	/* Re-encoding the decoded claim reproduces the signed payload
	 * bytes byte-for-byte (canonical stability) */
	ret = lichen_slot_coord_encode_claim(&claim, reenc, sizeof(reenc));
	CHECK(ret == (int)claim.cose_payload_len);
	CHECK(ret > 0);
	CHECK(memcmp(reenc, claim.cose_payload,
		     claim.cose_payload_len) == 0);

	/* Accept: expiry 3000 > now 1000 */
	CHECK(lichen_slot_coord_init(&ctx, IID_B) == 0);
	ret = lichen_slot_coord_process_claim(&ctx, &claim, 1000, true, &grant,
					      NULL, NULL);
	CHECK(ret == LICHEN_CLAIM_ACCEPTED);
	CHECK(grant.granted_count == 4);
	CHECK(grant.superframe_id == 4242);
	CHECK(grant.valid_until == 3000);
	CHECK(grant.granted_slots[0] == 3 && grant.granted_slots[3] == 27);
	/* Registration: gateway table has A's allocation */
	CHECK(ctx.gateway_count == 1);
	CHECK(ctx.gateways[0].valid);
	CHECK(memcmp(ctx.gateways[0].iid, IID_A, LICHEN_IID_LEN) == 0);
	CHECK(ctx.gateways[0].ordinal == 2);
	CHECK(ctx.gateways[0].slot_count == 4);
	CHECK(ctx.gateways[0].slots[0] == 3);
	CHECK(ctx.gateways[0].superframe_id == 4242);
	/* Stored COSE for 4.09 echoes the accepted claim */
	CHECK(ctx.gateways[0].last_claim_cose_len == cose_len);
	CHECK(memcmp(ctx.gateways[0].last_claim_cose, cose, cose_len) == 0);
}

static void test_mutation_breaks_verify(void)
{
	static uint8_t cose[LICHEN_SLOT_CLAIM_COSE_MAX];
	struct lichen_slot_coord_ctx ctx;
	struct lichen_slot_claim claim;
	struct lichen_slot_grant grant;
	const uint8_t *payload;
	size_t payload_len;
	int ret;

	reset_seq_hooks();

	ret = sign_into(IID_A, 2, 1, 3000, LICHEN_SLOT_ALLOC_INTERLEAVED,
			cose, sizeof(cose));
	CHECK(ret > 0);
	size_t cose_len = (size_t)ret;

	CHECK(lichen_slot_coord_init(&ctx, IID_B) == 0);
	CHECK(lichen_slot_coord_decode_claim(cose, cose_len, &claim) == 0);
	payload = claim.cose_payload;
	payload_len = claim.cose_payload_len;

	/* GCP-6.5 regression: the slots array is inside the signed payload;
	 * flipping ANY payload byte must break schnorr48_verify */
	size_t offs[] = { 0, payload_len / 2, payload_len - 1 };
	for (size_t i = 0; i < sizeof(offs) / sizeof(offs[0]); i++) {
		uint8_t saved = cose[payload - cose + offs[i]];

		cose[payload - cose + offs[i]] ^= 0x01;
		CHECK(lichen_slot_coord_process_claim(&ctx, &claim, 1000, true,
						      &grant, NULL,
						      NULL) ==
		      LICHEN_CLAIM_REJECT_INVALID_SIG);
		cose[payload - cose + offs[i]] = saved;
	}

	/* Flipping a signature byte must fail too */
	const uint8_t *sig = claim.cose_signature;
	uint8_t saved = cose[sig - cose + 10];

	cose[sig - cose + 10] ^= 0x80;
	CHECK(lichen_slot_coord_process_claim(&ctx, &claim, 1000, true, &grant,
					      NULL, NULL) ==
	      LICHEN_CLAIM_REJECT_INVALID_SIG);
	cose[sig - cose + 10] = saved;

	/* Untouched claim still verifies (control) */
	CHECK(lichen_slot_coord_process_claim(&ctx, &claim, 1000, true, &grant,
					      NULL, NULL) ==
	      LICHEN_CLAIM_ACCEPTED);
}

static void test_unknown_signer(void)
{
	static uint8_t cose[LICHEN_SLOT_CLAIM_COSE_MAX];
	struct lichen_slot_coord_ctx ctx;
	int ret;

	ret = sign_into(IID_UNKNOWN, 2, 1, 3000,
			LICHEN_SLOT_ALLOC_INTERLEAVED, cose, sizeof(cose));
	CHECK(ret > 0);
	reset_seq_hooks();

	CHECK(lichen_slot_coord_init(&ctx, IID_A) == 0);
	PROCESS_OK(&ctx, cose, (size_t)ret, 1000,
		       LICHEN_CLAIM_REJECT_INVALID_SIG);
}

static void test_no_verification_material(void)
{
	struct lichen_slot_coord_ctx ctx;
	struct lichen_slot_claim claim;
	struct lichen_slot_grant grant;

	fill_claim(&claim, IID_A, 0, 1, 3000, 0);
	CHECK(lichen_slot_coord_init(&ctx, IID_A) == 0);
	CHECK(lichen_slot_coord_process_claim(&ctx, &claim, 1000, true, &grant,
					      NULL, NULL) ==
	      LICHEN_CLAIM_REJECT_NO_SIG);
}

static void test_gates(void)
{
	static uint8_t cose[LICHEN_SLOT_CLAIM_COSE_MAX];
	struct lichen_slot_coord_ctx ctx;
	int ret;

	reset_seq_hooks();

	CHECK(lichen_slot_coord_init(&ctx, IID_A) == 0);

	/* Expired: expiry 1000 <= now 1000 (spec step 7: expiry > now) */
	ret = sign_into(IID_A, 2, 1, 1000, 0, cose, sizeof(cose));
	CHECK(ret > 0);
	PROCESS_OK(&ctx, cose, (size_t)ret, 1000,
		       LICHEN_CLAIM_REJECT_EXPIRED);

	/* Fail-closed: unsynced wall clock (now 0, clock_valid false) must
	 * reject even a not-yet-expired claim instead of accepting it with
	 * no expiry validation (GCP-6.5 step 7 precondition). Seq 7 chosen
	 * above the later accept (seq 5): if a regression ever persisted
	 * the high-water on this rejection, the following seq-5 ACCEPTED
	 * assertion below would fail. */
	ret = sign_into(IID_A, 2, 7, 3000, 0, cose, sizeof(cose));
	CHECK(ret > 0);
	PROCESS_NO_CLOCK(&ctx, cose, (size_t)ret,
			 LICHEN_CLAIM_REJECT_NO_CLOCK);

	/* Replay: seq 5 accepted, then 5 and 4 rejected, 6 accepted
	 * (spec step 8) */
	ret = sign_into(IID_A, 2, 5, 3000, 0, cose, sizeof(cose));
	CHECK(ret > 0);
	PROCESS_OK(&ctx, cose, (size_t)ret, 1000, LICHEN_CLAIM_ACCEPTED);
	PROCESS_OK(&ctx, cose, (size_t)ret, 1000, LICHEN_CLAIM_REJECT_REPLAY);

	ret = sign_into(IID_A, 2, 4, 3000, 0, cose, sizeof(cose));
	CHECK(ret > 0);
	PROCESS_OK(&ctx, cose, (size_t)ret, 1000, LICHEN_CLAIM_REJECT_REPLAY);

	ret = sign_into(IID_A, 2, 6, 3000, 0, cose, sizeof(cose));
	CHECK(ret > 0);
	PROCESS_OK(&ctx, cose, (size_t)ret, 1000, LICHEN_CLAIM_ACCEPTED);
}

static void test_persist_failure(void)
{
	static uint8_t cose[LICHEN_SLOT_CLAIM_COSE_MAX];
	struct lichen_slot_coord_ctx ctx;
	int ret;

	reset_seq_hooks();

	CHECK(lichen_slot_coord_init(&ctx, IID_A) == 0);
	seq_cache_b.commit_fails = true;

	/* Sign by B so the failing cache entry (B) is the one consulted */
	ret = sign_into(IID_B, 2, 1, 3000, 0, cose, sizeof(cose));
	CHECK(ret > 0);
	PROCESS_OK(&ctx, cose, (size_t)ret, 1000,
		       LICHEN_CLAIM_REJECT_PERSIST);
	/* Claim not applied */
	CHECK(ctx.gateway_count == 0);
	CHECK(!lichen_slot_coord_tx_allowed(&ctx, 3));

	seq_cache_b.commit_fails = false;
}

static void test_conflict_resolution(void)
{
	static uint8_t cose_a[LICHEN_SLOT_CLAIM_COSE_MAX];
	static uint8_t cose_b[LICHEN_SLOT_CLAIM_COSE_MAX];
	struct lichen_slot_coord_ctx ctx;
	struct lichen_slot_claim claim;
	struct lichen_slot_grant grant;
	const uint8_t *conflict_cose = NULL;
	size_t conflict_len = 0;
	int ret;

	reset_seq_hooks();

	CHECK(lichen_slot_coord_init(&ctx, IID_A) == 0);

	/* B (higher IID) takes slot 5 first */
	struct lichen_slot_claim claim_b;

	fill_claim(&claim_b, IID_B, 3, 1, 3000, 0);
	claim_b.slots[0] = 5;
	claim_b.slot_count = 1;
	ret = lichen_slot_coord_sign_claim(privkey_b, pubkey_b, &claim_b,
					   cose_b, sizeof(cose_b));
	CHECK(ret > 0);
	PROCESS_OK(&ctx, cose_b, (size_t)ret, 1000, LICHEN_CLAIM_ACCEPTED);

	/* A (lower IID) claims the same slot: overrides, accepted */
	struct lichen_slot_claim claim_a;

	fill_claim(&claim_a, IID_A, 2, 1, 3000, 0);
	claim_a.slots[0] = 5;
	claim_a.slot_count = 1;
	ret = lichen_slot_coord_sign_claim(privkey_a, pubkey_a, &claim_a,
					   cose_a, sizeof(cose_a));
	CHECK(ret > 0);
	size_t cose_a_len = (size_t)ret;
	PROCESS_OK(&ctx, cose_a, cose_a_len, 1000, LICHEN_CLAIM_ACCEPTED);

	/* B re-claims slot 5: 4.09 conflict, payload is A's stored claim */
	struct lichen_slot_claim claim_b2;

	fill_claim(&claim_b2, IID_B, 3, 2, 3000, 0);
	claim_b2.slots[0] = 5;
	claim_b2.slot_count = 1;
	ret = lichen_slot_coord_sign_claim(privkey_b, pubkey_b, &claim_b2,
					   cose_b, sizeof(cose_b));
	CHECK(ret > 0);
	CHECK(lichen_slot_coord_decode_claim(cose_b, (size_t)ret, &claim) ==
	      0);
	CHECK(lichen_slot_coord_process_claim(&ctx, &claim, 1000, true, &grant,
					      &conflict_cose,
					      &conflict_len) ==
	      LICHEN_CLAIM_REJECT_CONFLICT);
	CHECK(conflict_cose != NULL);
	CHECK(conflict_len == cose_a_len);
	CHECK(conflict_cose != NULL &&
	      memcmp(conflict_cose, cose_a, cose_a_len) == 0);
}

static void test_structural_rejects(void)
{
	static uint8_t cose[LICHEN_SLOT_CLAIM_COSE_MAX];
	struct lichen_slot_claim claim;
	struct tb t;
	const uint8_t empty_sig[48] = { 0 };
	const uint8_t protected_decoy[] = { 0xa1, 0x01, 0x39, 0xff, 0xff };
	const uint8_t protected_noncanon[] = {
		0xa2, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00, 0x01, 0x3a,
		0x00, 0x01, 0x00, 0x00
	};
	const uint8_t protected_canon[] = {
		0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00
	};
	int ret;

	ret = sign_into(IID_A, 2, 1, 3000, 0, cose, sizeof(cose));
	CHECK(ret > 0);
	size_t cose_len = (size_t)ret;

	/* Trailing garbage */
	CHECK(lichen_slot_coord_decode_claim(cose, cose_len, &claim) == 0);
	CHECK(lichen_slot_coord_decode_claim(cose, cose_len + 1, &claim) ==
	      -EBADMSG);
	CHECK(lichen_slot_coord_decode_claim(cose, cose_len - 1, &claim) ==
	      -EBADMSG);

	/* kid != payload gateway_iid (flip one kid byte) */
	memcpy(t.buf, cose, cose_len);
	t.len = cose_len;
	t.buf[KID_OFFSET + 3] ^= 0xff;
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	/* -65536 decoy protected header */
	memset(&t, 0, sizeof(t));
	tb_cose(&t, protected_decoy, sizeof(protected_decoy), IID_A,
		claim.cose_payload, claim.cose_payload_len, empty_sig,
		sizeof(empty_sig), 0, NULL, 0);
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	/* Non-canonical protected header (duplicate alg key) */
	memset(&t, 0, sizeof(t));
	tb_cose(&t, protected_noncanon, sizeof(protected_noncanon), IID_A,
		claim.cose_payload, claim.cose_payload_len, empty_sig,
		sizeof(empty_sig), 0, NULL, 0);
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	/* Wrong element count: 3 and 5 */
	memset(&t, 0, sizeof(t));
	tb_head(&t, 4, 3);
	tb_bstr(&t, protected_canon, sizeof(protected_canon));
	tb_head(&t, 5, 1);
	tb_head(&t, 0, COSE_KID_TEST);
	tb_bstr(&t, IID_A, LICHEN_IID_LEN);
	tb_bstr(&t, claim.cose_payload, claim.cose_payload_len);
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	memset(&t, 0, sizeof(t));
	tb_head(&t, 4, 5);
	tb_bstr(&t, protected_canon, sizeof(protected_canon));
	tb_head(&t, 5, 1);
	tb_head(&t, 0, COSE_KID_TEST);
	tb_bstr(&t, IID_A, LICHEN_IID_LEN);
	tb_bstr(&t, claim.cose_payload, claim.cose_payload_len);
	tb_bstr(&t, empty_sig, sizeof(empty_sig));
	tb_bstr(&t, empty_sig, 1);
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	/* Unprotected header: missing kid, short kid, non-4 key */
	memset(&t, 0, sizeof(t));
	tb_head(&t, 4, 4);
	tb_bstr(&t, protected_canon, sizeof(protected_canon));
	tb_head(&t, 5, 1);
	tb_head(&t, 0, 5); /* wrong key */
	tb_bstr(&t, IID_A, LICHEN_IID_LEN);
	tb_bstr(&t, claim.cose_payload, claim.cose_payload_len);
	tb_bstr(&t, empty_sig, sizeof(empty_sig));
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	memset(&t, 0, sizeof(t));
	tb_head(&t, 4, 4);
	tb_bstr(&t, protected_canon, sizeof(protected_canon));
	tb_head(&t, 5, 1);
	tb_head(&t, 0, COSE_KID_TEST);
	tb_bstr(&t, IID_A, LICHEN_IID_LEN - 3); /* short kid */
	tb_bstr(&t, claim.cose_payload, claim.cose_payload_len);
	tb_bstr(&t, empty_sig, sizeof(empty_sig));
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	/* Signature length: 47 and 49 bytes */
	memset(&t, 0, sizeof(t));
	tb_cose(&t, protected_canon, sizeof(protected_canon), IID_A,
		claim.cose_payload, claim.cose_payload_len, empty_sig,
		sizeof(empty_sig) - 1, 0, NULL, 0);
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	memset(&t, 0, sizeof(t));
	tb_cose(&t, protected_canon, sizeof(protected_canon), IID_A,
		claim.cose_payload, claim.cose_payload_len, empty_sig,
		sizeof(empty_sig) + 1, 0, NULL, 0);
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	/* Payload structural rejects, all with a well-formed envelope */
	struct lichen_slot_claim base;

	fill_claim(&base, IID_A, 2, 1, 3000, 0);

	const struct {
		const char *name;
		unsigned key_mask;
		bool extra_key;
		bool duplicate_key1;
	} payload_cases[] = {
		{ "missing key 6", 0x7f & ~(1u << 6u), false, false },
		{ "missing key 7", 0x7f & ~(1u << 7u), false, false },
		{ "missing key 1", 0x7f & ~(1u << 1u), false, false },
		{ "unknown key 8", 0x7f, true, false },
		{ "duplicate key 1", 0x7f, false, true },
	};

	for (size_t i = 0; i < sizeof(payload_cases) / sizeof(payload_cases[0]);
	     i++) {
		struct tb p;

		memset(&p, 0, sizeof(p));
		tb_payload(&p, &base, payload_cases[i].key_mask,
			   payload_cases[i].extra_key,
			   payload_cases[i].duplicate_key1);
		CHECK(!p.overflow);
		memset(&t, 0, sizeof(t));
		tb_cose(&t, protected_canon, sizeof(protected_canon), IID_A,
			p.buf, p.len, empty_sig, sizeof(empty_sig), 0, NULL, 0);
		CHECK(!t.overflow);
		CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
		      -EBADMSG);
	}

	/* Payload not a map (uint instead) */
	memset(&t, 0, sizeof(t));
	tb_head(&t, 4, 4);
	tb_bstr(&t, protected_canon, sizeof(protected_canon));
	tb_head(&t, 5, 1);
	tb_head(&t, 0, COSE_KID_TEST);
	tb_bstr(&t, IID_A, LICHEN_IID_LEN);
	tb_head(&t, 0, 7);
	tb_bstr(&t, empty_sig, sizeof(empty_sig));
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	/* Empty slots array */
	{
		struct lichen_slot_claim e = base;

		e.slot_count = 0;
		struct tb p;

		memset(&p, 0, sizeof(p));
		tb_payload(&p, &e, 0x7f, false, false);
		memset(&t, 0, sizeof(t));
		tb_cose(&t, protected_canon, sizeof(protected_canon), IID_A,
			p.buf, p.len, empty_sig, sizeof(empty_sig), 0, NULL, 0);
		CHECK(!t.overflow);
		CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
		      -EBADMSG);
	}

	/* Mode 2 out of range */
	{
		struct lichen_slot_claim m = base;

		m.mode = 2;
		struct tb p;

		memset(&p, 0, sizeof(p));
		tb_payload(&p, &m, 0x7f, false, false);
		memset(&t, 0, sizeof(t));
		tb_cose(&t, protected_canon, sizeof(protected_canon), IID_A,
			p.buf, p.len, empty_sig, sizeof(empty_sig), 0, NULL, 0);
		CHECK(!t.overflow);
		CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
		      -EBADMSG);
	}

	/* Slot value 256 exceeds uint8 */
	{
		struct lichen_slot_claim s = base;

		s.slots[0] = 0;
		s.slot_count = 1;
		struct tb p;

		memset(&p, 0, sizeof(p));
		tb_head(&p, 5, 7);
		tb_head(&p, 0, 1);
		tb_head(&p, 4, 1);
		tb_head(&p, 0, 256);
		tb_head(&p, 0, 2);
		tb_head(&p, 0, s.superframe_id);
		tb_head(&p, 0, 3);
		tb_head(&p, 0, s.mode);
		tb_head(&p, 0, 4);
		tb_head(&p, 0, s.expiry);
		tb_head(&p, 0, 5);
		tb_bstr(&p, s.gateway_iid, LICHEN_IID_LEN);
		tb_head(&p, 0, 6);
		tb_head(&p, 0, s.claim_seq);
		tb_head(&p, 0, 7);
		tb_head(&p, 0, s.ordinal);
		memset(&t, 0, sizeof(t));
		tb_cose(&t, protected_canon, sizeof(protected_canon), IID_A,
			p.buf, p.len, empty_sig, sizeof(empty_sig), 0, NULL, 0);
		CHECK(!t.overflow);
		CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
		      -EBADMSG);
	}

	/* Non-bstr protected header element */
	memset(&t, 0, sizeof(t));
	tb_head(&t, 4, 4);
	tb_head(&t, 0, 1);
	tb_head(&t, 5, 1);
	tb_head(&t, 0, COSE_KID_TEST);
	tb_bstr(&t, IID_A, LICHEN_IID_LEN);
	tb_bstr(&t, claim.cose_payload, claim.cose_payload_len);
	tb_bstr(&t, empty_sig, sizeof(empty_sig));
	CHECK(!t.overflow);
	CHECK(lichen_slot_coord_decode_claim(t.buf, t.len, &claim) ==
	      -EBADMSG);

	/* NULL / degenerate inputs (buf is _Nonnull; only lengths vary) */
	CHECK(lichen_slot_coord_decode_claim(cose, 0, &claim) == -EBADMSG);
}

static void test_max_slots_claim(void)
{
	static uint8_t cose[LICHEN_SLOT_CLAIM_COSE_MAX];
	struct lichen_slot_coord_ctx ctx;
	struct lichen_slot_claim claim;
	struct lichen_slot_grant grant;
	int ret;

	struct lichen_slot_claim big;

	memset(&big, 0, sizeof(big));
	memcpy(big.gateway_iid, IID_A, LICHEN_IID_LEN);
	big.slot_count = CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS;
	for (uint8_t i = 0; i < big.slot_count; i++) {
		big.slots[i] = (uint8_t)(i * 1);
	}
	big.superframe_id = 7;
	big.ordinal = 1;
	big.mode = 1;
	big.expiry = 3000;
	big.claim_seq = 1;

	ret = lichen_slot_coord_sign_claim(privkey_a, pubkey_a, &big, cose,
					   sizeof(cose));
	CHECK(ret > 0);
	CHECK(ret <= LICHEN_SLOT_CLAIM_COSE_MAX);

	reset_seq_hooks();

	CHECK(lichen_slot_coord_init(&ctx, IID_B) == 0);
	CHECK(lichen_slot_coord_decode_claim(cose, (size_t)ret, &claim) == 0);
	CHECK(claim.slot_count == CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS);
	CHECK(lichen_slot_coord_process_claim(&ctx, &claim, 1000, true, &grant,
					      NULL, NULL) ==
	      LICHEN_CLAIM_ACCEPTED);
}

static void test_slot_range_gate(void)
{
	static uint8_t cose[LICHEN_SLOT_CLAIM_COSE_MAX];
	struct lichen_slot_coord_ctx ctx;
	struct lichen_slot_claim claim;
	struct lichen_slot_grant grant;
	int ret;

	reset_seq_hooks();

	CHECK(lichen_slot_coord_init(&ctx, IID_A) == 0);

	fill_claim(&claim, IID_A, 2, 1, 3000, 0);
	claim.slot_count = 1;
	claim.slots[0] = 200; /* >= slots_per_superframe (60) */
	ret = lichen_slot_coord_sign_claim(privkey_a, pubkey_a, &claim, cose,
					   sizeof(cose));
	CHECK(ret > 0);
	CHECK(lichen_slot_coord_decode_claim(cose, (size_t)ret, &claim) == 0);
	CHECK(lichen_slot_coord_process_claim(&ctx, &claim, 1000, true, &grant,
					      NULL, NULL) ==
	      LICHEN_CLAIM_REJECT_INVALID_SLOTS);
}

static void test_bad_args(void)
{
	struct lichen_slot_coord_ctx ctx;
	struct lichen_slot_claim claim;
	uint8_t buf[16];

	CHECK(lichen_slot_coord_init(&ctx, IID_A) == 0);

	/* Buffer too small for the payload map */
	fill_claim(&claim, IID_A, 2, 1, 3000, 0);
	CHECK(lichen_slot_coord_encode_claim(&claim, buf, sizeof(buf)) ==
	      -ENOBUFS);
	CHECK(lichen_slot_coord_encode_claim(&claim, buf, 0) == -ENOBUFS);
}

int main(void)
{
	schnorr48_derive_keypair(SEED_A, privkey_a, pubkey_a);
	schnorr48_derive_keypair(SEED_B, privkey_b, pubkey_b);
	schnorr48_derive_keypair(SEED_UNKNOWN, privkey_unknown,
				 pubkey_unknown);

	test_sha256_known_answer();
	test_roundtrip_and_accept();
	test_mutation_breaks_verify();
	test_unknown_signer();
	test_no_verification_material();
	test_gates();
	test_persist_failure();
	test_conflict_resolution();
	test_structural_rejects();
	test_max_slots_claim();
	test_slot_range_gate();
	test_bad_args();

	printf("%d checks, %d failed\n", tests_run, tests_failed);
	return tests_failed == 0 ? 0 : 1;
}