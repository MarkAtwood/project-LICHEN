/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <assert.h>
#include <errno.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <lichen/gateway/capability_announce.h>
#include <lichen/schnorr48.h>
#include <monocypher.h>

static void test_corpus(void);
static void test_malformed(void);
static void test_table(void);
static void test_floor_ledger_bounds(void);

#include "capability_announce_vectors.h"

static int hash256(const uint8_t *input, size_t len, uint8_t out[32])
{
	return SHA256(input, len, out) == NULL ? -EIO : 0;
}

static int iid(const uint8_t pubkey[32], uint8_t out[8])
{
	uint8_t hash[64];
	if (SHA512(pubkey, 32, hash) == NULL) return -EIO;
	memcpy(out, hash, 8); out[0] &= (uint8_t)~0x02U;
	crypto_wipe(hash, sizeof(hash)); return 0;
}

static bool verify_digest(const uint8_t pk[32], const uint8_t d[32], const uint8_t s[48])
{ return schnorr48_verify(pk, d, 32, s, 48); }

static const struct lichen_capability_crypto crypto = { hash256, iid, verify_digest };

static void test_corpus(void)
{
	for (size_t i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
		const struct capability_vector *v = &vectors[i];
		struct lichen_capability_announcement a;
		enum lichen_capability_denial why;
		struct lichen_capability_result r;

		/* The C decode contract is strictly untagged COSE_Sign1: the
		 * corpus carries the same announcement tag-18 wrapped and that
		 * form must be rejected as malformed. */
		assert(!lichen_capability_announce_decode(v->wire_tagged, v->wire_tagged_len, &a, &why));
		assert(why == LICHEN_CAPABILITY_DENIAL_MALFORMED);

		bool ok = lichen_capability_announce_decode(v->wire, v->wire_len, &a, &why);
		if (v->kid_mismatch) {
			assert(!ok && why == LICHEN_CAPABILITY_DENIAL_KID_MISMATCH);
			continue;
		}
		assert(ok);
		if (v->has_capabilities) assert(a.payload.capabilities == v->capabilities);
		if (v->has_expiry) assert(a.payload.expiry == v->expiry);
		if (v->has_seq) assert(a.payload.seq == v->seq);
		if (v->announcer_iid != NULL) {
			assert(memcmp(a.payload.announcer_iid, v->announcer_iid, 8) == 0);
			/* IID scheme cross-check: derivation from the pinned
			 * pubkey reproduces the corpus announcer IID. */
			uint8_t derived[8];
			assert(iid(v->pubkey, derived) == 0);
			assert(memcmp(derived, v->announcer_iid, 8) == 0);
		}
		if (v->has_prefix_len) {
			assert(a.payload.prefix_len == v->prefix_len);
			if (v->prefix != NULL) {
				assert(memcmp(a.payload.prefix, v->prefix,
					      (size_t)((v->prefix_len + 7U) / 8U)) == 0);
			}
		}

		r = lichen_capability_announce_verify(&crypto, &a, v->pubkey, 0, NULL);
		if (!v->reserved_zero) {
			assert(!r.valid && r.denial == LICHEN_CAPABILITY_DENIAL_RESERVED_BITS);
			/* Ordering: reserved bits fire before expiry. */
			r = lichen_capability_announce_verify(&crypto, &a, v->pubkey, UINT64_MAX, NULL);
			assert(!r.valid && r.denial == LICHEN_CAPABILITY_DENIAL_RESERVED_BITS);
			continue;
		}
		assert(r.valid && r.denial == LICHEN_CAPABILITY_DENIAL_NONE);

		/* A different pubkey cannot announce this IID. */
		uint8_t other[32];
		memcpy(other, v->pubkey, 32);
		other[0] = (uint8_t)(other[0] ^ 0x01U);
		r = lichen_capability_announce_verify(&crypto, &a, other, 0, NULL);
		assert(!r.valid && r.denial == LICHEN_CAPABILITY_DENIAL_IID_MISMATCH);

		/* Corrupted signature. */
		struct lichen_capability_announcement bad = a;
		bad.signature[47] = (uint8_t)(bad.signature[47] ^ 0x01U);
		r = lichen_capability_announce_verify(&crypto, &bad, v->pubkey, 0, NULL);
		assert(!r.valid && r.denial == LICHEN_CAPABILITY_DENIAL_SIGNATURE);

		if (v->has_expiry) {
			r = lichen_capability_announce_verify(&crypto, &a, v->pubkey, v->expiry, NULL);
			assert(!r.valid && r.denial == LICHEN_CAPABILITY_DENIAL_EXPIRED);
			r = lichen_capability_announce_verify(&crypto, &a, v->pubkey, v->expiry - 1U, NULL);
			assert(r.valid);
		}
		if (v->has_seq) {
			r = lichen_capability_announce_verify(&crypto, &a, v->pubkey, 0, &v->seq);
			assert(!r.valid && r.denial == LICHEN_CAPABILITY_DENIAL_REPLAY);
			if (v->seq > 0U) {
				uint64_t prev = v->seq - 1U;
				r = lichen_capability_announce_verify(&crypto, &a, v->pubkey, 0, &prev);
				assert(r.valid);
			}
		}
	}
}

static void test_malformed(void)
{
	struct lichen_capability_announcement a;
	enum lichen_capability_denial why;
	struct lichen_capability_crypto defaults;

	/* Signature bytes from the first valid vector, for surgical mutations. */
	const uint8_t *valid = wire_capability_egress_only;
	const size_t valid_len = sizeof(wire_capability_egress_only);

	assert(!lichen_capability_announce_decode(NULL, 10, &a, &why));
	assert(why == LICHEN_CAPABILITY_DENIAL_MALFORMED);
	assert(!lichen_capability_announce_decode(valid, 0, &a, &why));

	const uint8_t lone[] = { 0x80 };
	assert(!lichen_capability_announce_decode(lone, sizeof(lone), &a, &why));

	/* Every truncation of a valid announcement is malformed. */
	for (size_t cut = 0; cut < valid_len; cut++) {
		assert(!lichen_capability_announce_decode(valid, cut, &a, &why));
	}

	/* Trailing byte after the signature. */
	uint8_t trail[sizeof(wire_capability_egress_only) + 1U];
	memcpy(trail, valid, valid_len);
	trail[valid_len] = 0x00;
	assert(!lichen_capability_announce_decode(trail, valid_len + 1U, &a, &why));

	/* Alg decoy: canonical one-entry map with a different alg value. */
	uint8_t decoy[sizeof(wire_capability_egress_only)];
	memcpy(decoy, valid, valid_len);
	assert(decoy[8] == 0x00);
	decoy[8] = 0x01;
	assert(!lichen_capability_announce_decode(decoy, valid_len, &a, &why));
	assert(why == LICHEN_CAPABILITY_DENIAL_ALGORITHM);

	/* Duplicate alg key head: malformed, not an algorithm denial. */
	uint8_t dup[sizeof(wire_capability_egress_only)];
	memcpy(dup, valid, valid_len);
	assert(dup[2] == 0xa1);
	dup[2] = 0xa2;
	assert(!lichen_capability_announce_decode(dup, valid_len, &a, &why));
	assert(why == LICHEN_CAPABILITY_DENIAL_MALFORMED);

	assert(!lichen_capability_announce_decode(valid, valid_len, NULL, &why));

	/* Prefix padding rule: 16-byte zero-extended prefixes are accepted
	 * (corpus form), but nonzero padding or truncated significant bytes
	 * are malformed.  Payloads are hand-built; decode fails before the
	 * signature is ever consulted. */
	{
		static const uint8_t head[] = { 0x84, 0x47, 0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00,
			0xa1, 0x04, 0x48, 0x71, 0x59, 0xbd, 0x63, 0x3b, 0x2e, 0x91, 0x20 };
		static const uint8_t sig[50] = { 0x58, 0x30 }; /* bstr head + 48 placeholder bytes */
		static const uint8_t bad_padding[] = {
			0xa6, 0x01, 0x01, 0x02, 0x50, 0xfd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x18, 0x40,
			0x04, 0x1a, 0x67, 0x74, 0x85, 0x80, 0x05, 0x01, 0x06, 0x48,
			0x71, 0x59, 0xbd, 0x63, 0x3b, 0x2e, 0x91, 0x20 };
		static const uint8_t truncated[] = {
			0xa6, 0x01, 0x01, 0x02, 0x41, 0xfd, 0x03, 0x18, 0x40,
			0x04, 0x1a, 0x67, 0x74, 0x85, 0x80, 0x05, 0x01, 0x06, 0x48,
			0x71, 0x59, 0xbd, 0x63, 0x3b, 0x2e, 0x91, 0x20 };
		uint8_t wire[128];
		size_t payload_len = sizeof(bad_padding);

		memcpy(wire, head, sizeof(head));
		wire[sizeof(head)] = 0x58;
		wire[sizeof(head) + 1U] = (uint8_t)payload_len;
		memcpy(wire + sizeof(head) + 2U, bad_padding, sizeof(bad_padding));
		memcpy(wire + sizeof(head) + 2U + payload_len, sig, sizeof(sig));
		assert(!lichen_capability_announce_decode(wire,
			sizeof(head) + 2U + payload_len + sizeof(sig), &a, &why));

		memcpy(wire, head, sizeof(head));
		payload_len = sizeof(truncated);
		wire[sizeof(head)] = 0x58;
		wire[sizeof(head) + 1U] = (uint8_t)payload_len;
		memcpy(wire + sizeof(head) + 2U, truncated, sizeof(truncated));
		memcpy(wire + sizeof(head) + 2U + payload_len, sig, sizeof(sig));
		assert(!lichen_capability_announce_decode(wire,
			sizeof(head) + 2U + payload_len + sizeof(sig), &a, &why));
	}

	assert(lichen_capability_announce_default_crypto(&defaults) == -ENOTSUP);
}

int main(void)
{
	test_corpus();
	test_malformed();
	test_table();
	test_floor_ledger_bounds();
	printf("capability_announce: all tests passed\n");
	return 0;
}

/* ---------------------------------------------------------------------------
 * Capability table (spec 8.12): LRU + 25% egress reservation + eviction
 * seq-floor ledger.  CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY is 8 here, so
 * the egress-reserved tail is 2 and non-egress inserts cap at 6.
 */

static struct lichen_capability_payload mk_payload(uint8_t seed, uint32_t caps,
						   uint64_t seq, uint64_t expiry)
{
	struct lichen_capability_payload p = { 0 };
	memset(p.announcer_iid, seed, 8);
	p.announcer_iid[7] = seed; /* distinct IIDs per seed */
	p.capabilities = caps;
	p.seq = seq;
	p.expiry = expiry;
	return p;
}

static void test_table(void)
{
	struct lichen_capability_table t;
	lichen_capability_table_init(&t);

	/* Unknown announcer reports no baseline. */
	assert(lichen_capability_table_cached_seq(&t, (const uint8_t *)"nonexist") == -1);

	/* Non-egress inserts fill to capacity - reserved (6 of 8). */
	for (uint8_t i = 1; i <= 6; i++) {
		struct lichen_capability_payload p = mk_payload(i, 0x0, i, 1000);
		assert(lichen_capability_table_record(&t, &p));
	}
	/* 7th non-egress insert would consume the reserved tail: refused. */
	struct lichen_capability_payload extra = mk_payload(7, 0x0, 7, 1000);
	assert(!lichen_capability_table_record(&t, &extra));

	/* Egress insert reclaims the reserved tail via LRU eviction. */
	struct lichen_capability_payload eg = mk_payload(0xe0, LICHEN_CAPABILITY_EGRESS, 100, 1000);
	assert(lichen_capability_table_record(&t, &eg));
	/* The LRU victim was seed=1 (seq 1); its floor survives eviction. */
	uint8_t victim[8] = { 0 };
	memset(victim, 1, 8); victim[7] = 1;
	assert(lichen_capability_table_cached_seq(&t, victim) == 1);

	/* cached_seq for a live entry returns its seq. */
	uint8_t live[8]; memset(live, 2, 8); live[7] = 2;
	assert(lichen_capability_table_cached_seq(&t, live) == 2);

	/* Insert-or-refresh updates an existing entry. */
	struct lichen_capability_payload upd = mk_payload(2, 0x2, 5, 2000);
	assert(lichen_capability_table_record(&t, &upd));
	assert(lichen_capability_table_cached_seq(&t, live) == 5);

	/* purge_expired drops lapsed entries; the floor pinned at record()
	 * time survives the purge. */
	struct lichen_capability_payload doomed = mk_payload(3, 0x0, 9, 10);
	assert(lichen_capability_table_record(&t, &doomed));
	uint8_t dseed[8]; memset(dseed, 3, 8); dseed[7] = 3;
	assert(lichen_capability_table_purge_expired(&t, 10) == 1);
	assert(lichen_capability_table_cached_seq(&t, dseed) == 9);
}

/* cached_seq for the all-<seed>-bytes IID of mk_payload.  Queries of dead
 * IIDs have no LRU side effect; only query live IIDs where noted. */
static int64_t seq_for_seed(struct lichen_capability_table *t, uint8_t seed)
{
	uint8_t iid[8];
	memset(iid, seed, sizeof(iid));
	return lichen_capability_table_cached_seq(t, iid);
}

/* Floor ledger stays bounded under churn: when full, the lowest-IID floor
 * of a non-resident announcer is pruned to make room (mirrors Python
 * CapabilityTable._bound_floors / Rust bound_seq_floors), so long-gone
 * announcers cannot permanently starve eviction-captured floors. */
static void test_floor_ledger_bounds(void)
{
	struct lichen_capability_table t;
	lichen_capability_table_init(&t);

	/* Six non-egress entries expire, leaving six dead floors. */
	for (uint8_t i = 1; i <= 6; i++) {
		struct lichen_capability_payload p = mk_payload(i, 0x0, i, 1000);
		assert(lichen_capability_table_record(&t, &p));
	}
	assert(lichen_capability_table_purge_expired(&t, 2000) == 6);

	/* Seeds 7..12 reinsert: the ledger fills at seed 8 and the stale
	 * dead floors 1..4 are pruned lowest-IID-first. */
	for (uint8_t i = 7; i <= 12; i++) {
		struct lichen_capability_payload p = mk_payload(i, 0x0, i, 1000);
		assert(lichen_capability_table_record(&t, &p));
	}
	assert(seq_for_seed(&t, 1) == -1); /* pruned: lowest dead */
	assert(seq_for_seed(&t, 4) == -1); /* pruned */
	assert(seq_for_seed(&t, 5) == 5);  /* dead but higher: retained */
	assert(seq_for_seed(&t, 6) == 6);  /* dead but higher: retained */
	assert(seq_for_seed(&t, 12) == 12); /* live entry reports its seq */

	/* Egress churn (LRU order: 7,8,9,10,11,12 — 12's cached_seq refresh
	 * above keeps it last among the originals).  Each new floor prunes
	 * the lowest dead floor; under saturation the just-evicted victim's
	 * floor is itself the prune target, as in Python and Rust. */
	for (uint8_t i = 0xF0; i <= 0xF8; i++) {
		struct lichen_capability_payload p =
			mk_payload(i, LICHEN_CAPABILITY_EGRESS, 100U * i, 100000);
		assert(lichen_capability_table_record(&t, &p));
	}
	assert(seq_for_seed(&t, 7) == -1);  /* evicted by 0xF2, pruned */
	assert(seq_for_seed(&t, 8) == -1);  /* evicted by 0xF3 */
	assert(seq_for_seed(&t, 9) == -1);  /* evicted by 0xF4 */
	assert(seq_for_seed(&t, 10) == -1); /* evicted by 0xF5 */
	assert(seq_for_seed(&t, 11) == -1); /* evicted by 0xF6 */
	assert(seq_for_seed(&t, 12) == -1); /* evicted by 0xF7 */
	assert(seq_for_seed(&t, 0xF0) == -1); /* evicted by 0xF8 */

	/* 0xF9 evicts 0xF1 (LRU); under saturation the victim's floor is
	 * itself the prune target, as in Python and Rust. */
	struct lichen_capability_payload last =
		mk_payload(0xF9, LICHEN_CAPABILITY_EGRESS, 100U * 0xF9, 100000);
	assert(lichen_capability_table_record(&t, &last));
	assert(seq_for_seed(&t, 0xF1) == -1);
	/* Live floors keep working: a fresh entry reports its seq (no
	 * silent starvation of new floors).  Queried on 0xF8, the newest
	 * entry, so the LRU order for the next eviction is unchanged. */
	assert(seq_for_seed(&t, 0xF8) == 100U * 0xF8);

	/* Purging everything leaves eight dead floors; the next insert
	 * prunes only the lowest-IID one and still gets a floor. */
	assert(lichen_capability_table_purge_expired(&t, 100001) == 8);
	struct lichen_capability_payload after =
		mk_payload(0xFA, LICHEN_CAPABILITY_EGRESS, 100U * 0xFA, 100000);
	assert(lichen_capability_table_record(&t, &after));
	assert(seq_for_seed(&t, 0xF2) == -1);          /* pruned: lowest dead */
	assert(seq_for_seed(&t, 0xF3) == 100U * 0xF3); /* dead but retained */

	/* A pending raiser is itself a prune candidate: a new announcer
	 * whose IID is lower than every dead floor gets no floor (Python
	 * and Rust raise it and immediately bound it away), and the
	 * protective dead floors survive. */
	struct lichen_capability_table t2;
	lichen_capability_table_init(&t2);
	for (uint8_t i = 30; i <= 35; i++) {
		struct lichen_capability_payload p = mk_payload(i, 0x0, i, 1000);
		assert(lichen_capability_table_record(&t2, &p));
	}
	assert(lichen_capability_table_purge_expired(&t2, 2000) == 6);
	for (uint8_t i = 36; i <= 41; i++) {
		struct lichen_capability_payload p = mk_payload(i, 0x0, i, 100000);
		assert(lichen_capability_table_record(&t2, &p));
	}
	/* Dead floors {34,35}; 36..41 live; ledger full. */
	struct lichen_capability_payload low =
		mk_payload(29, LICHEN_CAPABILITY_EGRESS, 100, 1500);
	assert(lichen_capability_table_record(&t2, &low));
	assert(seq_for_seed(&t2, 34) == 34); /* protective dead floor kept */
	assert(seq_for_seed(&t2, 35) == 35);
	assert(seq_for_seed(&t2, 29) == 100); /* live entry pins its seq */
	/* Expiring 29 leaves no floor: the Python reference's purge_expired
	 * (the only reference with expiry) captures no floors, so dead
	 * floors 34/35 survive untouched. */
	assert(lichen_capability_table_purge_expired(&t2, 2000) == 1);
	assert(seq_for_seed(&t2, 29) == -1);
	assert(seq_for_seed(&t2, 34) == 34);
	assert(seq_for_seed(&t2, 35) == 35);
}
