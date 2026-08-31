/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file main.c
 * @brief SIID-indexed signer key-selection fail-closed tests
 *
 * Host-level mirror of the L2 peer selection wiring (peer_try_all_pubkeys,
 * spec/02-physical-link.md 4.2, project-LICHEN-worker6-nxew option b):
 * the trust store is keyed by canonical key-derived EUI-64 (the wire SIID
 * form), the SIID selects the single candidate key, and lichen_link_rx_payload()
 * / lichen_link_relay_frame() provide the production verification, SIID
 * binding, replay, and relay re-signing gates. The Zephyr-side peer table
 * itself (peer_table, lichen_peer_add) is exercised by the Zephyr tests; the
 * invariants proven here are the ones enforced by the production link layer:
 *
 * 1. Unknown SIID: no candidate key -> reject, no replay/trust state created.
 * 2. Wrong key: pinned candidate fails to verify -> reject, no fallback.
 * 3. Pinned mismatch / decoy: a cryptographically VALID signature under a
 *    different pinned key is still rejected by the SIID binding gate.
 * 4. Multi-hop relay: C accepts the relay's re-signed frame against the
 *    relay's pinned key, with the origin payload preserved verbatim.
 * 5. Replay state is allocated only after verification succeeds.
 */

#include <lichen/errno.h>
#include <lichen/link.h>
#include <lichen/link_ctx.h>
#include <lichen/replay.h>
#include <lichen/schnorr48.h>

#include "schc_internal.h"
#include <monocypher.h>
#include <monocypher-ed25519.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define PAYLOAD_MAX 128
#define WIRE_CAP 255

#define PAYLOAD_A_LEN ((size_t)40)
#define PAYLOAD_B_LEN ((size_t)48)

static int failures;

#define FAIL(...)                                  \
	do {                                       \
		printf("FAIL %s:%d: ", __func__, __LINE__); \
		printf(__VA_ARGS__);               \
		printf("\n");                      \
		failures++;                        \
	} while (0)

#define CHECK_OK(cond, ...)  \
	do { if (!(cond)) { FAIL(__VA_ARGS__); } } while (0)

/* ─── Trust store: mirrors lichen_l2_peer.c peer_table/peer_find_locked ──── */

struct trust_entry {
	uint8_t siid[LICHEN_EUI64_LEN]; /* extended wire form (U/L set) */
	uint8_t pubkey[LICHEN_PK_LEN];
};

struct trust_store {
	struct trust_entry entry[4];
	size_t count;
};

/* memcmp over public EUI-64 identifiers, same class as peer_find_locked(). */
static const struct trust_entry *trust_find(const struct trust_store *store,
					    const uint8_t siid[LICHEN_EUI64_LEN])
{
	for (size_t i = 0; i < store->count; i++) {
		if (memcmp(store->entry[i].siid, siid, LICHEN_EUI64_LEN) == 0) {
			return &store->entry[i];
		}
	}
	return NULL;
}

/* Mirrors lichen_peer_add() TOFU semantics: pin on first (out-of-band
 * verified) contact, reject a key change for a pinned SIID. */
static int trust_pin(struct trust_store *store, const uint8_t siid[LICHEN_EUI64_LEN],
		     const uint8_t pubkey[LICHEN_PK_LEN])
{
	const struct trust_entry *existing = trust_find(store, siid);

	if (existing != NULL) {
		if (memcmp(existing->pubkey, pubkey, LICHEN_PK_LEN) != 0) {
			return -EEXIST;
		}
		return 0;
	}
	if (store->count >= sizeof(store->entry) / sizeof(store->entry[0])) {
		return -ENOSPC;
	}
	memcpy(store->entry[store->count].siid, siid, LICHEN_EUI64_LEN);
	memcpy(store->entry[store->count].pubkey, pubkey, LICHEN_PK_LEN);
	store->count++;
	return 0;
}

/* ─── Identities and frames ───────────────────────────────────────────────── */

static void make_identity(uint8_t tag, struct lichen_link_ctx *ctx,
			  uint8_t siid[LICHEN_EUI64_LEN])
{
	uint8_t seed[LICHEN_SEED_LEN];
	uint8_t eui64[LICHEN_EUI64_LEN] = { 0x02, 0, 0, 0, 0, 0, 0, tag };
	uint8_t hash[64];

	memset(seed, (int)tag, sizeof(seed));
	if (lichen_link_init(ctx, eui64) != 0) {
		FAIL("lichen_link_init tag=%u", tag);
		return;
	}
	if (lichen_link_load_key(ctx, seed) != 0) {
		FAIL("lichen_link_load_key tag=%u", tag);
	}
	crypto_wipe(seed, sizeof(seed));

	/* Wire SIID form: SHA-512(pubkey)[0:8] with U/L set exactly once. */
	crypto_sha512(hash, ctx->ed25519_pk, LICHEN_PK_LEN);
	memcpy(siid, hash, LICHEN_EUI64_LEN);
	siid[0] |= 0x02U;
	crypto_wipe(hash, sizeof(hash));
}

static size_t build_signed_frame(const struct lichen_link_ctx *signer,
				 const uint8_t siid[LICHEN_EUI64_LEN],
				 const uint8_t *payload, size_t payload_len,
				 uint8_t epoch, uint16_t seqnum,
				 uint8_t *wire)
{
	struct lichen_frame frame = { 0 };
	int wlen;

	frame.addr_mode = LICHEN_ADDR_BROADCAST;
	frame.epoch = epoch;
	frame.seqnum = seqnum;
	frame.signer_iid_present = true;
	frame.signer_iid_len = LICHEN_EUI64_LEN;
	memcpy(frame.signer_iid, siid, LICHEN_EUI64_LEN);
	frame.payload = payload;
	frame.payload_len = payload_len;
	frame.signature_present = true;
	frame.mic_length = LICHEN_MIC_32;
	frame.mic_len = LICHEN_SIG_LEN;

	wlen = lichen_frame_write(&frame, wire, WIRE_CAP);
	if (wlen <= 0) {
		FAIL("frame_write (pre-sign) = %d", wlen);
		return 0;
	}
	if (schnorr48_sign_frame(wire[0], wire[1], frame.epoch, frame.seqnum,
				 NULL, 0U, frame.signer_iid,
				 frame.signer_iid_len, payload, payload_len,
				 signer->ed25519_sk, signer->ed25519_pk,
				 frame.mic) != 0) {
		FAIL("schnorr48_sign_frame");
		return 0;
	}
	wlen = lichen_frame_write(&frame, wire, WIRE_CAP);
	if (wlen <= 0) {
		FAIL("frame_write = %d", wlen);
		return 0;
	}
	return (size_t)wlen;
}

static size_t build_unsigned_frame(const uint8_t *payload, size_t payload_len,
				   uint8_t epoch, uint16_t seqnum,
				   uint8_t *wire)
{
	struct lichen_frame frame = { 0 };
	int wlen;

	frame.addr_mode = LICHEN_ADDR_BROADCAST;
	frame.epoch = epoch;
	frame.seqnum = seqnum;
	frame.payload = payload;
	frame.payload_len = payload_len;
	/* S=0, SI=0: unsigned frames MUST clear both bits (spec 4.2). */

	wlen = lichen_frame_write(&frame, wire, WIRE_CAP);
	if (wlen <= 0) {
		FAIL("frame_write unsigned = %d", wlen);
		return 0;
	}
	return (size_t)wlen;
}

/* ─── RX driver: mirrors peer_try_all_pubkeys SIID-indexed selection ─────── */

static int rx_selected(const struct trust_store *store,
		       struct lichen_replay_table *replay,
		       const uint8_t *frame, size_t frame_len,
		       uint8_t *out_payload, size_t *out_len,
		       struct lichen_link_rx_payload_info *info)
{
	struct lichen_frame parsed;
	const struct trust_entry *candidate;
	struct lichen_link_rx_ctx rx;

	if (lichen_frame_parse(&parsed, frame, frame_len) < 0) {
		return -EINVAL;
	}
	if (!parsed.signature_present || !parsed.signer_iid_present ||
	    parsed.signer_iid_len != LICHEN_EUI64_LEN) {
		return -LICHEN_EAUTH;
	}
	candidate = trust_find(store, parsed.signer_iid);
	if (candidate == NULL) {
		return -LICHEN_EAUTH; /* fail closed: no candidate, no fallback */
	}
	rx.peer_pubkey = candidate->pubkey;
	rx.peer_eui64 = candidate->siid;
	rx.link_key = NULL;
	rx.current_time = 0U;
	return lichen_link_rx_payload(&rx, replay, frame, frame_len,
				      out_payload, out_len, info);
}

static size_t replay_active_count(const struct lichen_replay_table *rt)
{
	size_t n = 0;

	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (rt->peers[i].active) {
			n++;
		}
	}
	return n;
}

/* ─── Tests ───────────────────────────────────────────────────────────────── */

static uint8_t payload_a[PAYLOAD_MAX];
static uint8_t payload_b[PAYLOAD_MAX];

static void test_unknown_siid_rejected_fail_closed(void)
{
	struct lichen_link_ctx origin;
	uint8_t origin_siid[LICHEN_EUI64_LEN];
	uint8_t wire[WIRE_CAP];
	uint8_t out[PAYLOAD_MAX];
	struct lichen_replay_table replay;
	struct trust_store store = { 0 };
	struct lichen_link_rx_payload_info info = { 0 };
	size_t out_len = sizeof(out);
	size_t frame_len;
	int ret;

	make_identity(0xa1, &origin, origin_siid);
	lichen_replay_table_init(&replay);
	for (size_t i = 0; i < PAYLOAD_A_LEN; i++) {
		payload_a[i] = (uint8_t)(0x15 + i);
	}
	frame_len = build_signed_frame(&origin, origin_siid, payload_a,
				       PAYLOAD_A_LEN, 3U, 40U, wire);
	CHECK_OK(frame_len > 0, "frame build");

	/* Store empty: SIID unknown -> fail closed with no candidate. */
	ret = rx_selected(&store, &replay, wire, frame_len, out, &out_len, &info);
	CHECK_OK(ret == -LICHEN_EAUTH, "unknown SIID ret=%d want -EAUTH", ret);
	CHECK_OK(replay_active_count(&replay) == 0,
		 "replay state allocated pre-verify (%zu entries)",
		 replay_active_count(&replay));

	lichen_link_cleanup(&origin);
}

static void test_pinned_accept_then_duplicate_rejected(void)
{
	struct lichen_link_ctx origin;
	uint8_t origin_siid[LICHEN_EUI64_LEN];
	uint8_t wire[WIRE_CAP];
	uint8_t out[PAYLOAD_MAX];
	struct lichen_replay_table replay;
	struct trust_store store = { 0 };
	struct lichen_link_rx_payload_info info = { 0 };
	size_t out_len = sizeof(out);
	size_t frame_len;
	int ret;

	make_identity(0xb2, &origin, origin_siid);
	lichen_replay_table_init(&replay);
	frame_len = build_signed_frame(&origin, origin_siid, payload_a,
				       PAYLOAD_A_LEN, 1U, 7U, wire);
	CHECK_OK(frame_len > 0, "frame build");

	/* Pin on first verified contact (out-of-band announce/EDHOC path). */
	ret = trust_pin(&store, origin_siid, origin.ed25519_pk);
	CHECK_OK(ret == 0, "trust_pin = %d", ret);

	ret = rx_selected(&store, &replay, wire, frame_len, out, &out_len, &info);
	CHECK_OK(ret == 0, "pinned accept ret=%d", ret);
	if (ret == 0) {
		CHECK_OK(out_len == PAYLOAD_A_LEN, "payload len %zu != %zu",
			 out_len, PAYLOAD_A_LEN);
		CHECK_OK(memcmp(out, payload_a, PAYLOAD_A_LEN) == 0,
			 "payload mismatch");
		CHECK_OK(memcmp(info.src_eui64, origin_siid,
				LICHEN_EUI64_LEN) == 0,
			 "src_eui64 != SIID");
		CHECK_OK(info.signature_present, "signature_present not set");
	}
	CHECK_OK(replay_active_count(&replay) == 1,
		 "replay entries after accept = %zu", replay_active_count(&replay));

	/* Same frame again: replay rejection (state committed on accept). */
	out_len = sizeof(out);
	ret = rx_selected(&store, &replay, wire, frame_len, out, &out_len, &info);
	CHECK_OK(ret == -EALREADY, "duplicate ret=%d want -EALREADY", ret);
	CHECK_OK(replay_active_count(&replay) == 1,
		 "replay entries after duplicate = %zu",
		 replay_active_count(&replay));

	lichen_link_cleanup(&origin);
}

static void test_wrong_key_rejected_no_fallback(void)
{
	struct lichen_link_ctx victim;
	struct lichen_link_ctx attacker;
	uint8_t victim_siid[LICHEN_EUI64_LEN];
	uint8_t attacker_siid[LICHEN_EUI64_LEN];
	uint8_t wire[WIRE_CAP];
	uint8_t out[PAYLOAD_MAX];
	struct lichen_replay_table replay;
	struct trust_store store = { 0 };
	struct lichen_link_rx_payload_info info = { 0 };
	size_t out_len = sizeof(out);
	size_t frame_len;
	int ret;

	make_identity(0xc3, &victim, victim_siid);
	make_identity(0xd4, &attacker, attacker_siid);
	lichen_replay_table_init(&replay);
	CHECK_OK(trust_pin(&store, victim_siid, victim.ed25519_pk) == 0,
		 "pin victim");

	/* Attacker signs with own (unknown) key under own SIID. */
	frame_len = build_signed_frame(&attacker, attacker_siid, payload_a,
				       PAYLOAD_A_LEN, 1U, 8U, wire);
	CHECK_OK(frame_len > 0, "frame build");
	ret = rx_selected(&store, &replay, wire, frame_len, out, &out_len, &info);
	CHECK_OK(ret == -LICHEN_EAUTH, "unknown attacker SIID ret=%d", ret);
	CHECK_OK(replay_active_count(&replay) == 0, "replay state allocated");

	/* Attacker signs with own key but claims the victim's SIID. */
	frame_len = build_signed_frame(&attacker, victim_siid, payload_a,
				       PAYLOAD_A_LEN, 1U, 9U, wire);
	CHECK_OK(frame_len > 0, "frame build");
	ret = rx_selected(&store, &replay, wire, frame_len, out, &out_len, &info);
	CHECK_OK(ret == -LICHEN_EAUTH, "victim SIID + attacker key ret=%d", ret);
	CHECK_OK(replay_active_count(&replay) == 0, "replay state allocated");

	lichen_link_cleanup(&victim);
	lichen_link_cleanup(&attacker);
}

static void test_pinned_mismatch_decoy_rejected(void)
{
	struct lichen_link_ctx victim;
	struct lichen_link_ctx decoy;
	uint8_t victim_siid[LICHEN_EUI64_LEN];
	uint8_t decoy_siid[LICHEN_EUI64_LEN];
	uint8_t wire[WIRE_CAP];
	uint8_t out[PAYLOAD_MAX];
	struct lichen_replay_table replay;
	struct trust_store store = { 0 };
	struct lichen_link_rx_payload_info info = { 0 };
	size_t out_len = sizeof(out);
	size_t frame_len;
	int ret;

	make_identity(0xe5, &victim, victim_siid);
	make_identity(0xf6, &decoy, decoy_siid);
	lichen_replay_table_init(&replay);
	CHECK_OK(trust_pin(&store, victim_siid, victim.ed25519_pk) == 0,
		 "pin victim");
	CHECK_OK(trust_pin(&store, decoy_siid, decoy.ed25519_pk) == 0,
		 "pin decoy");

	/* Decoy frame: victim SIID, decoy key. The signature is
	 * CRYPTOGRAPHICALLY VALID under the pinned decoy key, so a
	 * trial-verify fallback would accept it. SIID-indexed selection
	 * must reject via the pinned victim key, and the production SIID
	 * binding gate must reject it even when handed the decoy key. */
	frame_len = build_signed_frame(&decoy, victim_siid, payload_a,
				       PAYLOAD_A_LEN, 2U, 10U, wire);
	CHECK_OK(frame_len > 0, "frame build");

	ret = rx_selected(&store, &replay, wire, frame_len, out, &out_len, &info);
	CHECK_OK(ret == -LICHEN_EAUTH,
		 "decoy via SIID selection ret=%d want -EAUTH", ret);
	CHECK_OK(replay_active_count(&replay) == 0, "replay state allocated");

	/* No-fallback proof against the production binding gate: even with
	 * the decoy key as candidate (what trial-verify would find), the
	 * frame is rejected because SIID != canonical EUI-64(decoy key). */
	{
		struct lichen_link_rx_ctx rx = { 0 };

		rx.peer_pubkey = decoy.ed25519_pk;
		rx.peer_eui64 = decoy_siid;
		out_len = sizeof(out);
		ret = lichen_link_rx_payload(&rx, &replay, wire, frame_len,
					     out, &out_len, &info);
		CHECK_OK(ret == -LICHEN_EAUTH,
			 "decoy key direct verify ret=%d want -EAUTH", ret);
	}
	CHECK_OK(replay_active_count(&replay) == 0, "replay state allocated");

	lichen_link_cleanup(&victim);
	lichen_link_cleanup(&decoy);
}

static void test_multihop_relay_resigned_and_accepted(void)
{
	struct lichen_link_ctx origin;
	struct lichen_link_ctx relay;
	uint8_t origin_siid[LICHEN_EUI64_LEN];
	uint8_t relay_siid[LICHEN_EUI64_LEN];
	uint8_t wire_a[WIRE_CAP];
	uint8_t wire_b[WIRE_CAP];
	uint8_t out[PAYLOAD_MAX];
	struct lichen_replay_table replay_b;
	struct lichen_replay_table replay_c;
	struct trust_store store_b = { 0 };
	struct trust_store store_c = { 0 };
	struct lichen_link_rx_payload_info info = { 0 };
	struct lichen_frame parsed_b;
	struct lichen_link_rx_ctx relay_rx = { 0 };
	uint16_t tx_seq_before;
	size_t out_len = sizeof(out);
	size_t wire_b_len;
	size_t frame_a_len;
	int ret;

	make_identity(0x11, &origin, origin_siid);
	make_identity(0x22, &relay, relay_siid);
	lichen_replay_table_init(&replay_b);
	lichen_replay_table_init(&replay_c);
	for (size_t i = 0; i < PAYLOAD_B_LEN; i++) {
		payload_b[i] = (uint8_t)(0x41 + (i % 26));
	}

	/* Hop 1: origin signs (payload preserved verbatim by the relay). */
	frame_a_len = build_signed_frame(&origin, origin_siid, payload_b,
					 PAYLOAD_B_LEN, 4U, 20U, wire_a);
	CHECK_OK(frame_a_len > 0, "origin frame build");

	/* Relay B pins A (first verified contact), then re-signs. */
	CHECK_OK(trust_pin(&store_b, origin_siid, origin.ed25519_pk) == 0,
		 "B pins A");
	relay_rx.peer_pubkey = origin.ed25519_pk;
	relay_rx.peer_eui64 = origin_siid;
	tx_seq_before = relay.tx_seq;
	ret = lichen_link_relay_frame(&relay_rx, &replay_b, &relay, wire_a,
				      frame_a_len, NULL, wire_b, &out_len);
	CHECK_OK(ret == 0, "relay_frame ret=%d", ret);
	CHECK_OK(relay.tx_seq != tx_seq_before, "relay tuple not consumed");
	wire_b_len = out_len;

	/* The relayed frame carries B's SIID and B's signature. */
	ret = lichen_frame_parse(&parsed_b, wire_b, wire_b_len);
	CHECK_OK(ret == 0, "parse relayed ret=%d", ret);
	if (ret == 0) {
		CHECK_OK(parsed_b.signature_present, "relayed not signed");
		CHECK_OK(memcmp(parsed_b.signer_iid, relay_siid,
				LICHEN_EUI64_LEN) == 0,
			 "relayed SIID != relay identity");
		CHECK_OK(parsed_b.payload_len == PAYLOAD_B_LEN,
			 "relayed payload len %zu != %zu",
			 parsed_b.payload_len, PAYLOAD_B_LEN);
		CHECK_OK(memcmp(parsed_b.payload, payload_b, PAYLOAD_B_LEN) == 0,
			 "relayed payload mutated");
	}

	/* Hop 2: C pins the relay (not the origin) and accepts B's frame. */
	CHECK_OK(trust_pin(&store_c, relay_siid, relay.ed25519_pk) == 0,
		 "C pins B");
	out_len = sizeof(out);
	ret = rx_selected(&store_c, &replay_c, wire_b, wire_b_len, out,
			  &out_len, &info);
	CHECK_OK(ret == 0, "C accept relayed ret=%d", ret);
	if (ret == 0) {
		CHECK_OK(out_len == PAYLOAD_B_LEN, "C payload len %zu", out_len);
		CHECK_OK(memcmp(out, payload_b, PAYLOAD_B_LEN) == 0,
			 "C payload mismatch");
		CHECK_OK(memcmp(info.src_eui64, relay_siid,
				LICHEN_EUI64_LEN) == 0,
			 "C src_eui64 != relay SIID (must pin relay, not origin)");
	}
	CHECK_OK(replay_active_count(&replay_c) == 1, "C replay entries");

	/* C does not know the origin: A's original frame fails closed. */
	out_len = sizeof(out);
	ret = rx_selected(&store_c, &replay_c, wire_a, frame_a_len, out,
			  &out_len, &info);
	CHECK_OK(ret == -LICHEN_EAUTH, "C origin frame ret=%d want -EAUTH", ret);

	/* Replaying the same frame into the relay is rejected. */
	out_len = sizeof(wire_b);
	ret = lichen_link_relay_frame(&relay_rx, &replay_b, &relay, wire_a,
				      frame_a_len, NULL, wire_b, &out_len);
	CHECK_OK(ret == -EALREADY, "relay duplicate ret=%d want -EALREADY", ret);

	/* A relay attempt against an unpinned signer fails closed and does
	 * not consume a relay TX tuple (no pre-verify state allocation). */
	{
		struct lichen_link_rx_ctx wrong_rx = { 0 };

		wrong_rx.peer_pubkey = relay.ed25519_pk; /* wrong candidate */
		wrong_rx.peer_eui64 = relay_siid;
		tx_seq_before = relay.tx_seq;
		out_len = sizeof(wire_b);
		ret = lichen_link_relay_frame(&wrong_rx, NULL, &relay, wire_a,
					      frame_a_len, NULL, wire_b,
					      &out_len);
		CHECK_OK(ret == -LICHEN_EAUTH, "relay wrong key ret=%d", ret);
		CHECK_OK(relay.tx_seq == tx_seq_before,
			 "TX tuple consumed on failed relay");
	}

	lichen_link_cleanup(&origin);
	lichen_link_cleanup(&relay);
}

static void test_unsigned_frame_rejected(void)
{
	struct lichen_link_ctx peer;
	uint8_t peer_siid[LICHEN_EUI64_LEN];
	uint8_t wire[WIRE_CAP];
	uint8_t out[PAYLOAD_MAX];
	struct lichen_replay_table replay;
	struct trust_store store = { 0 };
	struct lichen_link_rx_payload_info info = { 0 };
	size_t out_len = sizeof(out);
	size_t frame_len;
	int ret;

	make_identity(0x33, &peer, peer_siid);
	lichen_replay_table_init(&replay);
	CHECK_OK(trust_pin(&store, peer_siid, peer.ed25519_pk) == 0, "pin");
	frame_len = build_unsigned_frame(payload_a, PAYLOAD_A_LEN, 1U, 30U,
					 wire);
	CHECK_OK(frame_len > 0, "unsigned frame build");

	ret = rx_selected(&store, &replay, wire, frame_len, out, &out_len, &info);
	CHECK_OK(ret == -LICHEN_EAUTH, "unsigned ret=%d want -EAUTH", ret);
	CHECK_OK(replay_active_count(&replay) == 0, "replay state allocated");

	lichen_link_cleanup(&peer);
}

static void test_tx_schc_rejection_returns_eschc(void)
{
	struct lichen_link_ctx ctx;
	uint8_t siid[LICHEN_EUI64_LEN];
	uint8_t packet[52];
	uint8_t frame[256];
	size_t frame_len = sizeof(frame);
	uint16_t checksum = 0;
	int ret;

	make_identity(0x77, &ctx, siid);

	/* Valid UDP/IPv6 packet (5000->5001 "ping") whose SOURCE is loopback:
	 * structurally clean, checksum valid, but rejected by the SCHC
	 * emission endpoint policy.  lichen_link_tx must surface the
	 * LICHEN-specific rejection code, not a raw (POSIX-colliding) SCHC
	 * code, so L2 can distinguish caller-input rejections from transport
	 * failures. */
	memset(packet, 0, sizeof(packet));
	packet[0] = 0x60;
	packet[5] = 12; /* payload length */
	packet[6] = 17; /* UDP */
	packet[7] = 64; /* hop limit */
	memcpy(&packet[8], "\x00\x00\x00\x00\x00\x00\x00\x00"
			  "\x00\x00\x00\x00\x00\x00\x00\x01", 16);
	memcpy(&packet[24], "\xfe\x80\x00\x00\x00\x00\x00\x00"
			    "\x00\x00\x00\x00\x00\x00\x00\x02", 16);
	packet[40] = 0x13;
	packet[41] = 0x88; /* src port 5000 */
	packet[42] = 0x13;
	packet[43] = 0x89; /* dst port 5001 */
	packet[44] = 0;
	packet[45] = 12; /* UDP length */
	memcpy(&packet[48], "ping", 4);
	if (udp_checksum(&packet[8], &packet[24], 5000, 5001, &packet[48],
			 4, &checksum) != SCHC_OK) {
		FAIL("udp_checksum");
		return;
	}
	packet[46] = (uint8_t)(checksum >> 8);
	packet[47] = (uint8_t)(checksum & 0xff);

	ret = lichen_link_tx(&ctx, packet, sizeof(packet), NULL, frame,
			     &frame_len);
	CHECK_OK(ret == -LICHEN_ESCHC, "policy-rejected tx ret=%d want -ESCHC",
		 ret);
	CHECK_OK(frame_len == sizeof(frame),
		 "frame_len untouched on rejection (%zu)", frame_len);
	lichen_link_cleanup(&ctx);
}

static void test_tx_without_key_returns_enokey(void)
{
	struct lichen_link_ctx ctx;
	uint8_t eui64[LICHEN_EUI64_LEN] = { 0x02, 0, 0, 0, 0, 0, 0, 0x78 };
	uint8_t packet[52];
	uint8_t frame[256];
	size_t frame_len = sizeof(frame);
	int ret;

	if (lichen_link_init(&ctx, eui64) != 0) {
		FAIL("lichen_link_init keyless");
		return;
	}

	ret = lichen_link_tx(&ctx, packet, sizeof(packet), NULL, frame,
			     &frame_len);
	CHECK_OK(ret == -ENOKEY, "keyless tx ret=%d want -ENOKEY", ret);
	lichen_link_cleanup(&ctx);
}

int main(void)
{
	for (size_t i = 0; i < PAYLOAD_A_LEN; i++) {
		payload_a[i] = (uint8_t)(i ^ 0x5a);
	}
	for (size_t i = 0; i < PAYLOAD_B_LEN; i++) {
		payload_b[i] = (uint8_t)(i ^ 0xa5);
	}

	test_unknown_siid_rejected_fail_closed();
	test_pinned_accept_then_duplicate_rejected();
	test_wrong_key_rejected_no_fallback();
	test_pinned_mismatch_decoy_rejected();
	test_multihop_relay_resigned_and_accepted();
	test_unsigned_frame_rejected();
	test_tx_schc_rejection_returns_eschc();
	test_tx_without_key_returns_enokey();

	if (failures != 0) {
		printf("l2_key_selection: %d FAILURES\n", failures);
		return 1;
	}
	printf("l2_key_selection: all tests passed\n");
	return 0;
}
