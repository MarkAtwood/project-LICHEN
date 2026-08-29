/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen_l2_peer.c
 * @brief LICHEN L2 peer table management
 *
 * Contains peer_find_locked(), peer_find_oldest_locked(), the SIID-indexed
 * signer key selection in peer_try_all_pubkeys() (spec/02-physical-link.md
 * 4.2; historical name), lichen_peer_add(), lichen_peer_remove(), and
 * lichen_l2_publish_app_identity().
 */

#include "lichen_l2_internal.h"

LOG_MODULE_DECLARE(lichen_l2, CONFIG_LICHEN_L2_LOG_LEVEL);

/* ─── Peer table management ──────────────────────────────────────────────── */

#if HAVE_LICHEN_LINK
/**
 * @brief Find peer entry by EUI-64 (internal, caller must hold rx_mutex).
 *
 * Uses memcmp (not constant-time) because EUI-64 addresses are public
 * identifiers, not secrets. Peer-authenticated RX uses peer_try_all_pubkeys(),
 * which resolves the signer key with the same memcmp lookup (keyed by the
 * frame SIID, which the link layer binds to the canonical key-derived
 * EUI-64 after verification) and then runs exactly one lichen_link_rx()
 * Schnorr-48 verify with that candidate key. EUI-64 compare timing does
 * not reveal secret material.
 *
 * @param eui64 8-byte peer EUI-64 address
 * @return Pointer to entry if found, NULL otherwise
 */
struct lichen_peer_entry *peer_find_locked(const uint8_t eui64[8])
{
	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): If peer_table_valid is 0,
	 * the table may be in an inconsistent state (partially cleared by a
	 * crash-mid-loop or by lichen_l2_enable disable path before the
	 * clearing loop started). Treat as empty.
	 */
	if (!atomic_get(&peer_table_valid)) {
		return NULL;
	}
	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (peer_table[i].active &&
		    memcmp(peer_table[i].eui64, eui64, LICHEN_EUI64_LEN) == 0) {
			return &peer_table[i];
		}
	}
	return NULL;
}

/**
 * @brief Find oldest (least-recently-seen) peer for eviction.
 *
 * Used for LRU eviction when the peer table is full (project-LICHEN-tvfm.98).
 * Caller must hold rx_mutex.
 *
 * @return Index of oldest peer, or -1 if table is empty
 */
int peer_find_oldest_locked(void)
{
	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): If peer_table_valid is 0,
	 * the table may be partially cleared. Treat as empty.
	 */
	if (!atomic_get(&peer_table_valid)) {
		return -1;
	}
	int oldest_idx = -1;
	int64_t oldest_time = INT64_MAX;

	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (peer_table[i].active && peer_table[i].last_seen != INT64_MAX
		    && peer_table[i].last_seen < oldest_time) {
			oldest_time = peer_table[i].last_seen;
			oldest_idx = (int)i;
		}
	}
	return oldest_idx;
}

/**
 * @brief Resolve the signer key from the frame SIID and verify the frame.
 *
 * SIID-indexed key selection per spec/02-physical-link.md 4.2 (decision
 * project-LICHEN-worker6-nxew option b). The historical name is retained
 * because lichen_l2_rx.c calls it; selection is no longer trial
 * verification over the whole table. The wire SIID is the signer's
 * canonical key-derived EUI-64 in extended form (U/L set), which is the
 * same key the peer/TOFU cache is indexed by, so the lookup is a direct
 * peer_find_locked() on the SIID octets followed by exactly ONE
 * lichen_link_rx() Schnorr-48 verify with the selected candidate key.
 *
 * SECURITY: This function is the authentication boundary. Only returns
 * success if the SIID-selected trust-store entry's pubkey verifies the
 * signature. lichen_link_rx() additionally binds the authenticated SIID
 * to the canonical EUI-64 derived from the verified key, so the SIID is
 * a routing hint only and cannot authorize a caller-selected alias.
 *
 * CONSTANT-TIME TRADE (project-LICHEN-worker6-jfln): the former O(N)
 * trial-verify scanned every table entry at full Schnorr-48 cost and was
 * constant-time across the peer set. This selection replaces that with
 * one memcmp scan over EUI-64s - public routing identifiers, not
 * secrets, the same class of comparison peer_find_locked() already
 * makes - and a single always-full-cost verify. No key-dependent
 * branching or key-dependent memory access happens before verification;
 * the candidate key is chosen purely by the public SIID, and acceptance
 * is decided solely by that single verify.
 *
 * FAIL-CLOSED (spec 4.2 steps 1/2/4): an SIID with no trust-store entry
 * is rejected outright. Spec 4.2 step 3 first-contact trial verification
 * cannot succeed against this table: entries are keyed by the canonical
 * key-derived EUI-64 and lichen_link_rx() rejects any frame whose SIID
 * is not the canonical EUI-64 of the key that verified, so scanning the
 * remaining entries could never turn a lookup miss into an acceptance.
 * A pinned SIID whose frame fails verification is rejected with no
 * fallback and no key substitution.
 *
 * TOFU POPULATION (spec 4.2 step 3 pinning): trust-store entries are
 * pinned out-of-band on first VERIFIED contact via lichen_peer_add()
 * (announce/EDHOC processing or provisioning), which enforces
 * pin-on-first-contact, rejects key changes (-EEXIST), and clears the
 * evicted peer's replay state on LRU eviction (or refuses admission
 * entirely under CONFIG_LICHEN_LINK_REPLAY_PERSIST). RX never allocates
 * trust or replay state before verification succeeds.
 *
 * THREAD SAFETY: same contract as before - caller holds rx_mutex; the
 * ctx is a local stack variable in the caller (lichen_l2_input). The
 * modify-then-restore pattern is kept: success modifies ctx, failure
 * leaves it unmodified (project-LICHEN-tvfm.104).
 *
 * @param ctx        RX context (peer_pubkey set to the selected key)
 * @param replay     Replay table for duplicate detection (replay state
 *                   is only committed after signature verification)
 * @param frame      Raw LICHEN frame bytes
 * @param frame_len  Length of frame
 * @param out_ipv6   Output buffer for decompressed IPv6 packet
 * @param out_len    In: buffer size, Out: IPv6 packet length
 * @param src_eui64  Filled with sender's EUI-64 on success
 * @return 0 on success (peer found and verified), negative error otherwise
 */
int peer_try_all_pubkeys(struct lichen_link_rx_ctx *ctx,
			 struct lichen_replay_table *replay,
			 const uint8_t *frame, size_t frame_len,
			 uint8_t *out_ipv6, size_t *out_len,
			 uint8_t src_eui64[8])
{
	int ret;
	size_t saved_out_len = *out_len;
	const uint8_t *saved_peer_pubkey = ctx->peer_pubkey;
	const uint8_t *saved_peer_eui64 = ctx->peer_eui64;
	struct lichen_frame parsed;
	struct lichen_peer_entry *peer;

	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): If peer_table_valid is 0,
	 * the table may be partially cleared. Return auth failure rather
	 * than attempting verification against inconsistent state.
	 */
	if (!atomic_get(&peer_table_valid)) {
		ctx->peer_pubkey = saved_peer_pubkey;
		ctx->peer_eui64 = saved_peer_eui64;
		*out_len = saved_out_len;
		return -LICHEN_EAUTH;
	}

	ret = lichen_frame_parse(&parsed, frame, frame_len);
	if (ret < 0) {
		return -EINVAL;
	}

	/*
	 * SECURITY: This helper is the peer-authenticated RX path. Unsigned frames
	 * must not be attributed to a known peer by trying each peer's public key;
	 * without a signature, lichen_link_rx() has no peer-auth proof to verify.
	 */
	if (!parsed.signature_present) {
		return -LICHEN_EAUTH;
	}

	/*
	 * SECURITY (spec/02-physical-link.md 4.2): Signed frames MUST set both
	 * S and SI and carry exactly one 8-byte signer EUI-64. lichen_frame_parse()
	 * rejects an S/SI mismatch; this check keeps the selection independent
	 * of parser internals.
	 */
	if (!parsed.signer_iid_present ||
	    parsed.signer_iid_len != LICHEN_EUI64_LEN) {
		return -LICHEN_EAUTH;
	}

	/*
	 * SECURITY: SIID-indexed lookup into the peer/TOFU cache keyed by
	 * canonical EUI-64 (see function comment for the constant-time
	 * trade, fail-closed policy, and TOFU population). A lookup miss
	 * is an authentication failure: no candidate key, no trial
	 * verification, no state allocation.
	 */
	peer = peer_find_locked(parsed.signer_iid);
	if (peer == NULL) {
		LOG_DBG("lichen_l2: RX unknown SIID ..%02x:%02x rejected",
			parsed.signer_iid[6], parsed.signer_iid[7]);
		ctx->peer_pubkey = saved_peer_pubkey;
		ctx->peer_eui64 = saved_peer_eui64;
		*out_len = saved_out_len;
		return -LICHEN_EAUTH;
	}

	ctx->peer_pubkey = peer->pubkey;
	ctx->peer_eui64 = peer->eui64;
	*out_len = saved_out_len;

	/* Single verify with the SIID-selected pinned key. lichen_link_rx()
	 * commits replay state only after the signature verifies, so a
	 * rejected frame never allocates replay/trust state. */
	ret = lichen_link_rx(ctx, replay, frame, frame_len,
			     out_ipv6, out_len, src_eui64);
	if (ret < 0) {
		ctx->peer_pubkey = saved_peer_pubkey;
		ctx->peer_eui64 = saved_peer_eui64;
		*out_len = saved_out_len;
		return ret;
	}

	peer->last_seen = k_uptime_get();
	LOG_DBG("lichen_l2: RX auth ok (peer ..%02x:%02x)",
		peer->eui64[6], peer->eui64[7]);
	return 0;
}
#endif /* HAVE_LICHEN_LINK */

int lichen_peer_add(const uint8_t *eui64,
		    const uint8_t *pubkey)
{
#if HAVE_LICHEN_LINK
	/*
	 * SECURITY: Array parameters decay to pointers - no compile-time or
	 * runtime size enforcement. BUILD_ASSERTs at lines 108-111 verify the
	 * array sizes in the function signature (8, 32) match our constants.
	 * Callers MUST pass buffers of exactly these sizes; undersized buffers
	 * cause undefined behavior (buffer overread in memcpy below).
	 */
	if (eui64 == NULL || pubkey == NULL) {
		return -EINVAL;
	}

	/* SECURITY: Reject peer_add if interface initialization failed (project-LICHEN-0li1.66) */
	if (atomic_get(&iface_init_failed)) {
		LOG_ERR("lichen_l2: peer_add rejected (init failed)");
		return -ENODEV;
	}

	/*
	 * Check for prior abort BEFORE acquiring mutex (project-LICHEN-dq6n.21).
	 *
	 * If the lora_l2 RX thread was forcibly aborted, it may have been terminated
	 * while holding rx_mutex (during lichen_l2_input callback processing).
	 * Attempting to acquire rx_mutex would deadlock forever.
	 *
	 * Recovery requires: lichen_lora_l2_deinit() + lichen_lora_l2_init()
	 */
	if (lichen_lora_l2_needs_reinit()) {
		LOG_ERR("lichen_l2: peer_add rejected (reinit required after abort)");
		return -ECANCELED;
	}

	/*
	 * Reject peer_add when module is not initialized (project-LICHEN-i1gk.53).
	 *
	 * After deinit(), the state is UNINIT. needs_reinit() returns false (state !=
	 * ABORTED), so the check above passes. But peer_add() would populate peer_table
	 * that gets wiped by the next init() (via memset/secure_zero). This causes
	 * silent peer data loss. Reject early with a clear error.
	 *
	 * Note: is_running() returns false for UNINIT, STOPPED, ABORTED, and DEINITING.
	 * We specifically need the "not initialized at all" case, which is UNINIT.
	 * Using copy_eui64() as a proxy because there's no is_initialized() API.
	 */
	uint8_t self_eui64[LICHEN_EUI64_LEN];
	int ret = lichen_lora_l2_copy_eui64(self_eui64);
	if (ret < 0) {
		LOG_ERR("lichen_l2: peer_add rejected (LoRa L2 unavailable, %d)", ret);
		return ret;
	}

	k_mutex_lock(&rx_mutex, K_FOREVER);

	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): Reject peer_add if the peer
	 * table is in an inconsistent state (e.g., crash during disable-path
	 * clearing mid-loop). We cannot safely add a peer to a partially-
	 * cleared table.
	 */
	if (!atomic_get(&peer_table_valid)) {
		k_mutex_unlock(&rx_mutex);
		return -EBUSY;
	}

	/* Check if peer already exists - update pubkey if so */
	struct lichen_peer_entry *existing = peer_find_locked(eui64);
	if (existing != NULL) {
		/*
		 * SECURITY: TOFU key pinning (spec 8.6). First contact pins
		 * pubkey; subsequent contacts must present the same key.
		 * Key rotation requires explicit removal (lichen_peer_remove)
		 * followed by re-add. Silent key changes are rejected to
		 * prevent impersonation attacks.
		 */
		if (crypto_verify32(existing->pubkey, pubkey) != 0) {
			LOG_WRN("lichen_l2: TOFU violation for ..%02x:%02x "
				"(pubkey mismatch)", eui64[6], eui64[7]);
			k_mutex_unlock(&rx_mutex);
			return -EEXIST;
		}
		/* Same key — just refresh last_seen timestamp */
		existing->last_seen = k_uptime_get();
		k_mutex_unlock(&rx_mutex);
		return 0;  /* Peer already known with same key */
	}

	/* Find an empty slot */
	int slot = -1;
	for (size_t i = 0; i < CONFIG_LICHEN_LINK_MAX_NEIGHBORS; i++) {
		if (!peer_table[i].active) {
			slot = (int)i;
			break;
		}
	}

	/*
	 * LRU eviction when table is full (project-LICHEN-tvfm.98).
	 *
	 * If no empty slot, evict the least-recently-seen peer. This allows
	 * the mesh to adapt to topology changes without manual peer removal.
	 * The evicted peer can re-join via EDHOC handshake if still active.
	 */
	if (slot < 0) {
#ifdef CONFIG_LICHEN_LINK_REPLAY_PERSIST
		/* SECURITY: Durable replay history is trust lineage. Automatic LRU
		 * eviction would authorize captured frames from the evicted key after
		 * it rejoins. A protected table therefore requires an explicit
		 * administrative peer removal before admitting another identity. */
		k_mutex_unlock(&rx_mutex);
		return -ENOSPC;
#else
		slot = peer_find_oldest_locked();
		if (slot < 0) {
			/* Should not happen: table full but no oldest entry found */
			LOG_ERR("lichen_l2: peer table inconsistent (no eviction candidate)");
			crash_info_store(CRASH_STATE_CORRUPTION, __LINE__,
					 CONFIG_LICHEN_LINK_MAX_NEIGHBORS);
			k_mutex_unlock(&rx_mutex);
			return -ENOSPC;
		}
		/*
		 * SECURITY: Clear replay window before evicting peer.
		 * Stale replay state from the evicted peer could cause valid
		 * packets to be rejected if that peer reconnects and its new
		 * sequence numbers fall within the old window.
		 * (project-LICHEN-0li1.53)
		 */
		int replay_ret = lichen_replay_remove(&replay_table,
						 peer_table[slot].pubkey);
		if (replay_ret != 0) {
			LOG_ERR("replay state eviction persist failed (%d)", replay_ret);
			k_mutex_unlock(&rx_mutex);
			return replay_ret;
		}
		LOG_INF("lichen_l2: peer table full, evicting ..%02x:%02x",
			peer_table[slot].eui64[6], peer_table[slot].eui64[7]);
#endif
	}

	memcpy(peer_table[slot].eui64, eui64, LICHEN_EUI64_LEN);
	memcpy(peer_table[slot].pubkey, pubkey, LICHEN_L2_PUBKEY_LEN);
	peer_table[slot].last_seen = k_uptime_get();
	peer_table[slot].active = true;
	LOG_INF("lichen_l2: peer added ..%02x:%02x",
		eui64[6], eui64[7]);
	k_mutex_unlock(&rx_mutex);
	return 0;
#else
	ARG_UNUSED(eui64);
	ARG_UNUSED(pubkey);
	return -ENOTSUP;
#endif
}

int lichen_peer_remove(const uint8_t *eui64)
{
#if HAVE_LICHEN_LINK
	if (eui64 == NULL) {
		return -EINVAL;
	}

	/* SECURITY: Reject peer_remove if interface initialization failed (project-LICHEN-0li1.66) */
	if (atomic_get(&iface_init_failed)) {
		LOG_ERR("lichen_l2: peer_remove rejected (init failed)");
		return -ENODEV;
	}

	/*
	 * Check for prior abort BEFORE acquiring mutex (project-LICHEN-dq6n.21).
	 *
	 * If the lora_l2 RX thread was forcibly aborted, it may have been terminated
	 * while holding rx_mutex (during lichen_l2_input callback processing).
	 * Attempting to acquire rx_mutex would deadlock forever.
	 *
	 * Recovery requires: lichen_lora_l2_deinit() + lichen_lora_l2_init()
	 */
	if (lichen_lora_l2_needs_reinit()) {
		LOG_ERR("lichen_l2: peer_remove rejected (reinit required after abort)");
		return -ECANCELED;
	}

	/*
	 * Reject peer_remove when module is not initialized (project-LICHEN-0li1.11).
	 *
	 * After deinit(), the state is UNINIT. needs_reinit() returns false (state !=
	 * ABORTED), so the check above passes. But peer_remove() would attempt to
	 * access peer_table that may be in an indeterminate state. Reject early with
	 * a clear error.
	 *
	 * Using copy_eui64() as a proxy because there's no is_initialized() API.
	 */
	uint8_t self_eui64[LICHEN_EUI64_LEN];
	int ret = lichen_lora_l2_copy_eui64(self_eui64);
	if (ret < 0) {
		LOG_ERR("lichen_l2: peer_remove rejected (LoRa L2 unavailable, %d)", ret);
		return ret;
	}

	k_mutex_lock(&rx_mutex, K_FOREVER);

	/*
	 * CRASH SAFETY (project-LICHEN-tvfm.6): Reject peer_remove if the peer
	 * table is in an inconsistent state.
	 */
	if (!atomic_get(&peer_table_valid)) {
		k_mutex_unlock(&rx_mutex);
		return -EBUSY;
	}

	struct lichen_peer_entry *entry = peer_find_locked(eui64);
	if (entry == NULL) {
		k_mutex_unlock(&rx_mutex);
		return -ENOENT;
	}

	/*
	 * SECURITY: Clear replay window for this peer before removing.
	 * Stale replay state could cause valid packets to be rejected
	 * (if sequence numbers overlap) or replayed packets to be accepted
	 * (if the peer reconnects and the attacker replays old frames).
	 * (project-LICHEN-tvfm.45)
	 */
	ret = lichen_replay_remove(&replay_table, entry->pubkey);
	if (ret != 0) {
		LOG_ERR("replay state removal persist failed (%d)", ret);
		k_mutex_unlock(&rx_mutex);
		return ret;
	}

	/* SECURITY: Zero pubkey before marking inactive */
	secure_zero(entry->pubkey, sizeof(entry->pubkey));
	secure_zero(entry->eui64, sizeof(entry->eui64));
	entry->active = false;
	LOG_INF("lichen_l2: peer removed ..%02x:%02x",
		eui64[6], eui64[7]);

	k_mutex_unlock(&rx_mutex);
	return 0;
#else
	ARG_UNUSED(eui64);
	return -ENOTSUP;
#endif
}

int lichen_l2_publish_app_identity(const char *display_name,
				   const char *firmware_name)
{
#if HAVE_LICHEN_LINK && IS_ENABLED(CONFIG_LICHEN_APP_IDENTITY)
	int ret;

	if (atomic_get(&iface_init_failed)) {
		return -ENODEV;
	}
	if (!atomic_get(&link_ctx_initialized)) {
		return -EAGAIN;
	}

	k_mutex_lock(&tx_mutex, K_FOREVER);
	k_mutex_lock(&rx_mutex, K_FOREVER);
	ret = lichen_app_identity_set_self_from_link_ctx(
		&link_ctx, display_name, firmware_name);
	k_mutex_unlock(&rx_mutex);
	k_mutex_unlock(&tx_mutex);

	return ret;
#else
	ARG_UNUSED(display_name);
	ARG_UNUSED(firmware_name);
	return -ENOTSUP;
#endif
}
