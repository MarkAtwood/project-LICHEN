/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file coap_slot_coord.c
 * @brief Slot Coordination protocol implementation (GCP-6)
 *
 * Implements GCP-6 per spec/08-gateway-coordination.md Section 6:
 * - Superframe synchronization (GPS epoch, time master election)
 * - Slot allocation (interleaved and contiguous modes)
 * - Conflict resolution (lowest IID wins, signature validation)
 * - CoAP resources (/info, /slots, /channels)
 * - 6.5 Slot claims as COSE_Sign1 (alg -65537, Schnorr48-Ed25519) over the
 *   full claim payload (slots, superframe_epoch, mode, expiry, gateway_iid,
 *   claim_seq, ordinal)
 *
 * SECURITY: All slot claims are COSE_Sign1 signed with Schnorr48. Claims
 * with invalid or missing signatures are silently discarded per GCP-6.3.
 */

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/util.h>
#include <zephyr/net/coap.h>
#include <zephyr/net/coap_service.h>

#include <lichen/coap_slot_coord.h>
#include <lichen/coap_server.h>
#include <lichen/coap_oscore.h>
#include <lichen/coap_keys.h>
#include <lichen/link.h>
#include <lichen/schnorr48.h>

LOG_MODULE_REGISTER(lichen_slot_coord, CONFIG_LICHEN_COAP_SLOT_COORD_LOG_LEVEL);

/* --------------------------------------------------------------------------
 * CBOR key definitions (matching test vectors)
 * -------------------------------------------------------------------------- */

/* Slot grant keys */
#define KEY_GRANTED_SLOTS   "granted_slots"
#define KEY_VALID_UNTIL     "valid_until"
#define KEY_SUPERFRAME_ID   "superframe_id"

/* Resource response keys (string-keyed, unsigned — GET responses only) */
#define KEY_GATEWAY_COUNT   "gateway_count"
#define KEY_GATEWAY_IID     "gateway_iid"

/* Gateway info keys */
#define KEY_TIME_SOURCE     "time_source"
#define KEY_SLOTS_TOTAL     "slots_total"
#define KEY_ALLOCATED_SLOTS "allocated_slots"
#define KEY_SUPERFRAME_EPOCH "superframe_epoch"
#define KEY_SUPERFRAME_DURATION "superframe_duration_s"

/* Allocation map keys */
#define KEY_ALLOCATION_MODE "allocation_mode"
#define KEY_ALLOCATIONS     "allocations"

/* GCP-6.5 slot claim payload keys (integer, canonical order 1..7) */
#define CLAIM_KEY_SLOTS           1
#define CLAIM_KEY_SUPERFRAME_EPOCH 2
#define CLAIM_KEY_MODE            3
#define CLAIM_KEY_EXPIRY          4
#define CLAIM_KEY_GATEWAY_IID     5
#define CLAIM_KEY_CLAIM_SEQ       6
#define CLAIM_KEY_ORDINAL         7
#define CLAIM_KEY_COUNT           7

/* COSE key 4 = kid (RFC 9052) */
#define COSE_KEY_KID 4

/* COSE_Sign1 element count */
#define COSE_SIGN1_ELEMS 4

/* Protected header: bstr-wrapped canonical {1: -65537} (alg
 * Schnorr48-Ed25519). The map bytes are a1 01 3a 00 01 00 00; the value
 * -65536 (encoded a1 01 39 ff ff) is the spec's decoy and is rejected. */
static const uint8_t cose_protected_alg[] = {
	0xA1, 0x01, 0x3A, 0x00, 0x01, 0x00, 0x00
};

/* Maximum COSE_Sign1 payload we will decode: bounds the Sig_structure
 * scratch buffer. A 60-slot claim is ~165 bytes. */
#define CLAIM_PAYLOAD_MAX 255

/* CBOR content-format */
#define CBOR_CONTENT_FORMAT 60

/* --------------------------------------------------------------------------
 * Internal state
 * -------------------------------------------------------------------------- */

/* Coordinator singleton backing the CoAP resource handlers. Unused when
 * the resource handlers are compiled out (host codec/verify test builds). */
static struct lichen_slot_coord_ctx s_ctx __attribute__((unused));
static K_MUTEX_DEFINE(s_coord_lock);

/* --------------------------------------------------------------------------
 * IID comparison (big-endian unsigned 64-bit)
 * -------------------------------------------------------------------------- */

int lichen_iid_compare(const uint8_t iid_a[LICHEN_IID_LEN],
		       const uint8_t iid_b[LICHEN_IID_LEN])
{
	/* Compare as unsigned big-endian 64-bit integers */
	for (int i = 0; i < LICHEN_IID_LEN; i++) {
		if (iid_a[i] < iid_b[i]) {
			return -1;
		}
		if (iid_a[i] > iid_b[i]) {
			return 1;
		}
	}
	return 0;
}

/* --------------------------------------------------------------------------
 * Initialization
 * -------------------------------------------------------------------------- */

int lichen_slot_coord_init(struct lichen_slot_coord_ctx *ctx,
			   const uint8_t local_iid[LICHEN_IID_LEN])
{
	if (ctx == NULL || local_iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->local_iid, local_iid, LICHEN_IID_LEN);

	/* Default superframe configuration. duration_s comes from the
	 * Kconfig (single source of truth; the host fallback resolves to
	 * LICHEN_SUPERFRAME_DURATION_S) so the superframe-denominated
	 * claim-duration cap and the superframe math cannot diverge. */
	ctx->superframe.time_source = LICHEN_TIME_SOURCE_NONE;
	ctx->superframe.duration_s = CONFIG_LICHEN_CCP_SUPERFRAME_SEC;
	ctx->superframe.slots_per_superframe = LICHEN_SLOTS_PER_SUPERFRAME;
	ctx->superframe.slot_duration_ms = LICHEN_SLOT_DURATION_MS;
	ctx->superframe.synced = false;

	/* Default allocation mode */
	ctx->alloc_mode = LICHEN_SLOT_ALLOC_INTERLEAVED;
	ctx->gateway_count = 0;
	ctx->local_ordinal = 0;
	ctx->local_slot_count = 0;
	ctx->initialized = true;

	k_mutex_unlock(&s_coord_lock);

	LOG_INF("Slot coordination initialized");
	return 0;
}

/* --------------------------------------------------------------------------
 * Superframe timing
 * -------------------------------------------------------------------------- */

uint32_t lichen_slot_coord_superframe_id(const struct lichen_slot_coord_ctx *ctx,
					 uint64_t unix_time)
{
	if (ctx == NULL || ctx->superframe.duration_s == 0) {
		return 0;
	}
	return (uint32_t)(unix_time / ctx->superframe.duration_s);
}

uint8_t lichen_slot_coord_current_slot(const struct lichen_slot_coord_ctx *ctx,
				       uint64_t unix_time)
{
	if (ctx == NULL || ctx->superframe.duration_s == 0) {
		return 0;
	}

	uint64_t superframe_start = (unix_time / ctx->superframe.duration_s) *
				    ctx->superframe.duration_s;
	uint64_t offset = unix_time - superframe_start;

	return (uint8_t)(offset % ctx->superframe.slots_per_superframe);
}

int lichen_slot_coord_elect_time_master(struct lichen_slot_coord_ctx *ctx,
					uint8_t master_iid[LICHEN_IID_LEN])
{
	if (ctx == NULL || master_iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	if (ctx->gateway_count == 0) {
		/* No other gateways, we are the master */
		memcpy(master_iid, ctx->local_iid, LICHEN_IID_LEN);
		memcpy(ctx->superframe.time_master_iid, ctx->local_iid, LICHEN_IID_LEN);
		k_mutex_unlock(&s_coord_lock);
		return 0;
	}

	/* Find lowest IID among all gateways including ourselves */
	memcpy(master_iid, ctx->local_iid, LICHEN_IID_LEN);

	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!ctx->gateways[i].valid) {
			continue;
		}
		if (lichen_iid_compare(ctx->gateways[i].iid, master_iid) < 0) {
			memcpy(master_iid, ctx->gateways[i].iid, LICHEN_IID_LEN);
		}
	}

	memcpy(ctx->superframe.time_master_iid, master_iid, LICHEN_IID_LEN);

	k_mutex_unlock(&s_coord_lock);
	return 0;
}

/* --------------------------------------------------------------------------
 * Slot allocation computation
 * -------------------------------------------------------------------------- */

int lichen_slot_coord_interleaved(uint8_t ordinal, uint8_t gateway_count,
				  uint8_t num_slots, uint8_t *slots,
				  size_t max_slots)
{
	if (slots == NULL || gateway_count == 0) {
		return -EINVAL;
	}

	size_t count = 0;
	for (uint8_t s = ordinal; s < num_slots && count < max_slots; s += gateway_count) {
		slots[count++] = s;
	}

	return (int)count;
}

int lichen_slot_coord_contiguous(uint8_t ordinal, uint8_t gateway_count,
				 uint8_t num_slots, uint8_t *slot_start,
				 uint8_t *slot_count)
{
	if (slot_start == NULL || slot_count == NULL || gateway_count == 0) {
		return -EINVAL;
	}

	uint8_t slots_per_gw = num_slots / gateway_count;
	*slot_start = ordinal * slots_per_gw;
	*slot_count = slots_per_gw;

	return 0;
}

bool lichen_slot_coord_validate_interleaved(const uint8_t *slots,
					    uint8_t slot_count,
					    uint8_t ordinal,
					    uint8_t gateway_count)
{
	if (slots == NULL || gateway_count == 0) {
		return false;
	}

	for (uint8_t i = 0; i < slot_count; i++) {
		/* ordinal + i * gateway_count <= 255 by construction
		 * (slot_count slots, each < gateway_count apart), but int
		 * promotion trips -Werror=conversion on strict host builds. */
		uint8_t expected = (uint8_t)(ordinal + i * gateway_count);
		if (slots[i] != expected) {
			return false;
		}
	}

	return true;
}

bool lichen_slot_coord_tx_allowed(const struct lichen_slot_coord_ctx *ctx,
				  uint8_t current_slot)
{
	if (ctx == NULL || !ctx->initialized) {
		return false;
	}

	for (uint8_t i = 0; i < ctx->local_slot_count; i++) {
		if (ctx->local_slots[i] == current_slot) {
			return true;
		}
	}

	return false;
}

/* --------------------------------------------------------------------------
 * Conflict resolution
 * -------------------------------------------------------------------------- */

const struct lichen_slot_claim *lichen_slot_coord_resolve_conflict(
	const struct lichen_slot_claim *claim_a, bool sig_a_valid,
	const struct lichen_slot_claim *claim_b, bool sig_b_valid)
{
	if (claim_a == NULL || claim_b == NULL) {
		return NULL;
	}

	/* Per GCP-6.3: If one signature fails, valid claim wins */
	if (sig_a_valid && !sig_b_valid) {
		return claim_a;
	}
	if (sig_b_valid && !sig_a_valid) {
		return claim_b;
	}
	if (!sig_a_valid && !sig_b_valid) {
		return NULL; /* Both invalid */
	}

	/* Both valid: lowest IID wins */
	if (lichen_iid_compare(claim_a->gateway_iid, claim_b->gateway_iid) <= 0) {
		return claim_a;
	}
	return claim_b;
}

/* --------------------------------------------------------------------------
 * COSE_Sign1 signature computation and verification (GCP-6.5)
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_TINYCRYPT_SHA256
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#else
/* Keep the verify-path signatures compilable without the tinycrypt
 * headers; the Kconfig select (and the host test define) always provides
 * the real implementation. */
#define TC_SHA256_DIGEST_SIZE 32
#endif

/* Rate-limited WARN for silent discards (GCP-6.3): log the first event
 * then every 32nd so a flood cannot dominate the log. */
static uint32_t s_discard_count;

static void slot_coord_log_discard(const char *reason)
{
	(void)reason;
	if ((s_discard_count & 0x1FU) == 0) {
		LOG_WRN("Discarding slot claim: %s", reason);
	}
	s_discard_count++;
}

/* Zephyr builds get __weak from <zephyr/kernel.h>; host builds here. */
#ifndef __weak
#define __weak __attribute__((weak))
#endif

static size_t claim_store_cose(struct lichen_gateway_alloc *entry,
			       const struct lichen_slot_claim *claim);
static int claim_compute_digest(const uint8_t *payload, size_t payload_len,
				uint8_t digest[TC_SHA256_DIGEST_SIZE]);

enum lichen_claim_result lichen_slot_coord_process_claim(
	struct lichen_slot_coord_ctx *ctx,
	const struct lichen_slot_claim *claim,
	uint64_t now_unix,
	bool clock_valid,
	struct lichen_slot_grant *grant,
	const uint8_t **conflict_cose,
	size_t *conflict_cose_len)
{
	if (ctx == NULL || claim == NULL || grant == NULL) {
		return LICHEN_CLAIM_REJECT_INVALID_SLOTS;
	}

	/* SECURITY: Claims without COSE verification material MUST be
	 * silently discarded (structural guarantee: decode_claim always
	 * populates these) */
	if (claim->cose_payload == NULL || claim->cose_payload_len == 0 ||
	    claim->cose_payload_len > CLAIM_PAYLOAD_MAX ||
	    claim->cose_signature == NULL) {
		LOG_DBG("Discarding claim without verification material");
		return LICHEN_CLAIM_REJECT_NO_SIG;
	}

	/* SECURITY: Verify Schnorr48 signature over the full claim payload
	 * (GCP-6.3, GCP-6.5 validation steps 2-6) */
#ifdef CONFIG_LICHEN_LINK_SCHNORR
	{
		/* Fetch gateway public key from key store; the lookup IID is
		 * the payload gateway_iid (decode_claim already checked it
		 * equals the COSE kid) */
		struct lichen_key_entry key_entry;
		uint8_t digest[TC_SHA256_DIGEST_SIZE];
		int ret = claim_compute_digest(claim->cose_payload,
					       claim->cose_payload_len, digest);
		if (ret < 0) {
			return LICHEN_CLAIM_REJECT_INVALID_SIG;
		}

		ret = lichen_key_store_get(claim->gateway_iid, &key_entry);
		if (ret != 0) {
			slot_coord_log_discard("gateway key not found");
			return LICHEN_CLAIM_REJECT_INVALID_SIG;
		}

		if (!schnorr48_verify(key_entry.pubkey, digest,
				      TC_SHA256_DIGEST_SIZE,
				      claim->cose_signature,
				      LICHEN_SCHNORR48_LEN)) {
			slot_coord_log_discard("invalid signature");
			return LICHEN_CLAIM_REJECT_INVALID_SIG;
		}
	}
#else
#error "slot-coord requires LICHEN_LINK_SCHNORR: claim verification must never be compiled out (fail-open backstop)"
#endif

	/* GCP-6.5 validation step 7: expiry > now. A synced wall clock is a
	 * precondition: lichen_wall_clock_get() returns 0 until first sync,
	 * so without this gate every claim would pass the expiry check
	 * (fail-open) from boot to first time sync. Also treat now==0 as
	 * unsynced: get() and valid() snapshot independently, and a clock
	 * that synced between them could otherwise pair a valid flag with
	 * the stale pre-sync 0 (now==0 is impossible once synced - the
	 * epoch floor rejects it). */
	if (!clock_valid || now_unix == 0) {
		LOG_DBG("Claim rejected: wall clock unsynced");
		return LICHEN_CLAIM_REJECT_NO_CLOCK;
	}
	if (claim->expiry <= now_unix) {
		LOG_DBG("Claim rejected: expired");
		return LICHEN_CLAIM_REJECT_EXPIRED;
	}

	/* GCP-6.5 validation step 7 (upper bound): cap the claim lifetime
	 * at N superframes so a compromised key cannot squat slots with a
	 * far-future expiry (GCP-6 claim-model review). */
	if (claim->expiry >
	    now_unix + (uint64_t)LICHEN_SLOT_CLAIM_MAX_DURATION_SEC) {
		LOG_DBG("Claim rejected: expiry too far in future");
		return LICHEN_CLAIM_REJECT_EXPIRY_TOO_FAR;
	}

	/* GCP-6.5 validation step 8: claim_seq above cached high-water mark */
	{
		uint32_t cached_seq;
		int ret = lichen_slot_claim_seq_lookup(claim->gateway_iid,
						       &cached_seq);
		if (ret == 0 && claim->claim_seq <= cached_seq) {
			LOG_DBG("Claim rejected: claim_seq replay");
			return LICHEN_CLAIM_REJECT_REPLAY;
		}
	}

	/* Slot sanity: at least one slot, all within the superframe */
	if (claim->slot_count == 0 ||
	    claim->slot_count > CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS) {
		LOG_DBG("Claim rejected: invalid slot count");
		return LICHEN_CLAIM_REJECT_INVALID_SLOTS;
	}
	for (uint8_t cs = 0; cs < claim->slot_count; cs++) {
		if (claim->slots[cs] >= ctx->superframe.slots_per_superframe) {
			LOG_DBG("Claim rejected: slot out of range");
			return LICHEN_CLAIM_REJECT_INVALID_SLOTS;
		}
	}

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	/* GCP-6.5 validation step 8 (re-check inside the critical
	 * section): the pre-lock gate above is advisory only. A concurrent
	 * process_claim for the same gateway could pass its own gate and
	 * commit a higher seq between this claim's lookup and this
	 * critical section; without the re-check the stale claim would
	 * override the newer allocation (highest-seq-wins violated). The
	 * pre-lock gate is kept as a cheap fast reject for replay floods. */
	{
		uint32_t cached_seq;
		int ret = lichen_slot_claim_seq_lookup(claim->gateway_iid,
						       &cached_seq);
		if (ret == 0 && claim->claim_seq <= cached_seq) {
			k_mutex_unlock(&s_coord_lock);
			LOG_DBG("Claim rejected: claim_seq replay (recheck)");
			return LICHEN_CLAIM_REJECT_REPLAY;
		}
	}

	/* Check for conflicts with existing allocations (step 9) */
	const struct lichen_gateway_alloc *winner = NULL;
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!ctx->gateways[i].valid) {
			continue;
		}

		/* Check for overlapping slots */
		for (uint8_t cs = 0; cs < claim->slot_count; cs++) {
			for (uint8_t gs = 0; gs < ctx->gateways[i].slot_count; gs++) {
				if (claim->slots[cs] == ctx->gateways[i].slots[gs]) {
					/* Conflict detected: compare IIDs */
					if (lichen_iid_compare(claim->gateway_iid,
							       ctx->gateways[i].iid) > 0) {
						/* Existing allocation has lower IID, reject */
						winner = &ctx->gateways[i];
						break;
					}
					/* Claim has lower IID, will override */
				}
			}
			if (winner != NULL) {
				break;
			}
		}
		if (winner != NULL) {
			break;
		}
	}

	if (winner != NULL) {
		if (conflict_cose != NULL && conflict_cose_len != NULL) {
			*conflict_cose = winner->last_claim_cose;
			*conflict_cose_len = winner->last_claim_cose_len;
		}
		k_mutex_unlock(&s_coord_lock);
		LOG_DBG("Claim rejected: conflict with lower IID");
		return LICHEN_CLAIM_REJECT_CONFLICT;
	}

	/* Persist the new claim_seq high-water BEFORE applying the claim
	 * (GCP-6.5 persist-first ordering) */
	if (lichen_slot_claim_seq_commit(claim->gateway_iid,
					 claim->claim_seq) != 0) {
		k_mutex_unlock(&s_coord_lock);
		LOG_WRN("Claim rejected: claim_seq persist failed");
		return LICHEN_CLAIM_REJECT_PERSIST;
	}

	/* Accept claim and update grant */
	memcpy(grant->granted_slots, claim->slots, claim->slot_count);
	grant->granted_count = claim->slot_count;
	grant->superframe_id = claim->superframe_id;
	grant->valid_until = claim->expiry;

	/* Register the gateway allocation */
	uint8_t gateway_count_before = ctx->gateway_count;

	lichen_slot_coord_register_gateway(ctx, claim->gateway_iid, claim->ordinal,
					   claim->slots, claim->slot_count,
					   claim->superframe_id);

	/* Store the accepted COSE_Sign1 for 4.09 Conflict payloads */
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (ctx->gateways[i].valid &&
		    memcmp(ctx->gateways[i].iid, claim->gateway_iid,
			   LICHEN_IID_LEN) == 0) {
			if (claim_store_cose(&ctx->gateways[i], claim) == 0) {
				/* Cannot happen for spec-conformant claims
				 * (bounded well below the 255-byte entry);
				 * refuse to apply an unrecordable claim */
				ctx->gateways[i].valid = false;
				ctx->gateway_count = gateway_count_before;
				k_mutex_unlock(&s_coord_lock);
				LOG_WRN("Claim rejected: COSE too large to record");
				return LICHEN_CLAIM_REJECT_INVALID_SLOTS;
			}
			break;
		}
	}

	k_mutex_unlock(&s_coord_lock);
	LOG_INF("Slot claim accepted");
	return LICHEN_CLAIM_ACCEPTED;
}

/* --------------------------------------------------------------------------
 * claim_seq high-water hooks (GCP-6.5 persistence)
 *
 * Weak defaults keep this child compilable without NV storage; the
 * settings-backed replay gate supersedes them. The hooks are process-wide
 * (keyed by gateway IID), not per lichen_slot_coord_ctx. The host test
 * build (LICHEN_SLOT_CLAIM_TEST) omits the defaults and supplies strong
 * definitions, so the gate logic is always exercised through real hooks.
 * -------------------------------------------------------------------------- */

#ifndef LICHEN_SLOT_CLAIM_TEST
__weak int lichen_slot_claim_seq_lookup(const uint8_t iid[LICHEN_IID_LEN],
					uint32_t *cached)
{
	(void)iid;
	(void)cached;
	return -ENOENT;
}

__weak int lichen_slot_claim_seq_commit(const uint8_t iid[LICHEN_IID_LEN],
					uint32_t seq)
{
	(void)iid;
	(void)seq;
	return 0;
}
#endif /* !LICHEN_SLOT_CLAIM_TEST */

int lichen_slot_coord_find_available(const struct lichen_slot_coord_ctx *ctx,
				     uint8_t slot_count, uint8_t *available_slots,
				     size_t max_slots)
{
	if (ctx == NULL || available_slots == NULL) {
		return -EINVAL;
	}

	/* Build a bitmap of occupied slots */
	uint64_t occupied = 0;

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!ctx->gateways[i].valid) {
			continue;
		}
		for (uint8_t s = 0; s < ctx->gateways[i].slot_count; s++) {
			if (ctx->gateways[i].slots[s] < 64) {
				occupied |= (1ULL << ctx->gateways[i].slots[s]);
			}
		}
	}

	k_mutex_unlock(&s_coord_lock);

	/* Find available slots */
	uint8_t found = 0;
	for (uint8_t s = 0; s < ctx->superframe.slots_per_superframe &&
			    found < slot_count && found < max_slots; s++) {
		if (s < 64 && !(occupied & (1ULL << s))) {
			available_slots[found++] = s;
		}
	}

	return found;
}

int lichen_slot_coord_register_gateway(struct lichen_slot_coord_ctx *ctx,
				       const uint8_t iid[LICHEN_IID_LEN],
				       uint8_t ordinal, const uint8_t *slots,
				       uint8_t slot_count, uint32_t superframe_id)
{
	if (ctx == NULL || iid == NULL || slots == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	/* Check if gateway already exists */
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (ctx->gateways[i].valid &&
		    memcmp(ctx->gateways[i].iid, iid, LICHEN_IID_LEN) == 0) {
			/* Update existing entry */
			ctx->gateways[i].ordinal = ordinal;
			memcpy(ctx->gateways[i].slots, slots, slot_count);
			ctx->gateways[i].slot_count = slot_count;
			ctx->gateways[i].superframe_id = superframe_id;
			k_mutex_unlock(&s_coord_lock);
			return 0;
		}
	}

	/* Find free slot */
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!ctx->gateways[i].valid) {
			memcpy(ctx->gateways[i].iid, iid, LICHEN_IID_LEN);
			ctx->gateways[i].ordinal = ordinal;
			memcpy(ctx->gateways[i].slots, slots, slot_count);
			ctx->gateways[i].slot_count = slot_count;
			ctx->gateways[i].superframe_id = superframe_id;
			ctx->gateways[i].valid = true;
			ctx->gateway_count++;
			k_mutex_unlock(&s_coord_lock);
			return 0;
		}
	}

	k_mutex_unlock(&s_coord_lock);
	return -ENOMEM;
}

/* --------------------------------------------------------------------------
 * CBOR encoding context
 * -------------------------------------------------------------------------- */

struct cbor_enc_ctx {
	uint8_t *buf;
	size_t off;
	size_t size;
	bool overflow;
};

static void cbor_enc_init(struct cbor_enc_ctx *e, uint8_t *buf, size_t size)
{
	e->buf = buf;
	e->off = 0;
	e->size = size;
	e->overflow = false;
}

static bool cbor_enc_check(struct cbor_enc_ctx *e, size_t n)
{
	if (e->overflow || e->off + n > e->size) {
		e->overflow = true;
		return false;
	}
	return true;
}

static void cbor_enc_uint(struct cbor_enc_ctx *e, uint8_t major, uint64_t val)
{
	if (val < 24) {
		if (!cbor_enc_check(e, 1)) return;
		e->buf[e->off++] = (uint8_t)((major << 5) | (uint8_t)val);
	} else if (val <= UINT8_MAX) {
		if (!cbor_enc_check(e, 2)) return;
		e->buf[e->off++] = (uint8_t)((major << 5) | 24);
		e->buf[e->off++] = (uint8_t)val;
	} else if (val <= UINT16_MAX) {
		if (!cbor_enc_check(e, 3)) return;
		e->buf[e->off++] = (uint8_t)((major << 5) | 25);
		e->buf[e->off++] = (uint8_t)(val >> 8);
		e->buf[e->off++] = (uint8_t)val;
	} else if (val <= UINT32_MAX) {
		if (!cbor_enc_check(e, 5)) return;
		e->buf[e->off++] = (uint8_t)((major << 5) | 26);
		e->buf[e->off++] = (uint8_t)(val >> 24);
		e->buf[e->off++] = (uint8_t)(val >> 16);
		e->buf[e->off++] = (uint8_t)(val >> 8);
		e->buf[e->off++] = (uint8_t)val;
	} else {
		if (!cbor_enc_check(e, 9)) return;
		e->buf[e->off++] = (uint8_t)((major << 5) | 27);
		e->buf[e->off++] = (uint8_t)(val >> 56);
		e->buf[e->off++] = (uint8_t)(val >> 48);
		e->buf[e->off++] = (uint8_t)(val >> 40);
		e->buf[e->off++] = (uint8_t)(val >> 32);
		e->buf[e->off++] = (uint8_t)(val >> 24);
		e->buf[e->off++] = (uint8_t)(val >> 16);
		e->buf[e->off++] = (uint8_t)(val >> 8);
		e->buf[e->off++] = (uint8_t)val;
	}
}

static void cbor_enc_bstr(struct cbor_enc_ctx *e, const uint8_t *data, size_t len)
{
	cbor_enc_uint(e, 2, len);
	if (!cbor_enc_check(e, len)) return;
	memcpy(&e->buf[e->off], data, len);
	e->off += len;
}

static void cbor_enc_tstr(struct cbor_enc_ctx *e, const char *str)
{
	size_t len = str ? strlen(str) : 0;
	cbor_enc_uint(e, 3, len);
	if (!cbor_enc_check(e, len)) return;
	memcpy(&e->buf[e->off], str, len);
	e->off += len;
}

static void cbor_enc_map_header(struct cbor_enc_ctx *e, size_t count)
{
	cbor_enc_uint(e, 5, count);
}

static void cbor_enc_array_header(struct cbor_enc_ctx *e, size_t count)
{
	cbor_enc_uint(e, 4, count);
}

/*
 * Build Sig_structure = ["Signature1", protected, h'', payload] (RFC 9052
 * Section 4.4) and digest it with SHA-256 per spec/08 GCP-6.5 (house
 * convention: capability_announcements.py,
 * test/vectors/generate_gcp_handoff_cose_sign1.py).
 */
static int claim_compute_digest(const uint8_t *payload, size_t payload_len,
				uint8_t digest[TC_SHA256_DIGEST_SIZE])
{
	uint8_t scratch[COSE_SIGN1_ELEMS + sizeof(cose_protected_alg) +
			CLAIM_PAYLOAD_MAX + 16];
	struct cbor_enc_ctx e;
	struct tc_sha256_state_struct sha;

	cbor_enc_init(&e, scratch, sizeof(scratch));
	cbor_enc_array_header(&e, COSE_SIGN1_ELEMS);
	cbor_enc_tstr(&e, "Signature1");
	cbor_enc_bstr(&e, cose_protected_alg, sizeof(cose_protected_alg));
	cbor_enc_bstr(&e, (const uint8_t *)"", 0);
	cbor_enc_bstr(&e, payload, payload_len);
	if (e.overflow) {
		return -ENOBUFS;
	}

	if (tc_sha256_init(&sha) != TC_CRYPTO_SUCCESS) {
		return -EIO;
	}
	if (tc_sha256_update(&sha, scratch, e.off) != TC_CRYPTO_SUCCESS) {
		return -EIO;
	}
	if (tc_sha256_final(digest, &sha) != TC_CRYPTO_SUCCESS) {
		return -EIO;
	}

	return 0;
}

/*
 * Rebuild the accepted COSE_Sign1 [protected, {4: kid}, payload, sig] into
 * the gateway entry for 4.09 Conflict payloads. Deterministic: the
 * protected header is the fixed alg map and the unprotected header carries
 * only the kid. Returns 0 if the entry buffer is too small.
 */
static size_t claim_store_cose(struct lichen_gateway_alloc *entry,
			       const struct lichen_slot_claim *claim)
{
	struct cbor_enc_ctx e;

	cbor_enc_init(&e, entry->last_claim_cose, sizeof(entry->last_claim_cose));
	cbor_enc_array_header(&e, COSE_SIGN1_ELEMS);
	cbor_enc_bstr(&e, cose_protected_alg, sizeof(cose_protected_alg));
	cbor_enc_map_header(&e, 1);
	cbor_enc_uint(&e, 0, COSE_KEY_KID);
	cbor_enc_bstr(&e, claim->gateway_iid, LICHEN_IID_LEN);
	cbor_enc_bstr(&e, claim->cose_payload, claim->cose_payload_len);
	cbor_enc_bstr(&e, claim->cose_signature, LICHEN_SCHNORR48_LEN);
	if (e.overflow) {
		return 0;
	}
	entry->last_claim_cose_len = (uint8_t)e.off;
	return e.off;
}

/* --------------------------------------------------------------------------
 * CBOR encoding
 * -------------------------------------------------------------------------- */

/*
 * Encode the spec/08 GCP-6.5 payload map: integer keys 1-7 in canonical
 * order. gateway_count and slot_start are sender-local bookkeeping and are
 * never emitted.
 */
static void claim_encode_payload(struct cbor_enc_ctx *e,
				 const struct lichen_slot_claim *claim)
{
	cbor_enc_map_header(e, CLAIM_KEY_COUNT);

	cbor_enc_uint(e, 0, CLAIM_KEY_SLOTS);
	cbor_enc_array_header(e, claim->slot_count);
	for (uint8_t i = 0; i < claim->slot_count; i++) {
		cbor_enc_uint(e, 0, claim->slots[i]);
	}

	cbor_enc_uint(e, 0, CLAIM_KEY_SUPERFRAME_EPOCH);
	cbor_enc_uint(e, 0, claim->superframe_id);

	cbor_enc_uint(e, 0, CLAIM_KEY_MODE);
	cbor_enc_uint(e, 0, claim->mode);

	cbor_enc_uint(e, 0, CLAIM_KEY_EXPIRY);
	cbor_enc_uint(e, 0, claim->expiry);

	cbor_enc_uint(e, 0, CLAIM_KEY_GATEWAY_IID);
	cbor_enc_bstr(e, claim->gateway_iid, LICHEN_IID_LEN);

	cbor_enc_uint(e, 0, CLAIM_KEY_CLAIM_SEQ);
	cbor_enc_uint(e, 0, claim->claim_seq);

	cbor_enc_uint(e, 0, CLAIM_KEY_ORDINAL);
	cbor_enc_uint(e, 0, claim->ordinal);
}

int lichen_slot_coord_encode_claim(const struct lichen_slot_claim *claim,
				   uint8_t *buf, size_t buf_len)
{
	if (claim == NULL || buf == NULL) {
		return -EINVAL;
	}

	struct cbor_enc_ctx e;
	cbor_enc_init(&e, buf, buf_len);

	claim_encode_payload(&e, claim);

	if (e.overflow) {
		return -ENOBUFS;
	}

	return (int)e.off;
}

int lichen_slot_coord_sign_claim(const uint8_t *privkey,
				 const uint8_t *pubkey,
				 const struct lichen_slot_claim *claim,
				 uint8_t *buf, size_t buf_len)
{
	if (privkey == NULL || pubkey == NULL || claim == NULL || buf == NULL) {
		return -EINVAL;
	}
#ifdef CONFIG_TINYCRYPT_SHA256
	/* Payload -> Sig_structure digest -> Schnorr48 signature */
	uint8_t payload[CLAIM_PAYLOAD_MAX];
	uint8_t digest[TC_SHA256_DIGEST_SIZE];
	uint8_t sig[LICHEN_SCHNORR48_LEN];
	struct cbor_enc_ctx p, e;
	int ret;

	cbor_enc_init(&p, payload, sizeof(payload));
	claim_encode_payload(&p, claim);
	if (p.overflow || p.off > CLAIM_PAYLOAD_MAX) {
		return -ENOBUFS;
	}

	ret = claim_compute_digest(payload, p.off, digest);
	if (ret < 0) {
		return ret;
	}

	ret = schnorr48_sign(privkey, pubkey, digest, TC_SHA256_DIGEST_SIZE, sig);
	if (ret < 0) {
		return ret;
	}

	/* COSE_Sign1 = [protected, {4: kid}, payload, sig] */
	cbor_enc_init(&e, buf, buf_len);
	cbor_enc_array_header(&e, COSE_SIGN1_ELEMS);
	cbor_enc_bstr(&e, cose_protected_alg, sizeof(cose_protected_alg));
	cbor_enc_map_header(&e, 1);
	cbor_enc_uint(&e, 0, COSE_KEY_KID);
	cbor_enc_bstr(&e, claim->gateway_iid, LICHEN_IID_LEN);
	cbor_enc_bstr(&e, payload, p.off);
	cbor_enc_bstr(&e, sig, LICHEN_SCHNORR48_LEN);
	if (e.overflow) {
		return -ENOBUFS;
	}

	return (int)e.off;
#else
#error "slot-coord requires TINYCRYPT_SHA256: claim digest must never be compiled out"
	return -EIO;
#endif
}

int lichen_slot_coord_encode_grant(const struct lichen_slot_grant *grant,
				   uint8_t *buf, size_t buf_len)
{
	if (grant == NULL || buf == NULL) {
		return -EINVAL;
	}

	struct cbor_enc_ctx e;
	cbor_enc_init(&e, buf, buf_len);

	cbor_enc_map_header(&e, 3);

	cbor_enc_tstr(&e, KEY_VALID_UNTIL);
	cbor_enc_uint(&e, 0, grant->valid_until);

	cbor_enc_tstr(&e, KEY_GRANTED_SLOTS);
	cbor_enc_array_header(&e, grant->granted_count);
	for (uint8_t i = 0; i < grant->granted_count; i++) {
		cbor_enc_uint(&e, 0, grant->granted_slots[i]);
	}

	cbor_enc_tstr(&e, KEY_SUPERFRAME_ID);
	cbor_enc_uint(&e, 0, grant->superframe_id);

	if (e.overflow) {
		return -ENOBUFS;
	}

	return (int)e.off;
}

/* --------------------------------------------------------------------------
 * CBOR decoding helpers
 * -------------------------------------------------------------------------- */

struct cbor_dec_ctx {
	const uint8_t *buf;
	size_t off;
	size_t size;
	bool error;
};

static void cbor_dec_init(struct cbor_dec_ctx *d, const uint8_t *buf, size_t size)
{
	d->buf = buf;
	d->off = 0;
	d->size = size;
	d->error = false;
}

static bool cbor_dec_check(struct cbor_dec_ctx *d, size_t n)
{
	if (d->error || d->off + n > d->size) {
		d->error = true;
		return false;
	}
	return true;
}

static uint64_t cbor_dec_uint_arg(struct cbor_dec_ctx *d, uint8_t info)
{
	if (info < 24) {
		return info;
	} else if (info == 24) {
		if (!cbor_dec_check(d, 1)) return 0;
		return d->buf[d->off++];
	} else if (info == 25) {
		if (!cbor_dec_check(d, 2)) return 0;
		uint64_t val = ((uint64_t)d->buf[d->off] << 8) | d->buf[d->off + 1];
		d->off += 2;
		return val;
	} else if (info == 26) {
		if (!cbor_dec_check(d, 4)) return 0;
		uint64_t val = ((uint64_t)d->buf[d->off] << 24) |
			       ((uint64_t)d->buf[d->off + 1] << 16) |
			       ((uint64_t)d->buf[d->off + 2] << 8) |
			       d->buf[d->off + 3];
		d->off += 4;
		return val;
	} else if (info == 27) {
		if (!cbor_dec_check(d, 8)) return 0;
		uint64_t val = ((uint64_t)d->buf[d->off] << 56) |
			       ((uint64_t)d->buf[d->off + 1] << 48) |
			       ((uint64_t)d->buf[d->off + 2] << 40) |
			       ((uint64_t)d->buf[d->off + 3] << 32) |
			       ((uint64_t)d->buf[d->off + 4] << 24) |
			       ((uint64_t)d->buf[d->off + 5] << 16) |
			       ((uint64_t)d->buf[d->off + 6] << 8) |
			       d->buf[d->off + 7];
		d->off += 8;
		return val;
	}
	d->error = true;
	return 0;
}

static uint64_t cbor_dec_uint(struct cbor_dec_ctx *d)
{
	if (!cbor_dec_check(d, 1)) return 0;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 0) {
		d->error = true;
		return 0;
	}
	return cbor_dec_uint_arg(d, info);
}

/* Zero-copy byte string view: on success *ptr and *len reference the
 * input buffer (valid while the input is unmodified). Returns true on
 * success. */
static bool cbor_dec_bstr_view(struct cbor_dec_ctx *d,
			       const uint8_t **ptr, size_t *len)
{
	if (!cbor_dec_check(d, 1)) return false;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 2) {
		d->error = true;
		return false;
	}

	uint64_t blen = cbor_dec_uint_arg(d, info);
	if (blen > d->size || !cbor_dec_check(d, blen)) {
		d->error = true;
		return false;
	}

	*ptr = &d->buf[d->off];
	*len = (size_t)blen;
	d->off += blen;
	return true;
}

static size_t cbor_dec_tstr(struct cbor_dec_ctx *d, char *out, size_t max_len)
{
	if (!cbor_dec_check(d, 1)) return 0;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 3) {
		d->error = true;
		return 0;
	}

	uint64_t len = cbor_dec_uint_arg(d, info);
	if (len >= max_len || !cbor_dec_check(d, len)) {
		d->error = true;
		return 0;
	}

	memcpy(out, &d->buf[d->off], len);
	out[len] = '\0';
	d->off += len;
	return (size_t)len;
}

static size_t cbor_dec_map_header(struct cbor_dec_ctx *d)
{
	if (!cbor_dec_check(d, 1)) return 0;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 5) {
		d->error = true;
		return 0;
	}
	return (size_t)cbor_dec_uint_arg(d, info);
}

static size_t cbor_dec_array_header(struct cbor_dec_ctx *d)
{
	if (!cbor_dec_check(d, 1)) return 0;
	uint8_t initial = d->buf[d->off++];
	uint8_t major = initial >> 5;
	uint8_t info = initial & 0x1f;

	if (major != 4) {
		d->error = true;
		return 0;
	}
	return (size_t)cbor_dec_uint_arg(d, info);
}

/* --------------------------------------------------------------------------
 * CBOR decoding
 * -------------------------------------------------------------------------- */

/* Decode a uint that must fit uint32; marks the context and returns false
 * on error or overflow. */
static bool claim_dec_u32(struct cbor_dec_ctx *d, uint32_t *out)
{
	uint64_t v = cbor_dec_uint(d);

	if (d->error || v > UINT32_MAX) {
		d->error = true;
		return false;
	}
	*out = (uint32_t)v;
	return true;
}

/* Decode a uint that must fit uint8. */
static bool claim_dec_u8(struct cbor_dec_ctx *d, uint8_t *out)
{
	uint64_t v = cbor_dec_uint(d);

	if (d->error || v > UINT8_MAX) {
		d->error = true;
		return false;
	}
	*out = (uint8_t)v;
	return true;
}

/*
 * Decode the payload map (integer keys 1-7). All keys are required; each
 * key, duplicate keys, and unknown keys are rejected. Requires all keys
 * present in claim_seen on return.
 */
static void claim_decode_payload(struct cbor_dec_ctx *d,
				 struct lichen_slot_claim *claim,
				 uint8_t *claim_seen)
{
	size_t map_count = cbor_dec_map_header(d);
	if (map_count == 0 || map_count > CLAIM_KEY_COUNT) {
		d->error = true;
		return;
	}

	for (size_t i = 0; i < map_count && !d->error; i++) {
		uint64_t key = cbor_dec_uint(d);
		if (d->error || key == 0 || key > CLAIM_KEY_COUNT ||
		    (*claim_seen & (uint8_t)(1U << key)) != 0) {
			d->error = true;
			break;
		}
		*claim_seen |= (uint8_t)(1U << key);

		switch (key) {
		case CLAIM_KEY_SLOTS: {
			size_t arr_len = cbor_dec_array_header(d);
			if (arr_len == 0 ||
			    arr_len > CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS) {
				d->error = true;
				break;
			}
			for (size_t j = 0; j < arr_len; j++) {
				if (!claim_dec_u8(d, &claim->slots[j])) {
					break;
				}
			}
			if (!d->error) {
				claim->slot_count = (uint8_t)arr_len;
			}
			break;
		}
		case CLAIM_KEY_SUPERFRAME_EPOCH:
			(void)claim_dec_u32(d, &claim->superframe_id);
			break;
		case CLAIM_KEY_MODE: {
			uint8_t mode;

			if (claim_dec_u8(d, &mode) && mode > 1) {
				d->error = true;
				break;
			}
			claim->mode = mode;
			break;
		}
		case CLAIM_KEY_EXPIRY:
			(void)claim_dec_u32(d, &claim->expiry);
			break;
		case CLAIM_KEY_GATEWAY_IID: {
			const uint8_t *iid;
			size_t iid_len;
			if (!cbor_dec_bstr_view(d, &iid, &iid_len) ||
			    iid_len != LICHEN_IID_LEN) {
				d->error = true;
				break;
			}
			memcpy(claim->gateway_iid, iid, LICHEN_IID_LEN);
			break;
		}
		case CLAIM_KEY_CLAIM_SEQ:
			(void)claim_dec_u32(d, &claim->claim_seq);
			break;
		case CLAIM_KEY_ORDINAL:
			(void)claim_dec_u8(d, &claim->ordinal);
			break;
		default:
			d->error = true;
			break;
		}
	}
}

int lichen_slot_coord_decode_claim(const uint8_t *buf, size_t buf_len,
				   struct lichen_slot_claim *claim)
{
	if (buf == NULL || claim == NULL) {
		return -EINVAL;
	}

	memset(claim, 0, sizeof(*claim));

	struct cbor_dec_ctx d;
	cbor_dec_init(&d, buf, buf_len);

	/* COSE_Sign1 = [protected bstr, unprotected map, payload bstr, sig] */
	size_t arr_len = cbor_dec_array_header(&d);
	if (d.error || arr_len != COSE_SIGN1_ELEMS) {
		return -EBADMSG;
	}

	/* Element 1: protected header MUST byte-equal the canonical
	 * {1: -65537}; the -65536 decoy (a1 01 39 ff ff) is rejected */
	const uint8_t *protected_bytes;
	size_t protected_len;
	if (!cbor_dec_bstr_view(&d, &protected_bytes, &protected_len) ||
	    protected_len != sizeof(cose_protected_alg) ||
	    memcmp(protected_bytes, cose_protected_alg,
		   sizeof(cose_protected_alg)) != 0) {
		return -EBADMSG;
	}

	/* Element 2: unprotected header, kid only (COSE key 4, 8-byte IID) */
	size_t u_count = cbor_dec_map_header(&d);
	if (d.error || u_count != 1) {
		return -EBADMSG;
	}
	uint64_t u_key = cbor_dec_uint(&d);
	if (d.error || u_key != COSE_KEY_KID) {
		return -EBADMSG;
	}
	const uint8_t *kid;
	size_t kid_len;
	if (!cbor_dec_bstr_view(&d, &kid, &kid_len) ||
	    kid_len != LICHEN_IID_LEN) {
		return -EBADMSG;
	}

	/* Element 3: signed payload bytes (view into buf, kept for verify) */
	if (!cbor_dec_bstr_view(&d, &claim->cose_payload,
				&claim->cose_payload_len) ||
	    claim->cose_payload_len == 0 ||
	    claim->cose_payload_len > CLAIM_PAYLOAD_MAX) {
		return -EBADMSG;
	}

	/* Element 4: signature, exactly LICHEN_SCHNORR48_LEN bytes */
	if (!cbor_dec_bstr_view(&d, &claim->cose_signature, &kid_len) ||
	    kid_len != LICHEN_SCHNORR48_LEN) {
		return -EBADMSG;
	}

	/* No trailing data */
	if (d.off != d.size) {
		return -EBADMSG;
	}

	/* Payload map: keys 1-7, all required, none duplicated */
	uint8_t claim_seen = 0;
	struct cbor_dec_ctx pd;
	cbor_dec_init(&pd, claim->cose_payload, claim->cose_payload_len);
	claim_decode_payload(&pd, claim, &claim_seen);
	if (pd.error || pd.off != pd.size ||
	    claim_seen != (uint8_t)((1U << (CLAIM_KEY_COUNT + 1)) - 2)) {
		return -EBADMSG;
	}

	/* kid MUST equal the payload gateway_iid (spec/08 step 6) */
	if (memcmp(kid, claim->gateway_iid, LICHEN_IID_LEN) != 0) {
		return -EBADMSG;
	}

	return 0;
}

int lichen_slot_coord_decode_grant(const uint8_t *buf, size_t buf_len,
				   struct lichen_slot_grant *grant)
{
	if (buf == NULL || grant == NULL) {
		return -EINVAL;
	}

	memset(grant, 0, sizeof(*grant));

	struct cbor_dec_ctx d;
	cbor_dec_init(&d, buf, buf_len);

	size_t map_count = cbor_dec_map_header(&d);
	if (d.error) {
		return -EBADMSG;
	}

	char key[32];
	for (size_t i = 0; i < map_count && !d.error; i++) {
		cbor_dec_tstr(&d, key, sizeof(key));
		if (d.error) break;

		if (strcmp(key, KEY_GRANTED_SLOTS) == 0) {
			size_t arr_len = cbor_dec_array_header(&d);
			if (arr_len > CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS) {
				d.error = true;
				break;
			}
			for (size_t j = 0; j < arr_len; j++) {
				grant->granted_slots[j] = (uint8_t)cbor_dec_uint(&d);
			}
			grant->granted_count = (uint8_t)arr_len;
		} else if (strcmp(key, KEY_SUPERFRAME_ID) == 0) {
			grant->superframe_id = (uint32_t)cbor_dec_uint(&d);
		} else if (strcmp(key, KEY_VALID_UNTIL) == 0) {
			grant->valid_until = cbor_dec_uint(&d);
		} else {
			d.error = true;
		}
	}

	if (d.error) {
		return -EBADMSG;
	}

	return 0;
}

/* --------------------------------------------------------------------------
 * CoAP resource handlers
 * -------------------------------------------------------------------------- */

#ifdef CONFIG_LICHEN_COAP_SLOT_COORD_RESOURCE

static int slots_get(struct coap_resource *resource,
		     struct coap_packet *request,
		     struct sockaddr *addr, socklen_t addr_len)
{
	static uint8_t resp_buf[256];
	struct cbor_enc_ctx e;
	cbor_enc_init(&e, resp_buf, sizeof(resp_buf));

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	/* Build allocation map response */
	cbor_enc_map_header(&e, 4);

	cbor_enc_tstr(&e, KEY_ALLOCATION_MODE);
	cbor_enc_tstr(&e, s_ctx.alloc_mode == LICHEN_SLOT_ALLOC_INTERLEAVED ?
			  "interleaved" : "contiguous");

	cbor_enc_tstr(&e, KEY_GATEWAY_COUNT);
	cbor_enc_uint(&e, 0, s_ctx.gateway_count);

	cbor_enc_tstr(&e, KEY_SUPERFRAME_ID);
	cbor_enc_uint(&e, 0, s_ctx.superframe.current_superframe_id);

	cbor_enc_tstr(&e, KEY_ALLOCATIONS);
	/* Count valid gateways */
	uint8_t valid_count = 0;
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (s_ctx.gateways[i].valid) valid_count++;
	}
	cbor_enc_map_header(&e, valid_count);

	/* Encode each gateway's slots keyed by IID hex string */
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!s_ctx.gateways[i].valid) continue;

		/* IID as hex string key */
		char iid_hex[17];
		for (int j = 0; j < LICHEN_IID_LEN; j++) {
			snprintf(&iid_hex[j*2], 3, "%02x", s_ctx.gateways[i].iid[j]);
		}
		cbor_enc_tstr(&e, iid_hex);

		/* Slots array */
		cbor_enc_array_header(&e, s_ctx.gateways[i].slot_count);
		for (uint8_t s = 0; s < s_ctx.gateways[i].slot_count; s++) {
			cbor_enc_uint(&e, 0, s_ctx.gateways[i].slots[s]);
		}
	}

	k_mutex_unlock(&s_coord_lock);

	if (e.overflow) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   CBOR_CONTENT_FORMAT, resp_buf, e.off);
}

static int slots_post(struct coap_resource *resource,
		      struct coap_packet *request,
		      struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_oscore_unprotect_result oscore;
	struct lichen_slot_claim claim;
	struct lichen_slot_grant grant;
	const uint8_t *payload;
	uint16_t payload_len;
	int ret;

	ret = coap_oscore_authorize_mutating(resource, request, addr,
					     addr_len, COAP_METHOD_POST,
					     &oscore);
	if (ret != 0) {
		return ret;
	}

	/* GCP-6.4: "All CoAP messages use OSCORE." Local-admin (LCI) callers
	 * are the only transport exception, per the house dispatch gate. */
	if (!oscore.is_protected &&
	    !lichen_coap_is_local_admin(addr, addr_len)) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_UNAUTHORIZED,
						    0, NULL, 0);
	}

	payload = oscore.payload;
	payload_len = oscore.payload_len;
	if (payload == NULL || payload_len == 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_BAD_REQUEST,
						    0, NULL, 0);
	}

	/* Decode claim (COSE_Sign1 per GCP-6.5). Malformed or structurally
	 * invalid claims are silently discarded per GCP-6.3, logged at a
	 * rate-limited WARN. */
	ret = lichen_slot_coord_decode_claim(payload, payload_len, &claim);
	if (ret < 0) {
		slot_coord_log_discard("decode failed");
		return 0;
	}

	/* Process claim: COSE verify, expiry, claim_seq, conflicts */
	const uint8_t *conflict_cose = NULL;
	size_t conflict_cose_len = 0;
	uint64_t now_unix = lichen_wall_clock_get();
	enum lichen_claim_result result = lichen_slot_coord_process_claim(
		&s_ctx, &claim, now_unix, lichen_wall_clock_valid(), &grant,
		&conflict_cose, &conflict_cose_len);

	if (result != LICHEN_CLAIM_ACCEPTED) {
		/* GCP-6.3: Claims with invalid or missing signatures MUST be
		 * silently discarded. Return 0 without responding. */
		if (result == LICHEN_CLAIM_REJECT_NO_SIG ||
		    result == LICHEN_CLAIM_REJECT_INVALID_SIG) {
			return 0;
		}
		/* spec/08 GCP-6.5: validation failures (invalid slots, expired,
		 * expiry too far, replay, persist) respond 4.03 Forbidden; only
		 * conflicts override to 4.09, with the winning gateway's
		 * claim as payload. */
		uint8_t code = COAP_RESPONSE_CODE_FORBIDDEN;
		uint8_t conflict_buf[LICHEN_SLOT_CLAIM_COSE_MAX];
		const uint8_t *resp_payload = NULL;
		uint16_t resp_len = 0;

		if (result == LICHEN_CLAIM_REJECT_CONFLICT &&
		    conflict_cose != NULL && conflict_cose_len > 0 &&
		    conflict_cose_len <= sizeof(conflict_buf)) {
			/* Snapshot the winner's stored claim under the coord
			 * lock: the pointer outlives process_claim's critical
			 * section but the entry can be concurrently updated.
			 * conflict_cose is the const uint8_t * out-parameter
			 * (process_claim wrote it through &conflict_cose), so
			 * memcpy uses the pointer directly, without deref; the
			 * bead 3yhv cleanup targeted the invalid *conflict_cose_len
			 * unary-* on a plain size_t, not this pointer. */
			code = COAP_RESPONSE_CODE_CONFLICT;
			k_mutex_lock(&s_coord_lock, K_FOREVER);
			memcpy(conflict_buf, conflict_cose, conflict_cose_len);
			k_mutex_unlock(&s_coord_lock);
			resp_payload = conflict_buf;
			resp_len = (uint16_t)conflict_cose_len;
		}
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    code, 0, resp_payload,
						    resp_len);
	}

	/* Encode grant response */
	static uint8_t resp_buf[128];
	ret = lichen_slot_coord_encode_grant(&grant, resp_buf, sizeof(resp_buf));
	if (ret < 0) {
		return coap_oscore_respond_resource(resource, request, addr,
						    addr_len, &oscore,
						    COAP_RESPONSE_CODE_INTERNAL_ERROR,
						    0, NULL, 0);
	}

	/* spec/08 GCP-6.5 step 10: accepted claims respond 2.04 Changed */
	return coap_oscore_respond_resource(resource, request, addr, addr_len,
					    &oscore, COAP_RESPONSE_CODE_CHANGED,
					    CBOR_CONTENT_FORMAT, resp_buf, ret);
}

static int info_get(struct coap_resource *resource,
		    struct coap_packet *request,
		    struct sockaddr *addr, socklen_t addr_len)
{
	static uint8_t resp_buf[256];
	struct cbor_enc_ctx e;
	cbor_enc_init(&e, resp_buf, sizeof(resp_buf));

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	cbor_enc_map_header(&e, 6);

	cbor_enc_tstr(&e, KEY_GATEWAY_IID);
	cbor_enc_bstr(&e, s_ctx.local_iid, LICHEN_IID_LEN);

	cbor_enc_tstr(&e, KEY_SLOTS_TOTAL);
	cbor_enc_uint(&e, 0, s_ctx.superframe.slots_per_superframe);

	cbor_enc_tstr(&e, KEY_TIME_SOURCE);
	const char *ts_str;
	switch (s_ctx.superframe.time_source) {
	case LICHEN_TIME_SOURCE_GPS:      ts_str = "gps"; break;
	case LICHEN_TIME_SOURCE_BACKBONE: ts_str = "backbone"; break;
	case LICHEN_TIME_SOURCE_LOCAL:    ts_str = "local"; break;
	default:                          ts_str = "none"; break;
	}
	cbor_enc_tstr(&e, ts_str);

	cbor_enc_tstr(&e, KEY_ALLOCATED_SLOTS);
	cbor_enc_array_header(&e, s_ctx.local_slot_count);
	for (uint8_t i = 0; i < s_ctx.local_slot_count; i++) {
		cbor_enc_uint(&e, 0, s_ctx.local_slots[i]);
	}

	cbor_enc_tstr(&e, KEY_SUPERFRAME_EPOCH);
	cbor_enc_uint(&e, 0, s_ctx.superframe.epoch_unix);

	cbor_enc_tstr(&e, KEY_SUPERFRAME_DURATION);
	cbor_enc_uint(&e, 0, s_ctx.superframe.duration_s);

	k_mutex_unlock(&s_coord_lock);

	if (e.overflow) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   CBOR_CONTENT_FORMAT, resp_buf, e.off);
}

static int channels_get(struct coap_resource *resource,
			struct coap_packet *request,
			struct sockaddr *addr, socklen_t addr_len)
{
	static uint8_t resp_buf[128];
	struct cbor_enc_ctx e;
	cbor_enc_init(&e, resp_buf, sizeof(resp_buf));

	k_mutex_lock(&s_coord_lock, K_FOREVER);

	/* Channel ownership map: channel_id (int) -> gateway IID (bstr) */
	uint8_t valid_count = 0;
	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (s_ctx.gateways[i].valid) valid_count++;
	}

	cbor_enc_map_header(&e, valid_count);

	for (int i = 0; i < CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS; i++) {
		if (!s_ctx.gateways[i].valid) continue;
		cbor_enc_uint(&e, 0, i); /* Channel ID = ordinal */
		cbor_enc_bstr(&e, s_ctx.gateways[i].iid, LICHEN_IID_LEN);
	}

	k_mutex_unlock(&s_coord_lock);

	if (e.overflow) {
		return lichen_coap_respond(resource, request, addr, addr_len,
					   COAP_RESPONSE_CODE_INTERNAL_ERROR,
					   0, NULL, 0);
	}

	return lichen_coap_respond(resource, request, addr, addr_len,
				   COAP_RESPONSE_CODE_CONTENT,
				   CBOR_CONTENT_FORMAT, resp_buf, e.off);
}

/* Path: /.well-known/lichen-gw/info */
static const char * const info_path[] = {
	".well-known", "lichen-gw", "info", NULL
};

static const char * const info_attrs[] = {
	"rt=\"gcp.info\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_gw_info, lichen_coap_server, {
	.get = info_get,
	.path = info_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = info_attrs,
	}),
});

/* Path: /.well-known/lichen-gw/slots */
static const char * const slots_path[] = {
	".well-known", "lichen-gw", "slots", NULL
};

static const char * const slots_attrs[] = {
	"rt=\"gcp.slots\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_gw_slots, lichen_coap_server, {
	.get = slots_get,
	.post = slots_post,
	.path = slots_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = slots_attrs,
	}),
});

/* Path: /.well-known/lichen-gw/channels */
static const char * const channels_path[] = {
	".well-known", "lichen-gw", "channels", NULL
};

static const char * const channels_attrs[] = {
	"rt=\"gcp.channels\"",
	"ct=\"60\"",
	NULL,
};

COAP_RESOURCE_DEFINE(lichen_gw_channels, lichen_coap_server, {
	.get = channels_get,
	.path = channels_path,
	.user_data = &((struct coap_core_metadata) {
		.attributes = channels_attrs,
	}),
});

#endif /* CONFIG_LICHEN_COAP_SLOT_COORD_RESOURCE */
