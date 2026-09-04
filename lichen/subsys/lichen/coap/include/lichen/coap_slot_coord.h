/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/coap_slot_coord.h
 * @brief Slot Coordination protocol for multi-gateway coordination (GCP-6)
 *
 * Per spec section 08-gateway-coordination.md GCP-6, this implements:
 *
 * - 6.1 Superframe Synchronization: GPS epoch or time master election
 * - 6.2 Slot Allocation: Interleaved or contiguous block modes
 * - 6.3 Conflict Resolution: Lowest IID wins, signature validation
 * - 6.4 CoAP Resources: /info, /slots, /channels
 * - 6.5 Slot Claim COSE_Sign1: Schnorr48 over the full claim payload
 *
 * SECURITY: All slot-claim messages are COSE_Sign1 (alg -65537,
 * Schnorr48-Ed25519) covering the complete claim payload: slots,
 * superframe_epoch, mode, expiry, gateway_iid, claim_seq, and ordinal.
 * Claims with invalid or missing signatures MUST be silently discarded.
 */

#ifndef LICHEN_COAP_SLOT_COORD_H_
#define LICHEN_COAP_SLOT_COORD_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <lichen/compiler.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum gateways in a federation */
#ifndef CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS
#define CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS 8
#endif

/** Maximum claim_seq high-water entries (spec/08 GCP-6.5: MUST bound the
 *  claim_seq cache to 64 entries, LRU-evicting by last claim timestamp) */
#ifndef CONFIG_LICHEN_SLOT_CLAIM_SEQ_CACHE_MAX
#define CONFIG_LICHEN_SLOT_CLAIM_SEQ_CACHE_MAX 64
#endif

/** Maximum slots per superframe */
#ifndef CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS
#define CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS 60
#endif

/** Default superframe duration in seconds */
#define LICHEN_SUPERFRAME_DURATION_S 60

/** Superframe duration in seconds used for claim-duration math
 *  (Kconfig-overridable on Zephyr; defaults match
 *  LICHEN_SUPERFRAME_DURATION_S) */
#ifndef CONFIG_LICHEN_CCP_SUPERFRAME_SEC
#define CONFIG_LICHEN_CCP_SUPERFRAME_SEC LICHEN_SUPERFRAME_DURATION_S
#endif

/** Maximum accepted slot-claim lifetime, in superframes (GCP-6.5
 *  validation step 7 upper bound; Kconfig-overridable on Zephyr) */
#ifndef CONFIG_LICHEN_SLOT_CLAIM_MAX_DURATION_SUPERFRAMES
#define CONFIG_LICHEN_SLOT_CLAIM_MAX_DURATION_SUPERFRAMES 5
#endif

/** Maximum accepted slot-claim lifetime in seconds: a claim whose expiry
 *  exceeds now + this is rejected (LICHEN_CLAIM_REJECT_EXPIRY_TOO_FAR) */
#define LICHEN_SLOT_CLAIM_MAX_DURATION_SEC \
	(CONFIG_LICHEN_CCP_SUPERFRAME_SEC * \
	 CONFIG_LICHEN_SLOT_CLAIM_MAX_DURATION_SUPERFRAMES)

/** Default slots per superframe */
#define LICHEN_SLOTS_PER_SUPERFRAME 60

/** Default slot duration in milliseconds */
#define LICHEN_SLOT_DURATION_MS 1000

/** IID length (8 bytes) */
#define LICHEN_IID_LEN 8

/** Schnorr48 signature length */
#define LICHEN_SCHNORR48_LEN 48

/** Maximum stored COSE_Sign1 slot-claim bytes per gateway entry (echoed in
 *  4.09 Conflict responses). A spec-conformant claim (60-slot cap) is ~230
 *  bytes, bounded by the 255-byte LoRa PHY payload. */
#ifndef LICHEN_SLOT_CLAIM_COSE_MAX
#define LICHEN_SLOT_CLAIM_COSE_MAX 255
#endif

/**
 * @brief Time source type for superframe synchronization
 */
enum lichen_time_source {
	/** No time source available */
	LICHEN_TIME_SOURCE_NONE = 0,
	/** GPS epoch (absolute time) */
	LICHEN_TIME_SOURCE_GPS = 1,
	/** Backbone-elected time master */
	LICHEN_TIME_SOURCE_BACKBONE = 2,
	/** Local RTC fallback */
	LICHEN_TIME_SOURCE_LOCAL = 3,
};

/**
 * @brief Slot allocation mode (GCP-6.2)
 */
enum lichen_slot_alloc_mode {
	/** Interleaved: Gateway N owns slots N, N+G, N+2G... where G=gateway_count */
	LICHEN_SLOT_ALLOC_INTERLEAVED = 0,
	/** Contiguous: Each gateway owns sequential block of slots */
	LICHEN_SLOT_ALLOC_CONTIGUOUS = 1,
};

/**
 * @brief Slot claim validation result
 */
enum lichen_claim_result {
	/** Claim accepted */
	LICHEN_CLAIM_ACCEPTED = 0,
	/** Claim struct carries no COSE verification material (not decoded
	 *  from a COSE_Sign1); nothing produces this after decode_claim */
	LICHEN_CLAIM_REJECT_NO_SIG = 1,
	/** Claim rejected: invalid signature or unknown signer */
	LICHEN_CLAIM_REJECT_INVALID_SIG = 2,
	/** Claim rejected: conflict with higher priority gateway */
	LICHEN_CLAIM_REJECT_CONFLICT = 3,
	/** Claim rejected: invalid slot range */
	LICHEN_CLAIM_REJECT_INVALID_SLOTS = 4,
	/** Claim rejected: expired (spec/08 GCP-6.5 validation step 7) */
	LICHEN_CLAIM_REJECT_EXPIRED = 5,
	/** Claim rejected: claim_seq not above cached high-water mark
	 *  (spec/08 GCP-6.5 validation step 8) */
	LICHEN_CLAIM_REJECT_REPLAY = 6,
	/** Claim rejected: claim_seq high-water persist failed; claim not
	 *  applied (spec/08 GCP-6.5: persist before apply) */
	LICHEN_CLAIM_REJECT_PERSIST = 7,
	/** Claim rejected: wall clock unsynced, so expiry (GCP-6.5 step 7)
	 *  cannot be evaluated; fail-closed, never accept without it */
	LICHEN_CLAIM_REJECT_NO_CLOCK = 8,
	/** Claim rejected: expiry beyond the superframe-denominated cap
	 *  (GCP-6.5 step 7 upper bound; spec/08 also numbers this check as
	 *  step 7a; anti-squatting). Both intents merged: the resolved
	 *  implementation (coap_slot_coord.c) calls this the step 7 upper
	 *  bound, and the check itself is expiry - now exceeding
	 *  LICHEN_SLOT_CLAIM_MAX_DURATION_SEC. */
	LICHEN_CLAIM_REJECT_EXPIRY_TOO_FAR = 9,
};

/**
 * @brief Gateway slot allocation entry
 */
struct lichen_gateway_alloc {
	uint8_t iid[LICHEN_IID_LEN];     /**< Gateway IID (8 bytes big-endian) */
	uint8_t ordinal;                  /**< Gateway ordinal (0-indexed) */
	uint8_t slots[CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS]; /**< Assigned slots */
	uint8_t slot_count;               /**< Number of assigned slots */
	uint32_t superframe_id;           /**< Superframe ID when allocated */
	uint64_t valid_until;             /**< Unix timestamp of allocation expiry */
	uint8_t last_claim_cose[LICHEN_SLOT_CLAIM_COSE_MAX]; /**< Accepted COSE_Sign1, echoed in 4.09 */
	uint8_t last_claim_cose_len;      /**< Length of last_claim_cose */
	bool valid;                       /**< Entry is in use */
};

/**
 * @brief Slot claim message (POST /slots)
 *
 * Populated by lichen_slot_coord_decode_claim() from a spec/08 GCP-6.5
 * COSE_Sign1. The cose_* fields point into the decode input buffer and are
 * only valid while that buffer is unmodified (zero-copy verification
 * material).
 */
struct lichen_slot_claim {
	uint8_t gateway_iid[LICHEN_IID_LEN];  /**< Payload key 5 (== COSE kid) */
	uint8_t slots[CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS]; /**< Payload key 1 */
	uint8_t slot_count;                   /**< Length of slots[] */
	uint32_t superframe_id;               /**< Payload key 2: superframe_epoch */
	uint8_t gateway_count;                /**< Sender-local bookkeeping, not on wire */
	uint8_t ordinal;                      /**< Payload key 7 */
	uint8_t slot_start;                   /**< Sender-local bookkeeping, not on wire */
	uint8_t mode;                         /**< Payload key 3: 0=interleaved, 1=contiguous */
	uint32_t expiry;                      /**< Payload key 4: unix seconds */
	uint32_t claim_seq;                   /**< Payload key 6: monotonic sequence */
	const uint8_t *_Nullable cose_payload;     /**< Signed payload bytes (into decode input) */
	size_t cose_payload_len;                   /**< Length of cose_payload */
	const uint8_t *_Nullable cose_signature;   /**< 48-byte signature (into decode input) */
};

/**
 * @brief Slot grant response (2.04 Changed, GCP-6.5 step 10)
 */
struct lichen_slot_grant {
	uint8_t granted_slots[CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS];
	uint8_t granted_count;
	uint32_t superframe_id;
	uint64_t valid_until;
};

/**
 * @brief Superframe timing context
 */
struct lichen_superframe_ctx {
	enum lichen_time_source time_source;
	uint64_t epoch_unix;              /**< Superframe epoch (Unix seconds) */
	uint32_t duration_s;              /**< Superframe duration in seconds */
	uint32_t slots_per_superframe;
	uint32_t slot_duration_ms;
	uint32_t current_superframe_id;
	uint8_t time_master_iid[LICHEN_IID_LEN];
	bool synced;
};

/**
 * @brief Slot coordination context
 */
struct lichen_slot_coord_ctx {
	uint8_t local_iid[LICHEN_IID_LEN];
	struct lichen_superframe_ctx superframe;
	enum lichen_slot_alloc_mode alloc_mode;
	struct lichen_gateway_alloc gateways[CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS];
	uint8_t gateway_count;
	uint8_t local_ordinal;
	uint8_t local_slots[CONFIG_LICHEN_SLOT_COORD_MAX_SLOTS];
	uint8_t local_slot_count;
	bool initialized;
};

/**
 * @brief Initialize slot coordination subsystem.
 *
 * @param[out] ctx       Slot coordination context
 * @param[in]  local_iid Local gateway's IID (8 bytes)
 * @return 0 on success, negative error code on failure
 */
int lichen_slot_coord_init(struct lichen_slot_coord_ctx *_Nonnull ctx,
			   const uint8_t local_iid[_Nonnull LICHEN_IID_LEN]);

/**
 * @brief Compute superframe ID from Unix timestamp.
 *
 * Formula: superframe_id = unix_timestamp / superframe_duration_s
 *
 * @param[in] ctx       Slot coordination context
 * @param[in] unix_time Unix timestamp in seconds
 * @return Superframe ID
 */
uint32_t lichen_slot_coord_superframe_id(const struct lichen_slot_coord_ctx *_Nonnull ctx,
					 uint64_t unix_time);

/**
 * @brief Compute current slot within superframe.
 *
 * Formula: current_slot = (timestamp - superframe_start) % slots_per_superframe
 *
 * @param[in] ctx       Slot coordination context
 * @param[in] unix_time Unix timestamp in seconds
 * @return Current slot index (0 to slots_per_superframe-1)
 */
uint8_t lichen_slot_coord_current_slot(const struct lichen_slot_coord_ctx *_Nonnull ctx,
				       uint64_t unix_time);

/**
 * @brief Compare two IIDs as unsigned big-endian 64-bit integers.
 *
 * Per GCP-6.3: lowest IID wins in conflict resolution.
 *
 * @param[in] iid_a First IID (8 bytes)
 * @param[in] iid_b Second IID (8 bytes)
 * @return -1 if a < b, 0 if equal, +1 if a > b
 */
int lichen_iid_compare(const uint8_t iid_a[_Nonnull LICHEN_IID_LEN],
		       const uint8_t iid_b[_Nonnull LICHEN_IID_LEN]);

/**
 * @brief Elect time master from gateway candidates.
 *
 * Per GCP-6.1: lowest IID wins for non-GPS gateways.
 * GPS-equipped gateways are preferred.
 *
 * @param[in]  ctx        Slot coordination context
 * @param[out] master_iid Output IID of elected master
 * @return 0 on success, -ENOENT if no candidates
 */
int lichen_slot_coord_elect_time_master(struct lichen_slot_coord_ctx *_Nonnull ctx,
					uint8_t master_iid[_Nonnull LICHEN_IID_LEN]);

/**
 * @brief Compute interleaved slot allocation.
 *
 * Per GCP-6.2: Gateway with ordinal N owns slots N, N+G, N+2G...
 * where G = gateway_count.
 *
 * @param[in]  ordinal       Gateway ordinal (0-indexed)
 * @param[in]  gateway_count Total number of gateways
 * @param[in]  num_slots     Slots per superframe
 * @param[out] slots         Output slot array
 * @param[in]  max_slots     Maximum slots in output array
 * @return Number of slots assigned, or negative error
 */
int lichen_slot_coord_interleaved(uint8_t ordinal, uint8_t gateway_count,
				  uint8_t num_slots, uint8_t *_Nonnull slots,
				  size_t max_slots);

/**
 * @brief Compute contiguous block slot allocation.
 *
 * Per GCP-6.2: Each gateway owns sequential block of slots.
 *
 * @param[in]  ordinal       Gateway ordinal (0-indexed)
 * @param[in]  gateway_count Total number of gateways
 * @param[in]  num_slots     Slots per superframe
 * @param[out] slot_start    Output start slot
 * @param[out] slot_count    Output slot count
 * @return 0 on success, negative error
 */
int lichen_slot_coord_contiguous(uint8_t ordinal, uint8_t gateway_count,
				 uint8_t num_slots, uint8_t *_Nonnull slot_start,
				 uint8_t *_Nonnull slot_count);

/**
 * @brief Validate interleaved slot pattern.
 *
 * Checks: slots[i] == ordinal + i * gateway_count
 *
 * @param[in] slots         Slot array to validate
 * @param[in] slot_count    Number of slots
 * @param[in] ordinal       Expected ordinal
 * @param[in] gateway_count Expected gateway count
 * @return true if pattern is valid
 */
bool lichen_slot_coord_validate_interleaved(const uint8_t *_Nonnull slots,
					    uint8_t slot_count,
					    uint8_t ordinal,
					    uint8_t gateway_count);

/**
 * @brief Check if transmission is allowed in current slot.
 *
 * @param[in] ctx          Slot coordination context
 * @param[in] current_slot Current slot index
 * @return true if transmission allowed
 */
bool lichen_slot_coord_tx_allowed(const struct lichen_slot_coord_ctx *_Nonnull ctx,
				  uint8_t current_slot);

/**
 * @brief Process incoming slot claim.
 *
 * Per GCP-6.3 and GCP-6.5, in order:
 * - COSE_Sign1 verification against the signer's key-store entry
 * - expiry > now (step 7)
 * - expiry - now within the claim-duration cap now +
 *   LICHEN_SLOT_CLAIM_MAX_DURATION_SEC (step 7 upper bound; spec/08 also
 *   numbers this check as step 7a)
 * - claim_seq above the cached per-gateway high-water mark (step 8);
 *   on acceptance the new high-water is committed via
 *   lichen_slot_claim_seq_commit() BEFORE the claim is applied
 * - conflict resolution: lowest IID wins (step 9)
 *
 * Claims with invalid signatures or unknown signers MUST be silently
 * discarded by the caller (LICHEN_CLAIM_REJECT_NO_SIG /
 * LICHEN_CLAIM_REJECT_INVALID_SIG).
 *
 * @param[in]  ctx       Slot coordination context
 * @param[in]  claim     Incoming slot claim (decoded)
 * @param[in]  now_unix  Current unix time in seconds (expiry gate, step 7)
 * @param[out] grant     Output grant response (if accepted)
 * @param[out] conflict_cose  Optional; on LICHEN_CLAIM_REJECT_CONFLICT set
 *               to the winning gateway's stored COSE_Sign1 (4.09 payload).
 *               May be NULL. Valid until the next claim is processed.
 * @param[out] conflict_cose_len  Optional; length of *conflict_cose. May be NULL.
 * @return Claim result code
 */
enum lichen_claim_result lichen_slot_coord_process_claim(
	struct lichen_slot_coord_ctx *_Nonnull ctx,
	const struct lichen_slot_claim *_Nonnull claim,
	uint64_t now_unix,
	bool clock_valid,
	struct lichen_slot_grant *_Nonnull grant,
	const uint8_t *_Nullable *_Nullable conflict_cose,
	size_t *_Nullable conflict_cose_len);

/**
 * @brief Resolve slot conflict between two claims.
 *
 * Per GCP-6.3: If both signatures verify, lowest IID wins.
 * If one signature fails, valid claim wins regardless of IID.
 *
 * @param[in] claim_a First claim
 * @param[in] sig_a_valid True if claim_a signature verified
 * @param[in] claim_b Second claim
 * @param[in] sig_b_valid True if claim_b signature verified
 * @return Pointer to winning claim, or NULL if both invalid
 */
const struct lichen_slot_claim *_Nullable lichen_slot_coord_resolve_conflict(
	const struct lichen_slot_claim *_Nonnull claim_a, bool sig_a_valid,
	const struct lichen_slot_claim *_Nonnull claim_b, bool sig_b_valid);

/**
 * @brief Find next available slots after conflict.
 *
 * Per GCP-6.3: Loser MUST select next available slot.
 *
 * @param[in]  ctx             Slot coordination context
 * @param[in]  slot_count      Number of slots needed
 * @param[out] available_slots Output available slot array
 * @param[in]  max_slots       Maximum slots in output array
 * @return Number of available slots found, or negative error
 */
int lichen_slot_coord_find_available(const struct lichen_slot_coord_ctx *_Nonnull ctx,
				     uint8_t slot_count, uint8_t *_Nonnull available_slots,
				     size_t max_slots);

/**
 * @brief Register a gateway in the slot allocation table.
 *
 * @param[in] ctx         Slot coordination context
 * @param[in] iid         Gateway IID
 * @param[in] ordinal     Gateway ordinal
 * @param[in] slots       Assigned slots
 * @param[in] slot_count  Number of slots
 * @param[in] superframe_id Superframe when allocated
 * @return 0 on success, -ENOMEM if table full
 */
int lichen_slot_coord_register_gateway(struct lichen_slot_coord_ctx *_Nonnull ctx,
				       const uint8_t iid[_Nonnull LICHEN_IID_LEN],
				       uint8_t ordinal, const uint8_t *_Nonnull slots,
				       uint8_t slot_count, uint32_t superframe_id);

/**
 * @brief Encode slot claim payload to canonical CBOR.
 *
 * Emits the spec/08 GCP-6.5 payload map (integer keys 1-7): slots,
 * superframe_epoch, mode, expiry, gateway_iid, claim_seq, ordinal.
 * This is the unsigned COSE_Sign1 payload, not the full envelope; the
 * gateway's own signed claims are produced by
 * lichen_slot_coord_sign_claim().
 *
 * @param[in]  claim   Slot claim to encode
 * @param[out] buf     Output buffer
 * @param[in]  buf_len Buffer size
 * @return Bytes written, or negative error code
 */
int lichen_slot_coord_encode_claim(const struct lichen_slot_claim *_Nonnull claim,
				   uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Encode and sign a slot claim as a COSE_Sign1 (spec/08 GCP-6.5).
 *
 * Builds the canonical payload map, the RFC 9052 Sig_structure
 * ["Signature1", protected, h'', payload], and signs
 * SHA-256(CBOR(Sig_structure)) with Schnorr48. The protected header is the
 * canonical {1: -65537} (alg Schnorr48-Ed25519); the unprotected header is
 * {4: gateway_iid} (COSE kid).
 *
 * @param[in]  privkey  32-byte Ed25519 private key
 * @param[in]  pubkey   32-byte Ed25519 public key
 * @param[in]  claim    Slot claim to encode (gateway_iid becomes the kid)
 * @param[out] buf      Output buffer
 * @param[in]  buf_len  Buffer size (LICHEN_SLOT_CLAIM_COSE_MAX is sufficient)
 * @return Bytes written, or negative error code
 */
int lichen_slot_coord_sign_claim(const uint8_t *_Nonnull privkey,
				 const uint8_t *_Nonnull pubkey,
				 const struct lichen_slot_claim *_Nonnull claim,
				 uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Decode slot claim from a COSE_Sign1 (spec/08 GCP-6.5).
 *
 * Validates the COSE_Sign1 structure: exactly four elements, protected
 * header byte-equal to the canonical {1: -65537}, unprotected kid an 8-byte
 * bstr equal to the payload gateway_iid, signature exactly 48 bytes, and a
 * payload map carrying integer keys 1-7 (unknown, duplicate, or missing
 * keys are rejected). Populates claim->cose_payload/cose_signature with
 * pointers into buf for lichen_slot_coord_process_claim().
 *
 * @param[in]  buf     COSE_Sign1 payload
 * @param[in]  buf_len Payload length
 * @param[out] claim   Output claim
 * @return 0 on success, negative error code on failure
 */
int lichen_slot_coord_decode_claim(const uint8_t *_Nonnull buf, size_t buf_len,
				   struct lichen_slot_claim *_Nonnull claim);

/**
 * @brief Cached claim_seq high-water mark lookup for a gateway.
 *
 * Weak default returns -ENOENT (no cached entry). The NV-persisted
 * implementation supersedes this (spec/08 GCP-6.5 claim_seq persistence).
 *
 * @param[in]  iid    Gateway IID
 * @param[out] cached Cached high-water mark (valid when 0 is returned)
 * @return 0 if an entry exists, -ENOENT if none
 */
int lichen_slot_claim_seq_lookup(const uint8_t iid[_Nonnull LICHEN_IID_LEN],
				 uint32_t *_Nonnull cached);

/**
 * @brief Persist a new claim_seq high-water mark for a gateway.
 *
 * MUST be called before the claim is applied to the slot table
 * (spec/08 GCP-6.5 persist-first ordering). Weak default is a no-op;
 * the NV-persisted implementation supersedes this.
 *
 * @param[in] iid  Gateway IID
 * @param[in] seq  New high-water mark
 * @return 0 on success, negative error code on failure
 */
int lichen_slot_claim_seq_commit(const uint8_t iid[_Nonnull LICHEN_IID_LEN],
				 uint32_t seq);

/**
 * @brief Encode slot grant to CBOR.
 *
 * @param[in]  grant   Slot grant to encode
 * @param[out] buf     Output buffer
 * @param[in]  buf_len Buffer size
 * @return Bytes written, or negative error code
 */
int lichen_slot_coord_encode_grant(const struct lichen_slot_grant *_Nonnull grant,
				   uint8_t *_Nonnull buf, size_t buf_len);

/**
 * @brief Decode slot grant from CBOR.
 *
 * @param[in]  buf     CBOR payload
 * @param[in]  buf_len Payload length
 * @param[out] grant   Output grant
 * @return 0 on success, negative error code on failure
 */
int lichen_slot_coord_decode_grant(const uint8_t *_Nonnull buf, size_t buf_len,
				   struct lichen_slot_grant *_Nonnull grant);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_COAP_SLOT_COORD_H_ */
