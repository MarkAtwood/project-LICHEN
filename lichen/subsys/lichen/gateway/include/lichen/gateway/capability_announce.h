/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_GATEWAY_CAPABILITY_ANNOUNCE_H_
#define LICHEN_GATEWAY_CAPABILITY_ANNOUNCE_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LICHEN_CAPABILITY_ANNOUNCE_MAX_WIRE_SIZE 160U
#define LICHEN_CAPABILITY_ANNOUNCE_ALG (-65537)
/* Capability bits 2-7 are reserved and MUST be zero (spec 8.12). */
#define LICHEN_CAPABILITY_RESERVED_MASK 0xFCU
/* spec 8.12: bit 0 = egress, bit 1 = prefix-delegation. */
#define LICHEN_CAPABILITY_EGRESS 0x01U

enum lichen_capability_denial {
	LICHEN_CAPABILITY_DENIAL_NONE,
	LICHEN_CAPABILITY_DENIAL_MALFORMED,
	LICHEN_CAPABILITY_DENIAL_ALGORITHM,
	LICHEN_CAPABILITY_DENIAL_KID_MISMATCH,
	LICHEN_CAPABILITY_DENIAL_RESERVED_BITS,
	LICHEN_CAPABILITY_DENIAL_IID_MISMATCH,
	LICHEN_CAPABILITY_DENIAL_SIGNATURE,
	LICHEN_CAPABILITY_DENIAL_EXPIRED,
	LICHEN_CAPABILITY_DENIAL_REPLAY,
};

struct lichen_capability_crypto {
	int (*sha256)(const uint8_t *input, size_t input_len, uint8_t out[32]);
	int (*derive_iid)(const uint8_t pubkey[32], uint8_t iid[8]);
	bool (*verify)(const uint8_t public_key[32], const uint8_t digest[32],
		       const uint8_t signature[48]);
};

struct lichen_capability_payload {
	uint32_t capabilities;
	uint8_t prefix[16];
	uint8_t prefix_len;
	uint64_t expiry;
	uint64_t seq;
	uint8_t announcer_iid[8];
};

/* Decoded COSE_Sign1 announcement.  payload_bytes points into the caller's
 * input buffer and stays valid only while that buffer is unmodified: the
 * signature transcript covers the payload exactly as carried on the wire,
 * never a re-encoding. */
struct lichen_capability_announcement {
	uint8_t protected_header[7];
	const uint8_t *payload_bytes;
	size_t payload_len;
	uint8_t signature[48];
	struct lichen_capability_payload payload;
};

struct lichen_capability_result {
	bool valid;
	enum lichen_capability_denial denial;
};

/* Capability table (spec 8.12): a bounded LRU cache of accepted capability
 * announcements, keyed by announcer IID.  Mirrors the Python
 * CapabilityTable (python/.../resources/capability_announce.py) and Rust
 * CapabilityTable (rust/lichen-gateway/src/capability.rs): 256 entries, 25%
 * of capacity reserved for egress-bit announcements, strict LRU eviction,
 * and a monotone per-IID seq floor captured at eviction so an evicted
 * announcer cannot replay an older still-valid announcement to roll the
 * table back. */

#ifndef CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY
#define CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY 256U
#endif

/* Non-egress announcements may use all but the reserved egress tail. */
#define LICHEN_CAPABILITY_EGRESS_RESERVED (CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY / 4U)

struct lichen_capability_table_entry {
	bool used;
	uint8_t announcer_iid[8];
	uint32_t capabilities;
	uint64_t expiry;
	uint64_t seq;
	uint64_t last_used;
};

/* Monotone anti-replay floor captured when an entry is LRU-evicted. */
struct lichen_capability_seq_floor {
	bool used;
	uint8_t announcer_iid[8];
	uint64_t floor;
};

struct lichen_capability_table {
	struct lichen_capability_table_entry entries[CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY];
	struct lichen_capability_seq_floor floors[CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY];
	size_t entry_count;
	uint64_t tick;
	atomic_flag lock;
};

/* Initialize an empty table. */
void lichen_capability_table_init(struct lichen_capability_table *table);

/* Highest accepted seq for an announcer (max of the live entry and the
 * eviction-captured floor), or -1 when the announcer is unknown.  Touches
 * the entry's LRU position on a hit. */
int64_t lichen_capability_table_cached_seq(struct lichen_capability_table *table,
					   const uint8_t announcer_iid[8]);

/* Accept one verified announcement.  Returns false when a non-egress insert
 * would consume the reserved egress tail (table full for that class). */
bool lichen_capability_table_record(struct lichen_capability_table *table,
				    const struct lichen_capability_payload *payload);

/* Drop expired entries; returns the number purged. */
size_t lichen_capability_table_purge_expired(struct lichen_capability_table *table,
					     uint64_t now);

/* Strict untagged COSE_Sign1 decode: [protected bstr {1: -65537},
 * unprotected {4: kid(8)}, payload bstr, signature bstr(48)].  A CBOR tag 18
 * wrapper is malformed.  kid != payload announcer_iid is rejected here with
 * LICHEN_CAPABILITY_DENIAL_KID_MISMATCH (mirrors python from_cose_sign1). */
bool lichen_capability_announce_decode(const uint8_t *body, size_t body_len,
				       struct lichen_capability_announcement *out,
				       enum lichen_capability_denial *why);

/* Validation ordering mirrors python verify_capability_announcement and
 * rust verify_announcement: reserved bits zero -> announcer_iid matches the
 * IID derived from the pinned pubkey -> Schnorr48 signature over
 * SHA-256(Sig_structure) -> expiry > now -> seq > *cached_seq (strict; the
 * cache lives in the caller's capability table, NULL skips the check).  All
 * steps are deny-only, so the cheap-checks-first order is security-
 * equivalent to any other ordering. */
struct lichen_capability_result lichen_capability_announce_verify(
	const struct lichen_capability_crypto *crypto,
	const struct lichen_capability_announcement *announcement,
	const uint8_t announcer_pubkey[32], uint64_t now,
	const uint64_t *cached_seq);

/* Zephyr defaults: tinycrypt SHA-256 + lichen_key_pubkey_to_iid.  Returns
 * -ENOTSUP on non-Zephyr hosts; inject a crypto struct there instead. */
int lichen_capability_announce_default_crypto(struct lichen_capability_crypto *crypto);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_GATEWAY_CAPABILITY_ANNOUNCE_H_ */
