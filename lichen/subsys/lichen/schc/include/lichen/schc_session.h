/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/schc_session.h
 * @brief Authenticated SCHC fragmentation session authority: identity,
 *        key generation, and directional Rule-ID derivation.
 *
 * Foundation for spec/03-adaptation.md section 5.6. This module owns ONLY
 * the identity and direction primitives; it has no fragmentation state
 * machine. Higher slices (bounded tables, authenticated install, replay
 * counters, tombstones) build on these types.
 *
 * Authority rules (spec 5.6):
 * - A peer pair is identified by the two full 32-byte link-signing public
 *   keys. Endpoint A is the lexicographically smaller canonical key
 *   (unsigned octet compare); endpoint B is the larger. Equal keys do NOT
 *   identify a peer pair and MUST be rejected.
 * - Data fragments, ACK REQ, and Sender-Abort use Rule 0x78 when sent by A
 *   and Rule 0x79 when sent by B. ACK and Receiver-Abort travel in the
 *   reverse link direction but RETAIN the Rule ID of the data transfer they
 *   control.
 * - Direction MUST be derived from the authenticated full signer identities.
 *   An EUI-64, untrusted address, interface index, or caller-selected
 *   default Rule ID is never sufficient.
 */

#ifndef LICHEN_SCHC_SESSION_H_
#define LICHEN_SCHC_SESSION_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lichen/errno.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Full link-signing identity: 32-byte Ed25519 public key. */
#define LICHEN_SCHC_IDENTITY_LEN 32U

/** Directional fragmentation Rule IDs (spec 5.6). */
#define LICHEN_SCHC_RULE_A_TO_B 0x78U
#define LICHEN_SCHC_RULE_B_TO_A 0x79U

/**
 * @brief Opaque current key-generation token.
 *
 * Issued by the authority that owns the remote trust record. Opaque to this
 * module: only equality is meaningful. A generation change (revocation,
 * replacement, rotation) atomically retires every context, tombstone, cached
 * response, and admission floor issued under the retired token - even when
 * the same public key is reinstalled.
 */
typedef uint64_t lichen_schc_generation_t;

/**
 * @brief A full link-signing identity (local or remote).
 *
 * Wraps the raw 32-byte key so call sites cannot accidentally pass an
 * EUI-64, untrusted IPv6 address, or other non-identity byte string.
 */
struct lichen_schc_identity {
	uint8_t pubkey[LICHEN_SCHC_IDENTITY_LEN];
};

/**
 * @brief Canonical endpoint role within an authenticated peer pair.
 */
enum lichen_schc_endpoint {
	LICHEN_SCHC_ENDPOINT_A = 0, /**< Lexicographically smaller key. */
	LICHEN_SCHC_ENDPOINT_B = 1, /**< Lexicographically larger key. */
};

/**
 * @brief Class of a fragmentation-session control/data message.
 *
 * Determines which directional Rule ID a message carries (spec 5.6):
 * data-plane messages take the sender's directional Rule ID, while
 * control-plane ACK/Receiver-Abort retain the data transfer's Rule ID.
 */
enum lichen_schc_msg_class {
	LICHEN_SCHC_MSG_DATA = 0,     /**< Data fragment. */
	LICHEN_SCHC_MSG_ACK_REQ,      /**< ACK REQ (sender -> receiver). */
	LICHEN_SCHC_MSG_SENDER_ABORT, /**< Sender-Abort (sender -> receiver). */
	LICHEN_SCHC_MSG_ACK,          /**< ACK (receiver -> sender). */
	LICHEN_SCHC_MSG_RECEIVER_ABORT, /**< Receiver-Abort (receiver -> sender). */
};

/**
 * @brief Compare two identities as unsigned octet strings.
 *
 * NULL-tolerant: a NULL pointer compares less than any non-NULL identity and
 * two NULLs compare equal, giving a deterministic total order. Callers that
 * require non-NULL identities (e.g. lichen_schc_endpoint_role) validate that
 * separately before comparing.
 *
 * @param a First identity (may be NULL).
 * @param b Second identity (may be NULL).
 * @return <0 if a < b, 0 if equal, >0 if a > b (lexicographic, MSB first).
 */
int lichen_schc_identity_cmp(const struct lichen_schc_identity *a,
			     const struct lichen_schc_identity *b);

/**
 * @brief Determine the local endpoint's canonical role in a peer pair.
 *
 * Endpoint A is the endpoint whose canonical 32-byte key is lexicographically
 * smaller; B is the larger. Equal keys do not identify a peer pair.
 *
 * @param local  Local full signer identity (must not be NULL).
 * @param remote Remote full signer identity (must not be NULL).
 * @param[out] role Local endpoint's role (must not be NULL).
 * @return 0 on success, -EINVAL if any arg is NULL or the keys are equal.
 */
int lichen_schc_endpoint_role(const struct lichen_schc_identity *local,
			      const struct lichen_schc_identity *remote,
			      enum lichen_schc_endpoint *role);

/**
 * @brief Derive the directional Rule ID for a message.
 *
 * Data-plane messages (data, ACK REQ, Sender-Abort) use the sender's
 * directional Rule ID: 0x78 if the data sender is endpoint A, 0x79 if B.
 * Control-plane messages (ACK, Receiver-Abort) travel in the reverse link
 * direction but RETAIN the data transfer's Rule ID, so they use the data
 * sender's directional Rule ID, not the control sender's.
 *
 * @param data_sender_role Role of the endpoint that sent (or will send) the
 *                         data transfer this message belongs to.
 * @param cls              Message class.
 * @param[out] rule_id     Derived directional Rule ID (must not be NULL).
 * @return 0 on success, -EINVAL on NULL rule_id, out-of-range role, or
 *         out-of-range class.
 */
int lichen_schc_directional_rule(enum lichen_schc_endpoint data_sender_role,
				 enum lichen_schc_msg_class cls,
				 uint8_t *rule_id);

/**
 * @brief Validate that a received Rule ID matches the expected direction.
 *
 * Rejects equal/mismatched directions: a fragment arriving with a Rule ID
 * that does not equal the authenticated direction derived from the full
 * signer identities MUST be rejected before any decoder or state mutation.
 *
 * @param data_sender_role Authenticated role of the data sender.
 * @param cls              Message class being validated.
 * @param rule_id          Received Rule ID.
 * @return true iff rule_id equals the derived directional Rule ID.
 */
bool lichen_schc_direction_valid(enum lichen_schc_endpoint data_sender_role,
				 enum lichen_schc_msg_class cls,
				 uint8_t rule_id);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SCHC_SESSION_H_ */
