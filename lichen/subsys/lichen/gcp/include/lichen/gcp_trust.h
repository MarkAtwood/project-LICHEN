/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/gcp_trust.h
 * @brief GCP-3 Trust Models per spec/08-gateway-coordination.md
 *
 * Implements dual-mode federation support:
 * - Closed federation: PSK-based OSCORE context derivation
 * - Open federation: Ed25519 signatures with TOFU key pinning
 *
 * Trust levels ordered by verification strength:
 *   TOFU < BR_PROVISIONED < DANE < PKIX
 *
 * Test vectors: test/vectors/gcp3_trust_models.json
 * Python oracle: python/src/lichen/crypto/trust.py
 */

#ifndef LICHEN_GCP_TRUST_H_
#define LICHEN_GCP_TRUST_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

/* Nullability annotations */
#ifndef __has_feature
#define __has_feature(x) 0
#endif
#if !defined(__clang__) || !__has_feature(nullability)
#ifndef _Nonnull
#define _Nonnull
#endif
#ifndef _Nullable
#define _Nullable
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/** Ed25519 public key length */
#define GCP_TRUST_PUBKEY_LEN 32

/** Interface Identifier length */
#define GCP_TRUST_IID_LEN 8

/** Yggdrasil 02xx address length */
#define GCP_TRUST_YGG_ADDR_LEN 16

/** Schnorr-48 signature length */
#define GCP_TRUST_SIG_LEN 48

/** Maximum control message length (DoS protection) */
#define GCP_TRUST_MAX_CONTROL_MSG_LEN 256

/** Domain prefix for slot claim messages */
#define GCP_TRUST_SLOT_CLAIM_PREFIX "SLOT_CLAIM:"
#define GCP_TRUST_SLOT_CLAIM_PREFIX_LEN 11

/** Domain prefix for key rotation messages (Python oracle uses this format) */
#define GCP_TRUST_KEY_ROTATE_PREFIX "LICHEN-KEY-ROTATION-v1"
#define GCP_TRUST_KEY_ROTATE_PREFIX_LEN 22

/**
 * @brief Trust level enumeration per GCP-3.2.
 *
 * Values ordered by verification strength (lower = weaker verification).
 * Implementations may upgrade trust level but never downgrade.
 */
typedef enum {
    /** Trust-on-first-use: key pinned on first contact */
    GCP_TRUST_LEVEL_TOFU = 1,
    /** Key provisioned by border router administrator */
    GCP_TRUST_LEVEL_BR_PROVISIONED = 2,
    /** Key verified via DANE (DNS-based) */
    GCP_TRUST_LEVEL_DANE = 3,
    /** Key verified via X.509 PKI chain */
    GCP_TRUST_LEVEL_PKIX = 4
} gcp_trust_level_t;

/**
 * @brief Result of TOFU first-contact verification.
 */
typedef enum {
    /** Pubkey correctly derives to claimed IID; pin and accept */
    GCP_TOFU_PIN_AND_ACCEPT,
    /** Pubkey does not derive to claimed IID; reject (possible attack) */
    GCP_TOFU_REJECT_DERIVATION_MISMATCH
} gcp_tofu_result_t;

/**
 * @brief Result of key rotation verification.
 */
typedef enum {
    /** Old key validly signed the rotation; accept new key */
    GCP_ROTATION_ACCEPT,
    /** Signature verification failed; reject rotation */
    GCP_ROTATION_REJECT_INVALID_SIGNATURE,
    /** Replay attack: sequence number not strictly greater */
    GCP_ROTATION_REJECT_REPLAY
} gcp_rotation_result_t;

/**
 * @brief Result of slot claim verification.
 */
typedef enum {
    /** Signature verifies; accept the claim */
    GCP_SLOT_CLAIM_ACCEPT,
    /** Signature invalid or message malformed; reject claim */
    GCP_SLOT_CLAIM_REJECT_INVALID
} gcp_slot_claim_result_t;

/**
 * @brief Validate a DER certificate chain against one configured anchor.
 *
 * The leaf is followed through the supplied intermediates to the exact DER
 * trust anchor. Implementations MUST verify signatures and validity periods,
 * and MUST enforce leaf basicConstraints CA=false and digitalSignature key
 * usage. Issuer-DN equality alone is not authorization.
 *
 * @param[in] leaf_der       DER-encoded end-entity certificate
 * @param[in] leaf_len       Length of leaf_der
 * @param[in] chain_der      DER-encoded intermediate certificates, or NULL
 *                           when chain_count is zero
 * @param[in] chain_lens     Length of each intermediate, or NULL when
 *                           chain_count is zero
 * @param[in] chain_count    Number of intermediates
 * @param[in] anchor_der     DER-encoded configured trust anchor
 * @param[in] anchor_len     Length of anchor_der
 * @return 0 on success, -EINVAL for malformed/rejected input, or
 *         -ENOTSUP when X.509 support is disabled.
 */
#if defined(CONFIG_LICHEN_GCP_TRUST_X509)
int gcp_trust_validate_x509_chain(const uint8_t *_Nonnull leaf_der,
                                  size_t leaf_len,
                                  const uint8_t *const *_Nullable chain_der,
                                  const size_t *_Nullable chain_lens,
                                  size_t chain_count,
                                  const uint8_t *_Nonnull anchor_der,
                                  size_t anchor_len);
#else
static inline int gcp_trust_validate_x509_chain(
    const uint8_t *_Nonnull leaf_der, size_t leaf_len,
    const uint8_t *const *_Nullable chain_der,
    const size_t *_Nullable chain_lens, size_t chain_count,
    const uint8_t *_Nonnull anchor_der, size_t anchor_len)
{
    (void)leaf_der;
    (void)leaf_len;
    (void)chain_der;
    (void)chain_lens;
    (void)chain_count;
    (void)anchor_der;
    (void)anchor_len;
    return -ENOTSUP;
}
#endif

/**
 * @brief Derive IID from Ed25519 public key.
 *
 * IID = SHA-512(pubkey)[0:8] with U/L bit cleared (bit 1 of byte 0).
 * This is the cryptographic binding for TOFU verification.
 *
 * @param[in]  pubkey  32-byte Ed25519 public key
 * @param[out] iid     8-byte IID output
 */
void gcp_trust_derive_iid(const uint8_t *_Nonnull pubkey,
                          uint8_t *_Nonnull iid);

/**
 * @brief Derive Yggdrasil 02xx address from Ed25519 public key.
 *
 * 02xx = [0x02] || SHA-512(pubkey)[0:7] || IID
 * where IID = SHA-512(pubkey)[0:8] with U/L bit cleared.
 *
 * @param[in]  pubkey   32-byte Ed25519 public key
 * @param[out] ygg_addr 16-byte Yggdrasil address output
 */
void gcp_trust_derive_ygg_addr(const uint8_t *_Nonnull pubkey,
                               uint8_t *_Nonnull ygg_addr);

/**
 * @brief Verify that pubkey correctly derives to claimed IID.
 *
 * SECURITY: This is the core cryptographic binding check. A key that
 * does not derive to the claimed IID is spoofing that address.
 *
 * @param[in] pubkey      32-byte Ed25519 public key
 * @param[in] claimed_iid 8-byte IID to verify
 * @return true if pubkey derives to claimed_iid
 */
[[nodiscard]] bool gcp_trust_verify_iid_derivation(
    const uint8_t *_Nonnull pubkey,
    const uint8_t *_Nonnull claimed_iid);

/**
 * @brief Verify that pubkey correctly derives to claimed 02xx address.
 *
 * @param[in] pubkey       32-byte Ed25519 public key
 * @param[in] claimed_addr 16-byte Yggdrasil address
 * @return true if pubkey derives to claimed_addr
 */
[[nodiscard]] bool gcp_trust_verify_ygg_derivation(
    const uint8_t *_Nonnull pubkey,
    const uint8_t *_Nonnull claimed_addr);

/**
 * @brief Verify ygg_addr[8:16] == IID (binding invariant).
 *
 * @param[in] ygg_addr 16-byte Yggdrasil address
 * @param[in] iid      8-byte IID
 * @return true if lower 64 bits match
 */
[[nodiscard]] bool gcp_trust_verify_ygg_iid_binding(
    const uint8_t *_Nonnull ygg_addr,
    const uint8_t *_Nonnull iid);

/**
 * @brief TOFU first-contact verification.
 *
 * Per spec 8.7: verify pubkey derives to claimed IID. If valid,
 * caller should pin the key. If invalid, reject as potential attack.
 *
 * @param[in] pubkey      32-byte Ed25519 public key
 * @param[in] claimed_iid 8-byte IID the peer claims
 * @return GCP_TOFU_PIN_AND_ACCEPT if valid, GCP_TOFU_REJECT_DERIVATION_MISMATCH if not
 */
[[nodiscard]] gcp_tofu_result_t gcp_trust_tofu_first_contact(
    const uint8_t *_Nonnull pubkey,
    const uint8_t *_Nonnull claimed_iid);

/**
 * @brief Verify a slot claim signature (open federation).
 *
 * SECURITY: Validates domain prefix to prevent cross-context replay.
 * Message must start with "SLOT_CLAIM:" to be accepted.
 *
 * @param[in] gateway_pubkey 32-byte gateway Ed25519 public key
 * @param[in] message        Slot claim message bytes
 * @param[in] message_len    Message length
 * @param[in] signature      48-byte Schnorr-48 signature
 * @param[in] signature_len  Signature length (must be 48)
 * @return GCP_SLOT_CLAIM_ACCEPT if valid, GCP_SLOT_CLAIM_REJECT_INVALID otherwise
 */
[[nodiscard]] gcp_slot_claim_result_t gcp_trust_verify_slot_claim(
    const uint8_t *_Nonnull gateway_pubkey,
    const uint8_t *_Nonnull message, size_t message_len,
    const uint8_t *_Nonnull signature, size_t signature_len);

/**
 * @brief Build canonical key rotation transcript for signing.
 *
 * Transcript = domain_tag || old_pubkey || old_iid || new_pubkey || sequence(8BE)
 *
 * @param[in]  old_pubkey         32-byte old public key
 * @param[in]  new_pubkey         32-byte new public key
 * @param[in]  rotation_sequence  Monotonic counter (big-endian u64)
 * @param[out] transcript         Output buffer (must be >= 102 bytes)
 * @param[in]  transcript_size    Size of transcript buffer
 * @return Length of transcript on success, -1 if buffer too small
 */
[[nodiscard]] int gcp_trust_build_rotation_transcript(
    const uint8_t *_Nonnull old_pubkey,
    const uint8_t *_Nonnull new_pubkey,
    uint64_t rotation_sequence,
    uint8_t *_Nonnull transcript,
    size_t transcript_size);

/**
 * @brief Verify a key rotation signature.
 *
 * SECURITY: Computes canonical transcript internally. Never accepts
 * arbitrary caller-supplied messages (prevents signature replay).
 *
 * @param[in] old_pubkey         32-byte currently-pinned public key
 * @param[in] new_pubkey         32-byte new public key
 * @param[in] rotation_sequence  Monotonic counter (must be > stored sequence)
 * @param[in] stored_sequence    Currently stored sequence number
 * @param[in] signature          48-byte Schnorr-48 signature from old key
 * @param[in] signature_len      Signature length (must be 48)
 * @return GCP_ROTATION_ACCEPT if valid, appropriate error otherwise
 */
[[nodiscard]] gcp_rotation_result_t gcp_trust_verify_key_rotation(
    const uint8_t *_Nonnull old_pubkey,
    const uint8_t *_Nonnull new_pubkey,
    uint64_t rotation_sequence,
    uint64_t stored_sequence,
    const uint8_t *_Nonnull signature,
    size_t signature_len);

/**
 * @brief Convert trust level to string for logging.
 *
 * @param[in] level Trust level
 * @return Static string name
 */
const char *gcp_trust_level_name(gcp_trust_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_GCP_TRUST_H_ */
