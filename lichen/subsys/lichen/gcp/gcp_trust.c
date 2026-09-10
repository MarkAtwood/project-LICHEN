/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file gcp_trust.c
 * @brief GCP-3 Trust Models implementation per spec/08-gateway-coordination.md
 *
 * Dual-mode federation support for Zephyr border routers:
 * - Closed federation: PSK-based (handled by OSCORE layer)
 * - Open federation: Ed25519 + Schnorr-48 + TOFU
 *
 * Test vectors: test/vectors/gcp3_trust_models.json
 * Python oracle: python/src/lichen/crypto/trust.py
 */

#include <lichen/gcp_trust.h>
#include <lichen/link_ctx.h>
#include <string.h>

#ifdef CONFIG_LICHEN_GCP_TRUST_X509
#include <mbedtls/x509_crt.h>
#endif

/* ---- Logging ------------------------------------------------------------ */

#include <lichen/lichen_log.h>

#ifdef __ZEPHYR__
#ifndef CONFIG_LICHEN_GCP_LOG_LEVEL
#define CONFIG_LICHEN_GCP_LOG_LEVEL LOG_LEVEL_INF
#endif
LICHEN_LOG_MODULE(gcp_trust, CONFIG_LICHEN_GCP_LOG_LEVEL);
#else
LICHEN_LOG_MODULE(gcp_trust, LOG_LEVEL_WRN);
#endif

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
#include "monocypher.h"

/* ---- IID/Address Derivation --------------------------------------------- */

void gcp_trust_derive_iid(const uint8_t *pubkey, uint8_t *iid)
{
    uint8_t hash[64];

    /* IID = SHA-512(pubkey)[0:8] with U/L bit cleared */
    crypto_sha512(hash, pubkey, GCP_TRUST_PUBKEY_LEN);
    memcpy(iid, hash, GCP_TRUST_IID_LEN);

    /* Clear U/L bit (bit 1 of byte 0) per spec 8.5 */
    iid[0] &= ~0x02;

    crypto_wipe(hash, sizeof(hash));
}

void gcp_trust_derive_ygg_addr(const uint8_t *pubkey, uint8_t *ygg_addr)
{
    /* Upstream Yggdrasil AddrForKey via the single C derivation site
     * (spec/decisions.jsonl upstream-yggdrasil-addressing). The rejected
     * SHA-512 native profile lived here inline; routing through the link
     * module's implementation keeps every C consumer byte-identical.
     * Fails only on NULL inputs; both are caller-contract _Nonnull. */
    (void)lichen_identity_ygg_addr_from_ed25519(pubkey, ygg_addr);
}

/* ---- Verification ------------------------------------------------------- */

bool gcp_trust_verify_iid_derivation(const uint8_t *pubkey,
                                     const uint8_t *claimed_iid)
{
    uint8_t derived_iid[GCP_TRUST_IID_LEN];

    gcp_trust_derive_iid(pubkey, derived_iid);

    /* SECURITY: Constant-time comparison for 8-byte IID */
    uint8_t diff = 0;
    for (int i = 0; i < GCP_TRUST_IID_LEN; i++) {
        diff |= derived_iid[i] ^ claimed_iid[i];
    }

    crypto_wipe(derived_iid, sizeof(derived_iid));
    return diff == 0;
}

bool gcp_trust_verify_ygg_derivation(const uint8_t *pubkey,
                                     const uint8_t *claimed_addr)
{
    uint8_t derived_addr[GCP_TRUST_YGG_ADDR_LEN];

    gcp_trust_derive_ygg_addr(pubkey, derived_addr);

    /* SECURITY: Constant-time comparison */
    int result = crypto_verify16(derived_addr, claimed_addr);

    crypto_wipe(derived_addr, sizeof(derived_addr));
    return result == 0;
}

bool gcp_trust_verify_ygg_iid_binding(const uint8_t *ygg_addr,
                                      const uint8_t *iid)
{
    /* ygg_addr[8:16] must equal IID */
    uint8_t diff = 0;
    for (int i = 0; i < GCP_TRUST_IID_LEN; i++) {
        diff |= ygg_addr[8 + i] ^ iid[i];
    }
    return diff == 0;
}

/* ---- TOFU --------------------------------------------------------------- */

gcp_tofu_result_t gcp_trust_tofu_first_contact(const uint8_t *pubkey,
                                               const uint8_t *claimed_iid)
{
    if (gcp_trust_verify_iid_derivation(pubkey, claimed_iid)) {
        return GCP_TOFU_PIN_AND_ACCEPT;
    }
    LOG_WRN("TOFU: derivation mismatch for IID");
    return GCP_TOFU_REJECT_DERIVATION_MISMATCH;
}

/* ---- Slot Claim Verification (Open Federation) ------------------------- */

gcp_slot_claim_result_t gcp_trust_verify_slot_claim(
    const uint8_t *gateway_pubkey,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len)
{
    /* SECURITY: Reject oversized messages (DoS protection) */
    if (message_len > GCP_TRUST_MAX_CONTROL_MSG_LEN) {
        return GCP_SLOT_CLAIM_REJECT_INVALID;
    }

    /* SECURITY: Validate domain prefix (confused deputy prevention) */
    if (message_len < GCP_TRUST_SLOT_CLAIM_PREFIX_LEN) {
        return GCP_SLOT_CLAIM_REJECT_INVALID;
    }
    if (memcmp(message, GCP_TRUST_SLOT_CLAIM_PREFIX,
               GCP_TRUST_SLOT_CLAIM_PREFIX_LEN) != 0) {
        return GCP_SLOT_CLAIM_REJECT_INVALID;
    }

    /* Validate signature length */
    if (signature_len != GCP_TRUST_SIG_LEN) {
        return GCP_SLOT_CLAIM_REJECT_INVALID;
    }

    /* Verify Schnorr-48 signature */
    /* We need to include schnorr48.h and call schnorr48_verify */
    extern bool schnorr48_verify(const uint8_t *pubkey,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);

    if (schnorr48_verify(gateway_pubkey, message, message_len,
                         signature, signature_len)) {
        return GCP_SLOT_CLAIM_ACCEPT;
    }

    LOG_WRN("Slot claim: signature verification failed");
    return GCP_SLOT_CLAIM_REJECT_INVALID;
}

/* ---- Key Rotation ------------------------------------------------------- */

/* Transcript length: domain(22+1) + old_pubkey(32) + old_iid(8) + new_pubkey(32) + seq(8) = 103 */
#define GCP_ROTATION_TRANSCRIPT_LEN (GCP_TRUST_KEY_ROTATE_PREFIX_LEN + 1 + 32 + 8 + 32 + 8)

int gcp_trust_build_rotation_transcript(const uint8_t *old_pubkey,
                                        const uint8_t *new_pubkey,
                                        uint64_t rotation_sequence,
                                        uint8_t *transcript,
                                        size_t transcript_size)
{
    if (transcript_size < GCP_ROTATION_TRANSCRIPT_LEN) {
        return -1;
    }

    size_t offset = 0;

    /* Domain tag with null terminator */
    memcpy(transcript + offset, GCP_TRUST_KEY_ROTATE_PREFIX,
           GCP_TRUST_KEY_ROTATE_PREFIX_LEN);
    offset += GCP_TRUST_KEY_ROTATE_PREFIX_LEN;
    transcript[offset++] = 0x00;

    /* Old pubkey */
    memcpy(transcript + offset, old_pubkey, GCP_TRUST_PUBKEY_LEN);
    offset += GCP_TRUST_PUBKEY_LEN;

    /* Old IID (derived from old pubkey) */
    gcp_trust_derive_iid(old_pubkey, transcript + offset);
    offset += GCP_TRUST_IID_LEN;

    /* New pubkey */
    memcpy(transcript + offset, new_pubkey, GCP_TRUST_PUBKEY_LEN);
    offset += GCP_TRUST_PUBKEY_LEN;

    /* Sequence number (big-endian u64) */
    for (int i = 7; i >= 0; i--) {
        transcript[offset++] = (uint8_t)(rotation_sequence >> (i * 8));
    }

    return (int)offset;
}

gcp_rotation_result_t gcp_trust_verify_key_rotation(
    const uint8_t *old_pubkey,
    const uint8_t *new_pubkey,
    uint64_t rotation_sequence,
    uint64_t stored_sequence,
    const uint8_t *signature,
    size_t signature_len)
{
    uint8_t transcript[GCP_ROTATION_TRANSCRIPT_LEN];

    /* SECURITY: Anti-replay check - sequence must be strictly greater */
    if (rotation_sequence <= stored_sequence) {
        LOG_WRN("Key rotation: replay attack (seq %llu <= %llu)",
                (unsigned long long)rotation_sequence,
                (unsigned long long)stored_sequence);
        return GCP_ROTATION_REJECT_REPLAY;
    }

    /* Validate signature length */
    if (signature_len != GCP_TRUST_SIG_LEN) {
        return GCP_ROTATION_REJECT_INVALID_SIGNATURE;
    }

    /* SECURITY: Build canonical transcript internally (prevents replay) */
    int len = gcp_trust_build_rotation_transcript(old_pubkey, new_pubkey,
                                                  rotation_sequence,
                                                  transcript, sizeof(transcript));
    if (len < 0) {
        return GCP_ROTATION_REJECT_INVALID_SIGNATURE;
    }

    /* Verify signature from old key */
    extern bool schnorr48_verify(const uint8_t *pubkey,
                                 const uint8_t *msg, size_t msg_len,
                                 const uint8_t *sig, size_t sig_len);

    bool valid = schnorr48_verify(old_pubkey, transcript, (size_t)len,
                                  signature, signature_len);

    crypto_wipe(transcript, sizeof(transcript));

    if (valid) {
        return GCP_ROTATION_ACCEPT;
    }

    LOG_WRN("Key rotation: signature verification failed");
    return GCP_ROTATION_REJECT_INVALID_SIGNATURE;
}

/* ---- Utilities ---------------------------------------------------------- */

const char *gcp_trust_level_name(gcp_trust_level_t level)
{
    switch (level) {
    case GCP_TRUST_LEVEL_TOFU:
        return "TOFU";
    case GCP_TRUST_LEVEL_BR_PROVISIONED:
        return "BR_PROVISIONED";
    case GCP_TRUST_LEVEL_DANE:
        return "DANE";
    case GCP_TRUST_LEVEL_PKIX:
        return "PKIX";
    default:
        return "UNKNOWN";
    }
}

#else /* !CONFIG_LICHEN_CRYPTO_MONOCYPHER */

/*
 * Stub implementations for builds without Monocypher.
 * These abort at runtime to prevent silent security failures.
 */

#include <stdlib.h>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noreturn))
#endif
static void gcp_trust_stub_abort(const char *func)
{
    LOG_WRN("%s called without Monocypher - aborting", func);
    abort();
}

void gcp_trust_derive_iid(const uint8_t *pubkey, uint8_t *iid)
{
    (void)pubkey;
    (void)iid;
    gcp_trust_stub_abort("gcp_trust_derive_iid");
}

void gcp_trust_derive_ygg_addr(const uint8_t *pubkey, uint8_t *ygg_addr)
{
    (void)pubkey;
    (void)ygg_addr;
    gcp_trust_stub_abort("gcp_trust_derive_ygg_addr");
}

bool gcp_trust_verify_iid_derivation(const uint8_t *pubkey,
                                     const uint8_t *claimed_iid)
{
    (void)pubkey;
    (void)claimed_iid;
    gcp_trust_stub_abort("gcp_trust_verify_iid_derivation");
    return false;
}

bool gcp_trust_verify_ygg_derivation(const uint8_t *pubkey,
                                     const uint8_t *claimed_addr)
{
    (void)pubkey;
    (void)claimed_addr;
    gcp_trust_stub_abort("gcp_trust_verify_ygg_derivation");
    return false;
}

bool gcp_trust_verify_ygg_iid_binding(const uint8_t *ygg_addr, const uint8_t *iid)
{
    (void)ygg_addr;
    (void)iid;
    gcp_trust_stub_abort("gcp_trust_verify_ygg_iid_binding");
    return false;
}

gcp_tofu_result_t gcp_trust_tofu_first_contact(const uint8_t *pubkey,
                                               const uint8_t *claimed_iid)
{
    (void)pubkey;
    (void)claimed_iid;
    gcp_trust_stub_abort("gcp_trust_tofu_first_contact");
    return GCP_TOFU_REJECT_DERIVATION_MISMATCH;
}

gcp_slot_claim_result_t gcp_trust_verify_slot_claim(
    const uint8_t *gateway_pubkey,
    const uint8_t *message, size_t message_len,
    const uint8_t *signature, size_t signature_len)
{
    (void)gateway_pubkey;
    (void)message;
    (void)message_len;
    (void)signature;
    (void)signature_len;
    gcp_trust_stub_abort("gcp_trust_verify_slot_claim");
    return GCP_SLOT_CLAIM_REJECT_INVALID;
}

int gcp_trust_build_rotation_transcript(const uint8_t *old_pubkey,
                                        const uint8_t *new_pubkey,
                                        uint64_t rotation_sequence,
                                        uint8_t *transcript,
                                        size_t transcript_size)
{
    (void)old_pubkey;
    (void)new_pubkey;
    (void)rotation_sequence;
    (void)transcript;
    (void)transcript_size;
    gcp_trust_stub_abort("gcp_trust_build_rotation_transcript");
    return -1;
}

gcp_rotation_result_t gcp_trust_verify_key_rotation(
    const uint8_t *old_pubkey,
    const uint8_t *new_pubkey,
    uint64_t rotation_sequence,
    uint64_t stored_sequence,
    const uint8_t *signature,
    size_t signature_len)
{
    (void)old_pubkey;
    (void)new_pubkey;
    (void)rotation_sequence;
    (void)stored_sequence;
    (void)signature;
    (void)signature_len;
    gcp_trust_stub_abort("gcp_trust_verify_key_rotation");
    return GCP_ROTATION_REJECT_INVALID_SIGNATURE;
}

const char *gcp_trust_level_name(gcp_trust_level_t level)
{
    (void)level;
    return "STUB";
}

#endif /* CONFIG_LICHEN_CRYPTO_MONOCYPHER */

#ifdef CONFIG_LICHEN_GCP_TRUST_X509

static bool gcp_der_tlv(const uint8_t **cursor, const uint8_t *end,
                        uint8_t tag, const uint8_t **value, size_t *value_len)
{
    const uint8_t *p = *cursor;
    size_t len = 0;

    if (p >= end || *p++ != tag || p >= end) {
        return false;
    }
    if ((*p & 0x80U) == 0) {
        len = *p++;
    } else {
        size_t octets = *p++ & 0x7fU;
        if (octets == 0 || octets > sizeof(size_t) ||
            (size_t)(end - p) < octets) {
            return false;
        }
        for (size_t i = 0; i < octets; i++) {
            if (len > (SIZE_MAX >> 8)) {
                return false;
            }
            len = (len << 8) | *p++;
        }
    }
    if (len > (size_t)(end - p)) {
        return false;
    }
    *cursor = p + len;
    *value = p;
    *value_len = len;
    return true;
}

static bool gcp_x509_ed25519_key(const mbedtls_x509_buf *spki,
                                 uint8_t public_key[32])
{
    const uint8_t *p = spki->p;
    const uint8_t *end = p + spki->len;
    const uint8_t *sequence;
    size_t sequence_len;
    const uint8_t *algorithm;
    size_t algorithm_len;
    const uint8_t *oid;
    size_t oid_len;
    const uint8_t *bit_string;
    size_t bit_string_len;

    if (!gcp_der_tlv(&p, end, 0x30, &sequence, &sequence_len) || p != end) {
        return false;
    }
    p = sequence;
    end = sequence + sequence_len;
    if (!gcp_der_tlv(&p, end, 0x30, &algorithm, &algorithm_len)) {
        return false;
    }
    const uint8_t *algorithm_cursor = algorithm;
    const uint8_t *algorithm_end = algorithm + algorithm_len;
    if (!gcp_der_tlv(&algorithm_cursor, algorithm_end, 0x06, &oid,
                     &oid_len) || algorithm_cursor != algorithm_end ||
        oid_len != 3 || oid[0] != 0x2b || oid[1] != 0x65 || oid[2] != 0x70 ||
        !gcp_der_tlv(&p, end, 0x03, &bit_string, &bit_string_len) ||
        p != end || bit_string_len != 33 || bit_string[0] != 0) {
        return false;
    }
    memcpy(public_key, bit_string + 1, 32);
    return true;
}

static bool gcp_x509_san_critical(const mbedtls_x509_crt *crt,
                                  bool *critical)
{
    const uint8_t *p = crt->v3_ext.p;
    const uint8_t *end = p + crt->v3_ext.len;
    const uint8_t *extensions;
    size_t extensions_len;

    if (!gcp_der_tlv(&p, end, 0x30, &extensions, &extensions_len)) {
        return false;
    }
    p = extensions;
    end = extensions + extensions_len;
    while (p < end) {
        const uint8_t *extension;
        size_t extension_len;
        const uint8_t *oid;
        size_t oid_len;
        const uint8_t *q;
        const uint8_t *extension_end;
        const uint8_t *value;
        size_t value_len;

        if (!gcp_der_tlv(&p, end, 0x30, &extension, &extension_len)) {
            return false;
        }
        q = extension;
        extension_end = extension + extension_len;
        if (!gcp_der_tlv(&q, extension_end, 0x06, &oid, &oid_len)) {
            return false;
        }
        if (oid_len == 3 && oid[0] == 0x55 && oid[1] == 0x1d &&
            oid[2] == 0x11) {
            *critical = false;
            if (q < extension_end && *q == 0x01) {
                if (!gcp_der_tlv(&q, extension_end, 0x01, &value,
                                 &value_len) || value_len != 1) {
                    return false;
                }
                *critical = value[0] != 0;
            }
            return gcp_der_tlv(&q, extension_end, 0x04, &value, &value_len) &&
                   q == extension_end;
        }
    }
    return false;
}

static bool gcp_x509_san_binding(const mbedtls_x509_crt *crt)
{
    uint8_t public_key[32];
    uint8_t expected_address[GCP_TRUST_YGG_ADDR_LEN];
    bool san_critical;
    size_t native_count = 0;
    const mbedtls_x509_sequence *san = &crt->subject_alt_names;

    if (!gcp_x509_san_critical(crt, &san_critical) ||
        san_critical != (crt->subject_raw.len == 2 &&
                         crt->subject_raw.p[0] == 0x30 &&
                         crt->subject_raw.p[1] == 0x00) ||
        !gcp_x509_ed25519_key(&crt->pk_raw, public_key)) {
        return false;
    }
    gcp_trust_derive_ygg_addr(public_key, expected_address);

    for (; san != NULL; san = san->next) {
        if (san->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2) ||
            san->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 6)) {
            return false;
        }
        if (san->buf.tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7) &&
            san->buf.len == GCP_TRUST_YGG_ADDR_LEN && san->buf.p[0] == 0x02) {
            native_count++;
            if (memcmp(san->buf.p, expected_address,
                       GCP_TRUST_YGG_ADDR_LEN) != 0) {
                return false;
            }
        }
    }
    return native_count == 1;
}

int gcp_trust_validate_x509_chain(const uint8_t *leaf_der,
                                  size_t leaf_len,
                                  const uint8_t *const *chain_der,
                                  const size_t *chain_lens,
                                  size_t chain_count,
                                  const uint8_t *anchor_der,
                                  size_t anchor_len)
{
    int ret;
    uint32_t flags = 0;
    mbedtls_x509_crt chain;
    mbedtls_x509_crt anchor;

    if (leaf_der == NULL || leaf_len == 0 || anchor_der == NULL ||
        anchor_len == 0 || (chain_count != 0 &&
                            (chain_der == NULL || chain_lens == NULL))) {
        return -EINVAL;
    }

    mbedtls_x509_crt_init(&chain);
    mbedtls_x509_crt_init(&anchor);
    ret = mbedtls_x509_crt_parse_der(&chain, leaf_der, leaf_len);
    if (ret != 0) {
        ret = -EINVAL;
        goto out;
    }
    for (size_t i = 0; i < chain_count; i++) {
        if (chain_der[i] == NULL || chain_lens[i] == 0 ||
            mbedtls_x509_crt_parse_der(&chain, chain_der[i], chain_lens[i]) != 0) {
            ret = -EINVAL;
            goto out;
        }
    }
    if (mbedtls_x509_crt_parse_der(&anchor, anchor_der, anchor_len) != 0 ||
        anchor.next != NULL || anchor.raw.len != anchor_len ||
        memcmp(anchor.raw.p, anchor_der, anchor_len) != 0) {
        ret = -EINVAL;
        goto out;
    }

    if ((chain.ext_types & MBEDTLS_X509_EXT_BASIC_CONSTRAINTS) == 0 ||
        chain.ca_istrue ||
        (chain.ext_types & MBEDTLS_X509_EXT_KEY_USAGE) == 0 ||
        (chain.key_usage & MBEDTLS_X509_KU_DIGITAL_SIGNATURE) == 0) {
        ret = -EINVAL;
        goto out;
    }

    if (!gcp_x509_san_binding(&chain)) {
        ret = -EINVAL;
        goto out;
    }

    ret = mbedtls_x509_crt_verify(&chain, &anchor, NULL, NULL, &flags, NULL, NULL);
    if (ret != 0 || flags != 0) {
        ret = -EINVAL;
    }

out:
    mbedtls_x509_crt_free(&anchor);
    mbedtls_x509_crt_free(&chain);
    return ret;
}

#endif /* CONFIG_LICHEN_GCP_TRUST_X509 */
