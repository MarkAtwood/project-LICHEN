/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/link_ctx.h
 * @brief LICHEN link layer context
 *
 * Manages per-node link layer state: identity (EUI-64), Ed25519 keypair
 * for Schnorr-48 signatures, epoch counter, and TX sequence number.
 *
 * Replay window tracking is handled separately per-neighbor in replay.h.
 */

#ifndef LICHEN_LINK_CTX_H_
#define LICHEN_LINK_CTX_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** EUI-64 address length */
#define LICHEN_EUI64_LEN 8

/** Ed25519 seed length (input to key derivation) */
#define LICHEN_SEED_LEN 32

/** Ed25519 secret key length (clamped scalar) */
#define LICHEN_SK_LEN 32

/** Ed25519 public key length (compressed point) */
#define LICHEN_PK_LEN 32

/**
 * @brief LICHEN link layer context
 *
 * Holds the node's identity and cryptographic material for the link layer.
 * Initialize with lichen_link_init(), then load keys with lichen_link_load_key().
 */
struct lichen_link_ctx {
	uint8_t eui64[LICHEN_EUI64_LEN]; /**< Node's EUI-64 address */
	uint8_t ed25519_sk[LICHEN_SK_LEN]; /**< Ed25519 secret key (clamped) */
	uint8_t ed25519_pk[LICHEN_PK_LEN]; /**< Ed25519 public key */
	uint8_t epoch;    /**< Current epoch (key rotation counter) */
	uint16_t tx_seq;  /**< TX sequence counter */
	bool has_key;     /**< Whether keypair is loaded */
};

/**
 * @brief Initialize link context with an EUI-64 address.
 *
 * Sets the node's EUI-64 identity and clears all cryptographic state.
 * After calling this, the context has no keypair loaded (has_key = false).
 *
 * @param[out] ctx   Link context to initialize
 * @param[in]  eui64 8-byte EUI-64 address
 * @return 0 on success, -EINVAL if ctx or eui64 is NULL
 */
int lichen_link_init(struct lichen_link_ctx *ctx, const uint8_t *eui64);

/**
 * @brief Load an Ed25519 keypair from a 32-byte seed.
 *
 * Derives the Ed25519 keypair using the Schnorr-48 key derivation
 * (SHA-512 + clamping), which is compatible with standard Ed25519.
 *
 * @param[in,out] ctx  Link context
 * @param[in]     seed 32-byte random seed
 * @return 0 on success, -EINVAL if ctx or seed is NULL
 */
int lichen_link_load_key(struct lichen_link_ctx *ctx, const uint8_t seed[32]);

/**
 * @brief Increment and return the next TX sequence number.
 *
 * The sequence number wraps from 0xFFFF to 0x0000. Callers should
 * handle epoch rotation when this happens.
 *
 * @param[in,out] ctx Link context
 * @return Next sequence number to use
 */
uint16_t lichen_link_next_seq(struct lichen_link_ctx *ctx);

/**
 * @brief Set the current epoch.
 *
 * The epoch is typically incremented when the TX sequence wraps or
 * when a new symmetric key is derived for encryption.
 *
 * @param[in,out] ctx   Link context
 * @param[in]     epoch New epoch value
 */
void lichen_link_set_epoch(struct lichen_link_ctx *ctx, uint8_t epoch);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_LINK_CTX_H_ */
