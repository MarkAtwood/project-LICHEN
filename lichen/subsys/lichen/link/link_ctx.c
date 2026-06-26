/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file link_ctx.c
 * @brief LICHEN link layer context implementation
 */

#include <lichen/link_ctx.h>
#include <string.h>

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
#include "monocypher.h"
#include "monocypher-ed25519.h"
#endif

/* Error codes - use Zephyr errno if available */
#ifdef __ZEPHYR__
#include <errno.h>
#else
#define EINVAL 22
#endif

int lichen_link_init(struct lichen_link_ctx *ctx, const uint8_t *eui64)
{
	if (ctx == NULL || eui64 == NULL) {
		return -EINVAL;
	}

	memcpy(ctx->eui64, eui64, LICHEN_EUI64_LEN);
	memset(ctx->ed25519_sk, 0, LICHEN_SK_LEN);
	memset(ctx->ed25519_pk, 0, LICHEN_PK_LEN);
	ctx->epoch = 0;
	ctx->tx_seq = 0;
	ctx->has_key = false;

	return 0;
}

/**
 * @brief Apply Ed25519 clamping to a scalar.
 *
 * Clears bits 0-2, sets bit 254, clears bit 255.
 */
static void clamp_scalar(uint8_t s[32])
{
	s[0] &= 248;
	s[31] &= 127;
	s[31] |= 64;
}

int lichen_link_load_key(struct lichen_link_ctx *ctx, const uint8_t seed[32])
{
	if (ctx == NULL || seed == NULL) {
		return -EINVAL;
	}

#ifdef CONFIG_LICHEN_CRYPTO_MONOCYPHER
	uint8_t hash[64];

	/* h = SHA-512(seed) */
	crypto_sha512(hash, seed, 32);

	/* sk = clamp(h[0:32]) */
	memcpy(ctx->ed25519_sk, hash, LICHEN_SK_LEN);
	clamp_scalar(ctx->ed25519_sk);

	/* pk = sk * B */
	crypto_eddsa_scalarbase(ctx->ed25519_pk, ctx->ed25519_sk);

	/* Wipe sensitive intermediate data */
	crypto_wipe(hash, sizeof(hash));
#else
	/* Stub for builds without Monocypher - NOT FOR PRODUCTION */
	memcpy(ctx->ed25519_sk, seed, LICHEN_SK_LEN);
	memset(ctx->ed25519_pk, 0, LICHEN_PK_LEN);
	ctx->ed25519_pk[0] = 0x01;
#endif

	ctx->has_key = true;
	return 0;
}

uint16_t lichen_link_next_seq(struct lichen_link_ctx *ctx)
{
	uint16_t seq = ctx->tx_seq;
	ctx->tx_seq++;
	return seq;
}

void lichen_link_set_epoch(struct lichen_link_ctx *ctx, uint8_t epoch)
{
	ctx->epoch = epoch;
}
