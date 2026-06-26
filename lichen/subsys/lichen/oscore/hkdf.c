/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file hkdf.c
 * @brief HKDF-SHA256 key derivation for OSCORE
 *
 * Implements HKDF (RFC 5869) using tinycrypt's SHA-256 HMAC.
 * Used to derive sender/recipient keys and common IV from master secret.
 */

#include <string.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/hmac.h>
#include <monocypher.h>

#include "hkdf.h"

#define SHA256_HASH_LEN 32
#define SHA256_BLOCK_LEN 64

/**
 * @brief HMAC-SHA256
 */
static int hmac_sha256(const uint8_t *key, size_t key_len,
		       const uint8_t *data, size_t data_len,
		       uint8_t out[SHA256_HASH_LEN])
{
	struct tc_hmac_state_struct h;

	if (tc_hmac_set_key(&h, key, key_len) != TC_CRYPTO_SUCCESS) {
		return -1;
	}
	if (tc_hmac_init(&h) != TC_CRYPTO_SUCCESS) {
		crypto_wipe(&h, sizeof(h));
		return -1;
	}
	if (tc_hmac_update(&h, data, data_len) != TC_CRYPTO_SUCCESS) {
		crypto_wipe(&h, sizeof(h));
		return -1;
	}
	if (tc_hmac_final(out, TC_SHA256_DIGEST_SIZE, &h) != TC_CRYPTO_SUCCESS) {
		crypto_wipe(&h, sizeof(h));
		return -1;
	}
	crypto_wipe(&h, sizeof(h));
	return 0;
}

int lichen_hkdf_extract(const uint8_t *salt, size_t salt_len,
		 const uint8_t *ikm, size_t ikm_len,
		 uint8_t prk[32])
{
	/*
	 * HKDF-Extract: PRK = HMAC-Hash(salt, IKM)
	 * If salt is empty, use a string of HashLen zeros.
	 */
	uint8_t default_salt[SHA256_HASH_LEN];

	if (salt == NULL || salt_len == 0) {
		memset(default_salt, 0, sizeof(default_salt));
		salt = default_salt;
		salt_len = SHA256_HASH_LEN;
	}

	return hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

int lichen_hkdf_expand(const uint8_t prk[32],
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len)
{
	/*
	 * HKDF-Expand: OKM = T(1) || T(2) || ... || T(N)
	 * T(0) = empty string
	 * T(i) = HMAC-Hash(PRK, T(i-1) || info || i)
	 *
	 * We need ceil(L/HashLen) iterations.
	 */
	uint8_t t[SHA256_HASH_LEN];
	uint8_t buf[SHA256_HASH_LEN + 256 + 1]; /* T(i-1) || info || counter */
	size_t t_len = 0;
	size_t offset = 0;
	uint8_t counter = 1;

	if (okm_len > 255 * SHA256_HASH_LEN) {
		return -1; /* OKM too long (no secrets to wipe yet) */
	}
	if (info_len > 255) {
		return -1; /* Info too long for our buffer (no secrets to wipe yet) */
	}

	while (offset < okm_len) {
		size_t buf_len = 0;

		/* T(i-1) */
		if (t_len > 0) {
			memcpy(buf, t, t_len);
			buf_len = t_len;
		}

		/* info */
		if (info_len > 0) {
			memcpy(buf + buf_len, info, info_len);
			buf_len += info_len;
		}

		/* counter (1-byte) */
		buf[buf_len++] = counter++;

		/* T(i) = HMAC(PRK, T(i-1) || info || i) */
		if (hmac_sha256(prk, SHA256_HASH_LEN, buf, buf_len, t) != 0) {
			crypto_wipe(t, sizeof(t));
			crypto_wipe(buf, sizeof(buf));
			return -1;
		}
		t_len = SHA256_HASH_LEN;

		/* Copy to output */
		size_t to_copy = okm_len - offset;
		if (to_copy > SHA256_HASH_LEN) {
			to_copy = SHA256_HASH_LEN;
		}
		memcpy(okm + offset, t, to_copy);
		offset += to_copy;
	}

	/* Wipe intermediate key material */
	crypto_wipe(t, sizeof(t));
	crypto_wipe(buf, sizeof(buf));

	return 0;
}

int lichen_hkdf_sha256(const uint8_t *salt, size_t salt_len,
		const uint8_t *ikm, size_t ikm_len,
		const uint8_t *info, size_t info_len,
		uint8_t *okm, size_t okm_len)
{
	uint8_t prk[SHA256_HASH_LEN];
	int ret;

	ret = lichen_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
	if (ret != 0) {
		return ret;
	}

	ret = lichen_hkdf_expand(prk, info, info_len, okm, okm_len);

	/* Wipe PRK (crypto_wipe cannot be optimized away) */
	crypto_wipe(prk, sizeof(prk));

	return ret;
}
