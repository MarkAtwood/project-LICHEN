/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file aes_ccm.c
 * @brief AES-CCM-16-64-128 wrapper using tinycrypt
 *
 * Implements COSE Algorithm ID 10 (AES-CCM-16-64-128):
 *   - 128-bit key
 *   - 13-byte nonce (L=2, so counter can address 64KB)
 *   - 64-bit authentication tag
 *
 * Uses tinycrypt's CCM mode implementation.
 */

#include <string.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>
#include <monocypher.h>

#include "aes_ccm.h"

int lichen_aes_ccm_encrypt(const uint8_t key[AES_CCM_KEY_LEN],
		    const uint8_t nonce[AES_CCM_NONCE_LEN],
		    const uint8_t *aad, size_t aad_len,
		    const uint8_t *plaintext, size_t pt_len,
		    uint8_t *ciphertext)
{
	struct tc_aes_key_sched_struct sched;
	struct tc_ccm_mode_struct ccm;
	int ret;
	int result = -1;

	/* Initialize AES key schedule */
	ret = tc_aes128_set_encrypt_key(&sched, key);
	if (ret != TC_CRYPTO_SUCCESS) {
		goto cleanup;
	}

	/* Configure CCM mode */
	ret = tc_ccm_config(&ccm, &sched, (uint8_t *)nonce, AES_CCM_NONCE_LEN,
			    AES_CCM_TAG_LEN);
	if (ret != TC_CRYPTO_SUCCESS) {
		goto cleanup;
	}

	/* Encrypt and authenticate */
	ret = tc_ccm_generation_encryption(ciphertext, pt_len + AES_CCM_TAG_LEN,
					   aad, aad_len,
					   plaintext, pt_len,
					   &ccm);
	if (ret != TC_CRYPTO_SUCCESS) {
		goto cleanup;
	}

	result = 0;

cleanup:
	/* Wipe key schedule and CCM state to prevent key leakage */
	crypto_wipe(&sched, sizeof(sched));
	crypto_wipe(&ccm, sizeof(ccm));
	return result;
}

int lichen_aes_ccm_decrypt(const uint8_t key[AES_CCM_KEY_LEN],
		    const uint8_t nonce[AES_CCM_NONCE_LEN],
		    const uint8_t *aad, size_t aad_len,
		    const uint8_t *ciphertext, size_t ct_len,
		    uint8_t *plaintext)
{
	struct tc_aes_key_sched_struct sched;
	struct tc_ccm_mode_struct ccm;
	int ret;
	int result = -1;

	if (ct_len < AES_CCM_TAG_LEN) {
		return -1;
	}

	/* Initialize AES key schedule */
	ret = tc_aes128_set_encrypt_key(&sched, key);
	if (ret != TC_CRYPTO_SUCCESS) {
		goto cleanup;
	}

	/* Configure CCM mode */
	ret = tc_ccm_config(&ccm, &sched, (uint8_t *)nonce, AES_CCM_NONCE_LEN,
			    AES_CCM_TAG_LEN);
	if (ret != TC_CRYPTO_SUCCESS) {
		goto cleanup;
	}

	/* Decrypt and verify */
	ret = tc_ccm_decryption_verification(plaintext, ct_len - AES_CCM_TAG_LEN,
					     aad, aad_len,
					     ciphertext, ct_len,
					     &ccm);
	if (ret != TC_CRYPTO_SUCCESS) {
		goto cleanup;
	}

	result = 0;

cleanup:
	/* Wipe key schedule and CCM state to prevent key leakage */
	crypto_wipe(&sched, sizeof(sched));
	crypto_wipe(&ccm, sizeof(ccm));
	return result;
}
