/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file oscore.c
 * @brief OSCORE (RFC 8613) implementation
 *
 * Implements Object Security for Constrained RESTful Environments using
 * AES-CCM-16-64-128 and HKDF-SHA256 key derivation.
 */

#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <lichen/oscore.h>
#include "aes_ccm.h"
#include "hkdf.h"
#include <monocypher.h>

LOG_MODULE_REGISTER(oscore, CONFIG_LICHEN_OSCORE_LOG_LEVEL);

/* Context storage */
static struct oscore_ctx s_contexts[CONFIG_LICHEN_OSCORE_MAX_CONTEXTS];
static K_MUTEX_DEFINE(s_ctx_mutex);

/*
 * OSCORE info structure for HKDF (RFC 8613 Section 3.2.1):
 *
 * info = [
 *   id : bstr,
 *   id_context : bstr / nil,
 *   alg_aead : int,
 *   type : tstr,
 *   L : uint
 * ]
 *
 * We encode this as a minimal CBOR array.
 */

/* COSE Algorithm ID for AES-CCM-16-64-128 */
#define OSCORE_ALG_AEAD 10

/*
 * Build OSCORE HKDF info structure in CBOR format.
 * Returns encoded length, or negative on error.
 */
static int build_info_cbor(const uint8_t *id, size_t id_len,
			   const uint8_t *id_context, size_t id_context_len,
			   const char *type, size_t out_len,
			   uint8_t *buf, size_t buf_len)
{
	size_t off = 0;

	/* Array of 5 elements: 0x85 */
	if (off >= buf_len) return -1;
	buf[off++] = 0x85;

	/* id: bstr */
	if (id_len <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = 0x40 | (uint8_t)id_len;
	} else {
		if (off + 1 >= buf_len) return -1;
		buf[off++] = 0x58;
		buf[off++] = (uint8_t)id_len;
	}
	if (off + id_len > buf_len) return -1;
	memcpy(buf + off, id, id_len);
	off += id_len;

	/* id_context: bstr or null */
	if (id_context_len == 0) {
		if (off >= buf_len) return -1;
		buf[off++] = 0xf6; /* null */
	} else {
		if (id_context_len <= 23) {
			if (off >= buf_len) return -1;
			buf[off++] = 0x40 | (uint8_t)id_context_len;
		} else {
			if (off + 1 >= buf_len) return -1;
			buf[off++] = 0x58;
			buf[off++] = (uint8_t)id_context_len;
		}
		if (off + id_context_len > buf_len) return -1;
		memcpy(buf + off, id_context, id_context_len);
		off += id_context_len;
	}

	/* alg_aead: int (10 for AES-CCM-16-64-128) */
	if (off >= buf_len) return -1;
	buf[off++] = OSCORE_ALG_AEAD; /* 0..23 encodes directly */

	/* type: tstr ("Key", "IV", or "Info") */
	size_t type_len = strlen(type);
	if (type_len <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = 0x60 | (uint8_t)type_len;
	} else {
		return -1; /* type shouldn't be > 23 chars */
	}
	if (off + type_len > buf_len) return -1;
	memcpy(buf + off, type, type_len);
	off += type_len;

	/* L: uint (output length) */
	if (out_len <= 23) {
		if (off >= buf_len) return -1;
		buf[off++] = (uint8_t)out_len;
	} else if (out_len <= 255) {
		if (off + 1 >= buf_len) return -1;
		buf[off++] = 0x18;
		buf[off++] = (uint8_t)out_len;
	} else {
		return -1; /* L shouldn't be > 255 for OSCORE */
	}

	return (int)off;
}

/*
 * Derive sender/recipient key or common IV using HKDF.
 */
static int derive_key(const uint8_t *master_secret, size_t ms_len,
		      const uint8_t *master_salt, size_t salt_len,
		      const uint8_t *id, size_t id_len,
		      const uint8_t *id_context, size_t id_context_len,
		      const char *type, size_t out_len,
		      uint8_t *out)
{
	uint8_t info[64];
	int info_len;

	info_len = build_info_cbor(id, id_len, id_context, id_context_len,
				   type, out_len, info, sizeof(info));
	if (info_len < 0) {
		return OSCORE_ERR_KEY_DERIVATION;
	}

	if (hkdf_sha256(master_salt, salt_len,
			master_secret, ms_len,
			info, (size_t)info_len,
			out, out_len) != 0) {
		return OSCORE_ERR_KEY_DERIVATION;
	}

	return OSCORE_OK;
}

int oscore_init(void)
{
	k_mutex_lock(&s_ctx_mutex, K_FOREVER);
	memset(s_contexts, 0, sizeof(s_contexts));
	k_mutex_unlock(&s_ctx_mutex);

	LOG_INF("OSCORE initialized (%d contexts max)",
		CONFIG_LICHEN_OSCORE_MAX_CONTEXTS);
	return 0;
}

int oscore_ctx_create(const uint8_t master_secret[OSCORE_KEY_LEN],
		      const uint8_t *master_salt, size_t master_salt_len,
		      const uint8_t *sender_id, size_t sender_id_len,
		      const uint8_t *recipient_id, size_t recipient_id_len,
		      struct oscore_ctx **ctx_out)
{
	struct oscore_ctx *ctx = NULL;
	int ret;

	if (sender_id_len > OSCORE_ID_MAX_LEN ||
	    recipient_id_len > OSCORE_ID_MAX_LEN ||
	    master_salt_len > 8) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	/* Find free slot */
	for (int i = 0; i < CONFIG_LICHEN_OSCORE_MAX_CONTEXTS; i++) {
		if (!s_contexts[i].active) {
			ctx = &s_contexts[i];
			break;
		}
	}

	if (ctx == NULL) {
		k_mutex_unlock(&s_ctx_mutex);
		return OSCORE_ERR_NO_MEMORY;
	}

	/* Initialize context */
	memset(ctx, 0, sizeof(*ctx));
	memcpy(ctx->master_secret, master_secret, OSCORE_KEY_LEN);

	if (master_salt != NULL && master_salt_len > 0) {
		memcpy(ctx->master_salt, master_salt, master_salt_len);
		ctx->master_salt_len = (uint8_t)master_salt_len;
	}

	memcpy(ctx->sender_id, sender_id, sender_id_len);
	ctx->sender_id_len = (uint8_t)sender_id_len;

	memcpy(ctx->recipient_id, recipient_id, recipient_id_len);
	ctx->recipient_id_len = (uint8_t)recipient_id_len;

	/* Derive Sender Key */
	ret = derive_key(ctx->master_secret, OSCORE_KEY_LEN,
			 ctx->master_salt, ctx->master_salt_len,
			 ctx->sender_id, ctx->sender_id_len,
			 ctx->id_context, ctx->id_context_len,
			 "Key", OSCORE_KEY_LEN, ctx->sender_key);
	if (ret != OSCORE_OK) {
		k_mutex_unlock(&s_ctx_mutex);
		return ret;
	}

	/* Derive Recipient Key */
	ret = derive_key(ctx->master_secret, OSCORE_KEY_LEN,
			 ctx->master_salt, ctx->master_salt_len,
			 ctx->recipient_id, ctx->recipient_id_len,
			 ctx->id_context, ctx->id_context_len,
			 "Key", OSCORE_KEY_LEN, ctx->recipient_key);
	if (ret != OSCORE_OK) {
		k_mutex_unlock(&s_ctx_mutex);
		return ret;
	}

	/* Derive Common IV (id = empty for common context) */
	ret = derive_key(ctx->master_secret, OSCORE_KEY_LEN,
			 ctx->master_salt, ctx->master_salt_len,
			 NULL, 0,
			 ctx->id_context, ctx->id_context_len,
			 "IV", OSCORE_NONCE_LEN, ctx->common_iv);
	if (ret != OSCORE_OK) {
		k_mutex_unlock(&s_ctx_mutex);
		return ret;
	}

	ctx->sender_seq = 0;
	ctx->recipient_seq = 0;
	ctx->replay_window = 0;
	ctx->active = true;

	k_mutex_unlock(&s_ctx_mutex);

	*ctx_out = ctx;
	LOG_DBG("Created OSCORE context (sender=%u, recipient=%u)",
		sender_id_len, recipient_id_len);
	return OSCORE_OK;
}

void oscore_ctx_free(struct oscore_ctx *ctx)
{
	if (ctx == NULL) {
		return;
	}

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	/* Secure wipe of key material (crypto_wipe cannot be optimized away) */
	crypto_wipe(ctx->master_secret, sizeof(ctx->master_secret));
	crypto_wipe(ctx->sender_key, sizeof(ctx->sender_key));
	crypto_wipe(ctx->recipient_key, sizeof(ctx->recipient_key));
	crypto_wipe(ctx->common_iv, sizeof(ctx->common_iv));
	ctx->active = false;

	k_mutex_unlock(&s_ctx_mutex);
}

struct oscore_ctx *oscore_ctx_lookup(const uint8_t *recipient_id,
				     size_t recipient_id_len)
{
	struct oscore_ctx *ctx = NULL;

	k_mutex_lock(&s_ctx_mutex, K_FOREVER);

	for (int i = 0; i < CONFIG_LICHEN_OSCORE_MAX_CONTEXTS; i++) {
		if (s_contexts[i].active &&
		    s_contexts[i].recipient_id_len == recipient_id_len &&
		    memcmp(s_contexts[i].recipient_id, recipient_id,
			   recipient_id_len) == 0) {
			ctx = &s_contexts[i];
			break;
		}
	}

	k_mutex_unlock(&s_ctx_mutex);
	return ctx;
}

int oscore_option_parse(const uint8_t *data, size_t len,
			struct oscore_option *option)
{
	memset(option, 0, sizeof(*option));

	if (len == 0) {
		/* Empty option: no PIV, no KID, no KID Context */
		return OSCORE_OK;
	}

	/*
	 * OSCORE option format (RFC 8613 Section 6.1):
	 *
	 * +-----------+-----------+------+---------+--------+-----+
	 * | 0 (1 bit) | h (1 bit) | k    | n       | PIV    | ... |
	 * |           |           |(1bit)| (3 bits)| (n B)  |     |
	 * +-----------+-----------+------+---------+--------+-----+
	 *
	 * Followed by:
	 * - If h=1: s (1 byte) || kid_context (s bytes)
	 * - If k=1: kid (rest of option)
	 */

	const uint8_t *p = data;
	size_t remaining = len;

	/* First byte: flags */
	uint8_t flags = *p++;
	remaining--;

	/* Reserved bit must be 0 */
	if (flags & 0x80) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	bool h_flag = (flags & 0x10) != 0; /* KID Context present */
	bool k_flag = (flags & 0x08) != 0; /* KID present */
	uint8_t n = flags & 0x07;          /* PIV length */

	/* Parse PIV */
	if (n > 0) {
		if (n > OSCORE_PIV_MAX_LEN || n > remaining) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		memcpy(option->piv, p, n);
		option->piv_len = n;
		option->has_piv = true;
		p += n;
		remaining -= n;
	}

	/* Parse KID Context */
	if (h_flag) {
		if (remaining < 1) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		uint8_t s = *p++;
		remaining--;

		if (s > 8 || s > remaining) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		memcpy(option->kid_context, p, s);
		option->kid_context_len = s;
		option->has_kid_context = true;
		p += s;
		remaining -= s;
	}

	/* Parse KID (rest of option if k=1) */
	if (k_flag) {
		if (remaining > OSCORE_ID_MAX_LEN) {
			return OSCORE_ERR_INVALID_PARAM;
		}
		memcpy(option->kid, p, remaining);
		option->kid_len = (uint8_t)remaining;
		option->has_kid = true;
	}

	return OSCORE_OK;
}

int oscore_option_build(const struct oscore_option *option,
			uint8_t *buf, size_t buflen)
{
	size_t off = 0;

	/*
	 * Build OSCORE option value.
	 * Minimum is 1 byte (flags), plus variable parts.
	 */

	/* Flags byte */
	uint8_t flags = 0;
	if (option->has_kid_context) {
		flags |= 0x10;
	}
	if (option->has_kid) {
		flags |= 0x08;
	}
	if (option->has_piv) {
		flags |= option->piv_len & 0x07;
	}

	if (off >= buflen) {
		return OSCORE_ERR_BUFFER_TOO_SMALL;
	}
	buf[off++] = flags;

	/* PIV */
	if (option->has_piv && option->piv_len > 0) {
		if (off + option->piv_len > buflen) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(buf + off, option->piv, option->piv_len);
		off += option->piv_len;
	}

	/* KID Context */
	if (option->has_kid_context) {
		if (off + 1 + option->kid_context_len > buflen) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		buf[off++] = option->kid_context_len;
		memcpy(buf + off, option->kid_context, option->kid_context_len);
		off += option->kid_context_len;
	}

	/* KID */
	if (option->has_kid) {
		if (off + option->kid_len > buflen) {
			return OSCORE_ERR_BUFFER_TOO_SMALL;
		}
		memcpy(buf + off, option->kid, option->kid_len);
		off += option->kid_len;
	}

	return (int)off;
}

/*
 * Compute nonce from Partial IV and Common IV per RFC 8613 Section 5.2.
 *
 * nonce = left_pad(ID, nonce_len) XOR common_iv XOR left_pad(PIV, nonce_len)
 */
static void compute_nonce(const uint8_t *sender_id, size_t sender_id_len,
			  const uint8_t *piv, size_t piv_len,
			  const uint8_t *common_iv,
			  uint8_t nonce[OSCORE_NONCE_LEN])
{
	memset(nonce, 0, OSCORE_NONCE_LEN);

	/* Left-padded sender ID (XOR into positions starting at offset) */
	size_t id_offset = OSCORE_NONCE_LEN - 6; /* ID fits in last 6 bytes */
	if (sender_id_len <= 6) {
		size_t start = id_offset + (6 - sender_id_len);
		for (size_t i = 0; i < sender_id_len; i++) {
			nonce[start + i] = sender_id[i];
		}
	}

	/* Also encode sender_id_len at position NONCE_LEN - 6 - 1 */
	nonce[OSCORE_NONCE_LEN - 6 - 1] = (uint8_t)sender_id_len;

	/* Left-padded PIV */
	if (piv_len > 0 && piv_len <= 5) {
		size_t piv_start = OSCORE_NONCE_LEN - piv_len;
		for (size_t i = 0; i < piv_len; i++) {
			nonce[piv_start + i] ^= piv[i];
		}
	}

	/* XOR with common IV */
	for (size_t i = 0; i < OSCORE_NONCE_LEN; i++) {
		nonce[i] ^= common_iv[i];
	}
}

/*
 * Encode PIV (sequence number) as variable-length big-endian.
 */
static size_t encode_piv(uint32_t seq, uint8_t piv[OSCORE_PIV_MAX_LEN])
{
	if (seq == 0) {
		piv[0] = 0;
		return 1;
	}

	/* Find number of bytes needed */
	size_t len = 0;
	uint32_t tmp = seq;
	while (tmp > 0) {
		len++;
		tmp >>= 8;
	}

	/* Encode big-endian */
	for (size_t i = 0; i < len; i++) {
		piv[len - 1 - i] = (uint8_t)(seq & 0xFF);
		seq >>= 8;
	}

	return len;
}

/*
 * Decode PIV to sequence number.
 */
static uint32_t decode_piv(const uint8_t *piv, size_t piv_len)
{
	uint32_t seq = 0;
	for (size_t i = 0; i < piv_len; i++) {
		seq = (seq << 8) | piv[i];
	}
	return seq;
}

/*
 * Check replay window and update if valid.
 * Returns true if sequence number is acceptable.
 */
static bool check_replay(struct oscore_ctx *ctx, uint32_t seq)
{
	uint32_t window_size = CONFIG_LICHEN_OSCORE_REPLAY_WINDOW;

	if (seq > ctx->recipient_seq) {
		/* New highest seq - shift window */
		uint32_t shift = seq - ctx->recipient_seq;
		if (shift >= 32) {
			ctx->replay_window = 0;
		} else {
			ctx->replay_window <<= shift;
		}
		ctx->replay_window |= 1; /* Mark current as seen */
		ctx->recipient_seq = seq;
		return true;
	}

	/* seq <= recipient_seq: check if within window */
	uint32_t diff = ctx->recipient_seq - seq;
	if (diff >= window_size) {
		/* Too old */
		return false;
	}

	/* Check if already seen */
	uint32_t mask = 1U << diff;
	if (ctx->replay_window & mask) {
		/* Replay detected */
		return false;
	}

	/* Mark as seen */
	ctx->replay_window |= mask;
	return true;
}

int oscore_protect_request(struct oscore_ctx *ctx,
			   uint8_t code,
			   const uint8_t *options, size_t options_len,
			   const uint8_t *payload, size_t payload_len,
			   uint8_t *ciphertext, size_t *ciphertext_len,
			   uint8_t *oscore_opt, size_t *oscore_opt_len)
{
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t piv[OSCORE_PIV_MAX_LEN];
	size_t piv_len;
	uint8_t plaintext[256];
	size_t pt_len;
	int ret;

	if (ctx == NULL || ciphertext == NULL || oscore_opt == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Get and increment sender sequence number */
	uint32_t seq = ctx->sender_seq++;
	piv_len = encode_piv(seq, piv);

	/* Compute nonce */
	compute_nonce(ctx->sender_id, ctx->sender_id_len,
		      piv, piv_len, ctx->common_iv, nonce);

	/*
	 * Build plaintext: code || options || payload
	 * Code is first byte, options follow, then 0xFF marker and payload.
	 */
	pt_len = 0;
	plaintext[pt_len++] = code;

	if (options_len > 0) {
		if (pt_len + options_len >= sizeof(plaintext)) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_protect_request;
		}
		memcpy(plaintext + pt_len, options, options_len);
		pt_len += options_len;
	}

	if (payload_len > 0) {
		if (pt_len + 1 + payload_len >= sizeof(plaintext)) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_protect_request;
		}
		plaintext[pt_len++] = 0xFF; /* Payload marker */
		memcpy(plaintext + pt_len, payload, payload_len);
		pt_len += payload_len;
	}

	/* Build AAD (empty for now - would include Class I options) */
	/* TODO: Build proper OSCORE AAD structure */
	uint8_t aad[16];
	size_t aad_len = 0;

	/* Check output buffer size */
	size_t required_ct_len = pt_len + OSCORE_TAG_LEN;
	if (*ciphertext_len < required_ct_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_protect_request;
	}

	/* Encrypt */
	if (aes_ccm_encrypt(ctx->sender_key, nonce,
			    aad, aad_len,
			    plaintext, pt_len,
			    ciphertext) != 0) {
		ret = OSCORE_ERR_DECRYPT_FAILED;
		goto cleanup_protect_request;
	}
	*ciphertext_len = required_ct_len;

	/* Build OSCORE option */
	struct oscore_option opt = {
		.has_piv = true,
		.piv_len = (uint8_t)piv_len,
		.has_kid = true,
		.kid_len = ctx->sender_id_len,
	};
	memcpy(opt.piv, piv, piv_len);
	memcpy(opt.kid, ctx->sender_id, ctx->sender_id_len);

	int opt_len = oscore_option_build(&opt, oscore_opt, *oscore_opt_len);
	if (opt_len < 0) {
		ret = opt_len;
		goto cleanup_protect_request;
	}
	*oscore_opt_len = (size_t)opt_len;

	ret = OSCORE_OK;

cleanup_protect_request:
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(piv, sizeof(piv));
	crypto_wipe(plaintext, sizeof(plaintext));
	return ret;
}

int oscore_unprotect_request(struct oscore_ctx *ctx,
			     const uint8_t *oscore_opt, size_t oscore_opt_len,
			     const uint8_t *ciphertext, size_t ciphertext_len,
			     uint8_t *code,
			     uint8_t *options, size_t *options_len,
			     uint8_t *payload, size_t *payload_len)
{
	struct oscore_option opt;
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t plaintext[256];
	int ret;

	if (ctx == NULL || ciphertext == NULL || code == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (ciphertext_len < OSCORE_TAG_LEN + 1) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Parse OSCORE option */
	ret = oscore_option_parse(oscore_opt, oscore_opt_len, &opt);
	if (ret != OSCORE_OK) {
		return ret;
	}

	/* Need PIV for request */
	if (!opt.has_piv) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Check replay */
	uint32_t seq = decode_piv(opt.piv, opt.piv_len);
	if (!check_replay(ctx, seq)) {
		LOG_WRN("OSCORE replay detected: seq=%u", seq);
		return OSCORE_ERR_REPLAY;
	}

	/* Compute nonce using sender's ID from option (which is our recipient) */
	compute_nonce(ctx->recipient_id, ctx->recipient_id_len,
		      opt.piv, opt.piv_len, ctx->common_iv, nonce);

	/* Build AAD (empty for now) */
	uint8_t aad[16];
	size_t aad_len = 0;

	/* Decrypt */
	size_t pt_len = ciphertext_len - OSCORE_TAG_LEN;
	if (pt_len > sizeof(plaintext)) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_request;
	}

	if (aes_ccm_decrypt(ctx->recipient_key, nonce,
			    aad, aad_len,
			    ciphertext, ciphertext_len,
			    plaintext) != 0) {
		ret = OSCORE_ERR_DECRYPT_FAILED;
		goto cleanup_unprotect_request;
	}

	/* Parse plaintext: code || options || 0xFF || payload */
	if (pt_len < 1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_request;
	}
	*code = plaintext[0];

	/* Find payload marker */
	size_t marker_pos = 1;
	while (marker_pos < pt_len && plaintext[marker_pos] != 0xFF) {
		marker_pos++;
	}

	/* Copy options */
	size_t opt_len = marker_pos - 1;
	if (options != NULL && options_len != NULL) {
		if (*options_len < opt_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_unprotect_request;
		}
		memcpy(options, plaintext + 1, opt_len);
		*options_len = opt_len;
	}

	/* Copy payload */
	if (marker_pos < pt_len && plaintext[marker_pos] == 0xFF) {
		size_t pay_len = pt_len - marker_pos - 1;
		if (payload != NULL && payload_len != NULL) {
			if (*payload_len < pay_len) {
				ret = OSCORE_ERR_BUFFER_TOO_SMALL;
				goto cleanup_unprotect_request;
			}
			memcpy(payload, plaintext + marker_pos + 1, pay_len);
			*payload_len = pay_len;
		}
	} else if (payload_len != NULL) {
		*payload_len = 0;
	}

	ret = OSCORE_OK;

cleanup_unprotect_request:
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(plaintext, sizeof(plaintext));
	return ret;
}

int oscore_protect_response(struct oscore_ctx *ctx,
			    const uint8_t *request_piv, size_t request_piv_len,
			    uint8_t code,
			    const uint8_t *options, size_t options_len,
			    const uint8_t *payload, size_t payload_len,
			    uint8_t *ciphertext, size_t *ciphertext_len,
			    uint8_t *oscore_opt, size_t *oscore_opt_len)
{
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t plaintext[256];
	size_t pt_len;
	int ret;

	if (ctx == NULL || ciphertext == NULL || oscore_opt == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Response uses request's PIV for nonce */
	compute_nonce(ctx->recipient_id, ctx->recipient_id_len,
		      request_piv, request_piv_len, ctx->common_iv, nonce);

	/* Build plaintext: code || options || payload */
	pt_len = 0;
	plaintext[pt_len++] = code;

	if (options_len > 0) {
		if (pt_len + options_len >= sizeof(plaintext)) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_protect_response;
		}
		memcpy(plaintext + pt_len, options, options_len);
		pt_len += options_len;
	}

	if (payload_len > 0) {
		if (pt_len + 1 + payload_len >= sizeof(plaintext)) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_protect_response;
		}
		plaintext[pt_len++] = 0xFF;
		memcpy(plaintext + pt_len, payload, payload_len);
		pt_len += payload_len;
	}

	/* Build AAD */
	uint8_t aad[16];
	size_t aad_len = 0;

	/* Check output buffer size */
	size_t required_ct_len = pt_len + OSCORE_TAG_LEN;
	if (*ciphertext_len < required_ct_len) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_protect_response;
	}

	/* Encrypt with sender key */
	if (aes_ccm_encrypt(ctx->sender_key, nonce,
			    aad, aad_len,
			    plaintext, pt_len,
			    ciphertext) != 0) {
		ret = OSCORE_ERR_DECRYPT_FAILED;
		goto cleanup_protect_response;
	}
	*ciphertext_len = required_ct_len;

	/* Response OSCORE option: no PIV, no KID (echo) */
	struct oscore_option opt = {0};
	int opt_len = oscore_option_build(&opt, oscore_opt, *oscore_opt_len);
	if (opt_len < 0) {
		ret = opt_len;
		goto cleanup_protect_response;
	}
	*oscore_opt_len = (size_t)opt_len;

	ret = OSCORE_OK;

cleanup_protect_response:
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(plaintext, sizeof(plaintext));
	return ret;
}

int oscore_unprotect_response(struct oscore_ctx *ctx,
			      const uint8_t *request_piv, size_t request_piv_len,
			      const uint8_t *oscore_opt, size_t oscore_opt_len,
			      const uint8_t *ciphertext, size_t ciphertext_len,
			      uint8_t *code,
			      uint8_t *options, size_t *options_len,
			      uint8_t *payload, size_t *payload_len)
{
	uint8_t nonce[OSCORE_NONCE_LEN];
	uint8_t plaintext[256];
	int ret;

	(void)oscore_opt;
	(void)oscore_opt_len;

	if (ctx == NULL || ciphertext == NULL || code == NULL) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	if (ciphertext_len < OSCORE_TAG_LEN + 1) {
		return OSCORE_ERR_INVALID_PARAM;
	}

	/* Response uses request's PIV for nonce */
	compute_nonce(ctx->sender_id, ctx->sender_id_len,
		      request_piv, request_piv_len, ctx->common_iv, nonce);

	/* Build AAD */
	uint8_t aad[16];
	size_t aad_len = 0;

	/* Decrypt with recipient key */
	size_t pt_len = ciphertext_len - OSCORE_TAG_LEN;
	if (pt_len > sizeof(plaintext)) {
		ret = OSCORE_ERR_BUFFER_TOO_SMALL;
		goto cleanup_unprotect_response;
	}

	if (aes_ccm_decrypt(ctx->recipient_key, nonce,
			    aad, aad_len,
			    ciphertext, ciphertext_len,
			    plaintext) != 0) {
		ret = OSCORE_ERR_DECRYPT_FAILED;
		goto cleanup_unprotect_response;
	}

	/* Parse plaintext */
	if (pt_len < 1) {
		ret = OSCORE_ERR_INVALID_PARAM;
		goto cleanup_unprotect_response;
	}
	*code = plaintext[0];

	/* Find payload marker */
	size_t marker_pos = 1;
	while (marker_pos < pt_len && plaintext[marker_pos] != 0xFF) {
		marker_pos++;
	}

	/* Copy options */
	size_t opt_len = marker_pos - 1;
	if (options != NULL && options_len != NULL) {
		if (*options_len < opt_len) {
			ret = OSCORE_ERR_BUFFER_TOO_SMALL;
			goto cleanup_unprotect_response;
		}
		memcpy(options, plaintext + 1, opt_len);
		*options_len = opt_len;
	}

	/* Copy payload */
	if (marker_pos < pt_len && plaintext[marker_pos] == 0xFF) {
		size_t pay_len = pt_len - marker_pos - 1;
		if (payload != NULL && payload_len != NULL) {
			if (*payload_len < pay_len) {
				ret = OSCORE_ERR_BUFFER_TOO_SMALL;
				goto cleanup_unprotect_response;
			}
			memcpy(payload, plaintext + marker_pos + 1, pay_len);
			*payload_len = pay_len;
		}
	} else if (payload_len != NULL) {
		*payload_len = 0;
	}

	ret = OSCORE_OK;

cleanup_unprotect_response:
	crypto_wipe(nonce, sizeof(nonce));
	crypto_wipe(plaintext, sizeof(plaintext));
	return ret;
}
