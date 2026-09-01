// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
/** @file
 *  COSE_Sign1 Root DIO Signature decode and structural validation
 *  (spec/06-security.md 8.10.1).
 *
 *  Mirrors python/src/lichen/crypto/root_dio_signature.py
 *  (from_cose_sign1 + verify structural subset) and the committed vector
 *  oracle test/vectors/root_dio_signature.json. Byte-transparent transport
 *  lives in the option layer (OPT_ROOT_DIO_SIGNATURE); signature verification
 *  and replay consumption are layered on top (bead b7z9.37.2.2(b)).
 */

#include <lichen/rpl_root_dio_sig.h>

#include <lichen/link_ctx.h>

#include <string.h>

/* CBOR major types used by the COSE_Sign1 shape. */
#define CBOR_MAJOR_UINT 0U
#define CBOR_MAJOR_NINT 1U
#define CBOR_MAJOR_BSTR 2U
#define CBOR_MAJOR_ARRAY 4U
#define CBOR_MAJOR_MAP 5U
#define CBOR_MAJOR_TAG 6U

/* COSE header labels (RFC 9052). */
#define COSE_ALG_LABEL 1
#define COSE_KID_LABEL 4
/* Schnorr48-Ed25519 private-use algorithm id (spec 06 8.10.1). */
#define SCHNORR48_ED25519_ALG (-65537)
/* COSE_Sign1 tag (RFC 9052). */
#define COSE_SIGN1_TAG 18U

/** Strict bounded CBOR reader (definite lengths only). */
struct root_sig_reader {
	const uint8_t *data;
	size_t len;
	size_t pos;
};

static int root_sig_read_head(struct root_sig_reader *r, uint8_t *major,
			      uint64_t *arg)
{
	uint8_t head;

	if (r->pos >= r->len) {
		return -ROOT_SIG_ERR_DECODE;
	}
	head = r->data[r->pos++];
	*major = head >> 5U;
	*arg = head & 0x1fU;
	if (*arg >= 24U) {
		size_t nbytes = (size_t)1U << (*arg - 24U);
		uint64_t value = 0;

		if (*arg > 27U || nbytes > r->len - r->pos) {
			return -ROOT_SIG_ERR_DECODE;
		}
		for (size_t i = 0; i < nbytes; i++) {
			value = (value << 8U) | r->data[r->pos++];
		}
		*arg = value;
	}
	return ROOT_SIG_OK;
}

static int root_sig_read_bstr(struct root_sig_reader *r,
			      const uint8_t **data, size_t *len)
{
	uint8_t major;
	uint64_t arg;

	if (root_sig_read_head(r, &major, &arg) != ROOT_SIG_OK ||
	    major != CBOR_MAJOR_BSTR || arg > (uint64_t)(r->len - r->pos)) {
		return -ROOT_SIG_ERR_DECODE;
	}
	*data = &r->data[r->pos];
	*len = (size_t)arg;
	r->pos += (size_t)arg;
	return ROOT_SIG_OK;
}

/* Read one unsigned integer element (negatives and other types rejected). */
static int root_sig_read_uint(struct root_sig_reader *r, uint64_t *value)
{
	uint8_t major;
	uint64_t arg;

	if (root_sig_read_head(r, &major, &arg) != ROOT_SIG_OK ||
	    major != CBOR_MAJOR_UINT) {
		return -ROOT_SIG_ERR_DECODE;
	}
	*value = arg;
	return ROOT_SIG_OK;
}

int root_dio_sig_decode(const uint8_t *data, size_t len,
			struct root_dio_sig *out)
{
	struct root_sig_reader r = { data, len, 0 };
	uint8_t major;
	uint64_t arg;
	const uint8_t *protected_bytes = NULL;
	size_t protected_len = 0;
	const uint8_t *payload_bytes = NULL;
	size_t payload_len = 0;
	uint8_t kid[8] = { 0 };
	bool kid_found = false;
	bool alg_found = false;
	bool alg_ok = false;
	uint64_t fields[6] = { 0U, 0U, 0U, 0U, 0U, 0U };
	bool field_seen[6] = { false };
	uint8_t dodag_id[16] = { 0 };
	bool dodag_id_seen = false;

	if (data == NULL || out == NULL) {
		return -ROOT_SIG_ERR_DECODE;
	}

	/* Tag wrapper: tag 18 (COSE_Sign1) around a 4-element array. */
	if (root_sig_read_head(&r, &major, &arg) != ROOT_SIG_OK ||
	    major != CBOR_MAJOR_TAG || arg != COSE_SIGN1_TAG) {
		return -ROOT_SIG_ERR_DECODE;
	}
	if (root_sig_read_head(&r, &major, &arg) != ROOT_SIG_OK ||
	    major != CBOR_MAJOR_ARRAY || arg != 4U) {
		return -ROOT_SIG_ERR_DECODE;
	}

	/* Element 1: protected header bstr -> map {1: alg}. */
	if (root_sig_read_bstr(&r, &protected_bytes, &protected_len) !=
	    ROOT_SIG_OK) {
		return -ROOT_SIG_ERR_DECODE;
	}
	{
		struct root_sig_reader p = { protected_bytes, protected_len, 0 };
		uint8_t p_major;
		uint64_t p_arg;

		if (root_sig_read_head(&p, &p_major, &p_arg) != ROOT_SIG_OK ||
		    p_major != CBOR_MAJOR_MAP) {
			return -ROOT_SIG_ERR_DECODE;
		}
		for (uint64_t i = 0; i < p_arg; i++) {
			uint64_t key = 0;
			uint8_t v_major;
			uint64_t v_arg;
			int64_t alg;

			if (root_sig_read_uint(&p, &key) != ROOT_SIG_OK ||
			    key != (uint64_t)COSE_ALG_LABEL) {
				return -ROOT_SIG_ERR_DECODE;
			}
			if (root_sig_read_head(&p, &v_major, &v_arg) !=
			    ROOT_SIG_OK) {
				return -ROOT_SIG_ERR_DECODE;
			}
			if (v_major != CBOR_MAJOR_NINT) {
				return -ROOT_SIG_ERR_ALGORITHM;
			}
			/* Negative int value: -1 - arg. */
			alg = -(int64_t)v_arg - 1;
			/* Python dict get(1) is last-wins; track the last. */
			alg_found = true;
			alg_ok = (alg == SCHNORR48_ED25519_ALG);
		}
	}
	if (!alg_found || !alg_ok) {
		return -ROOT_SIG_ERR_ALGORITHM;
	}

	/* Element 2: unprotected map -> kid (label 4, bstr 8). Python get(4)
	 * is last-wins; earlier entries are overwritten. */
	if (root_sig_read_head(&r, &major, &arg) != ROOT_SIG_OK ||
	    major != CBOR_MAJOR_MAP) {
		return -ROOT_SIG_ERR_DECODE;
	}
	for (uint64_t i = 0; i < arg; i++) {
		uint64_t key = 0;
		const uint8_t *value = NULL;
		size_t value_len = 0;

		if (root_sig_read_uint(&r, &key) != ROOT_SIG_OK ||
		    key != (uint64_t)COSE_KID_LABEL) {
			return -ROOT_SIG_ERR_DECODE;
		}
		if (root_sig_read_bstr(&r, &value, &value_len) != ROOT_SIG_OK ||
		    value_len != 8U) {
			return -ROOT_SIG_ERR_DECODE;
		}
		memcpy(kid, value, 8U);
		kid_found = true;
	}
	if (!kid_found) {
		return -ROOT_SIG_ERR_DECODE;
	}

	/* Element 3: payload bstr -> map with keys 1-7 (python indexes each
	 * key directly; missing keys are KeyErrors there, decode errors here;
	 * keys outside 1-7 are rejected in both). */
	if (root_sig_read_bstr(&r, &payload_bytes, &payload_len) != ROOT_SIG_OK) {
		return -ROOT_SIG_ERR_DECODE;
	}
	{
		struct root_sig_reader q = { payload_bytes, payload_len, 0 };
		uint8_t q_major;
		uint64_t q_arg;

		if (root_sig_read_head(&q, &q_major, &q_arg) != ROOT_SIG_OK ||
		    q_major != CBOR_MAJOR_MAP) {
			return -ROOT_SIG_ERR_DECODE;
		}
		for (uint64_t i = 0; i < q_arg; i++) {
			uint64_t key = 0;
			uint8_t v_major;
			uint64_t v_arg;

			if (root_sig_read_uint(&q, &key) != ROOT_SIG_OK ||
			    key == 0U || key > 7U) {
				return -ROOT_SIG_ERR_DECODE;
			}
			if (key == 1U) {
				if (root_sig_read_bstr(&q, &payload_bytes,
						       &payload_len) !=
					ROOT_SIG_OK ||
				    payload_len != 16U) {
					return -ROOT_SIG_ERR_DECODE;
				}
				memcpy(dodag_id, payload_bytes, 16U);
				dodag_id_seen = true;
				continue;
			}
			if (root_sig_read_uint(&q, &v_arg) != ROOT_SIG_OK) {
				return -ROOT_SIG_ERR_DECODE;
			}
			fields[key - 2U] = v_arg;
			field_seen[key - 2U] = true;
		}
	}
	for (size_t i = 0; i < 6U; i++) {
		if (!field_seen[i]) {
			return -ROOT_SIG_ERR_DECODE;
		}
	}
	if (!dodag_id_seen) {
		return -ROOT_SIG_ERR_DECODE;
	}

	/* Element 4: signature bstr, exactly 48 bytes. */
	{
		const uint8_t *signature = NULL;
		size_t signature_len = 0;

		if (root_sig_read_bstr(&r, &signature, &signature_len) !=
			ROOT_SIG_OK ||
		    signature_len != 48U) {
			return -ROOT_SIG_ERR_DECODE;
		}
		memcpy(out->signature, signature, 48U);
	}

	/* Python cbor2.loads rejects trailing bytes; so does this decoder. */
	if (r.pos != r.len) {
		return -ROOT_SIG_ERR_DECODE;
	}

	memcpy(out->root_iid, kid, 8U);
	memcpy(out->payload.dodag_id, dodag_id, 16U);
	if (fields[0] > 255U || fields[1] > 255U || fields[2] > 0xffffU ||
	    fields[5] > 7U) {
		return -ROOT_SIG_ERR_DECODE;
	}
	out->payload.instance = (uint8_t)fields[0];
	out->payload.version = (uint8_t)fields[1];
	out->payload.rank = (uint16_t)fields[2];
	out->payload.expiry = fields[3];
	out->payload.root_seq = fields[4];
	out->payload.mop = (uint8_t)fields[5];
	if (out->payload.mop > 7U) {
		return -ROOT_SIG_ERR_DECODE;
	}

	return ROOT_SIG_OK;
}

int root_dio_sig_verify_structural(
	const struct root_dio_sig *sig, const uint8_t *pubkey, size_t pubkey_len,
	uint64_t now_unix, const uint8_t *dio_dodag_id, uint8_t dio_instance,
	uint8_t dio_version, uint16_t dio_rank, uint8_t dio_mop)
{
	uint8_t iid[8];
	uint8_t ygg[16];

	if (sig == NULL || pubkey == NULL || pubkey_len != 32U ||
	    dio_dodag_id == NULL) {
		return ROOT_SIG_ERR_DECODE;
	}

	/* kid must equal the IID derived from the signer pubkey (step 1). */
	if (lichen_key_pubkey_to_iid(pubkey, iid) != 0 ||
	    memcmp(iid, sig->root_iid, 8U) != 0) {
		return ROOT_SIG_ERR_KID_MISMATCH;
	}
	/* DODAGID must equal ygg_addr(pubkey) (DODAGID-to-key binding). */
	if (lichen_identity_ygg_addr_from_ed25519(pubkey, ygg) != 0 ||
	    memcmp(ygg, sig->payload.dodag_id, 16U) != 0) {
		return ROOT_SIG_ERR_DODAGID_MISMATCH;
	}
	/* Expiry (step 4 of the python oracle). */
	if (sig->payload.expiry <= now_unix) {
		return ROOT_SIG_ERR_EXPIRED;
	}
	/* DIO header cross-checks (step 5). */
	if (memcmp(sig->payload.dodag_id, dio_dodag_id, 16U) != 0) {
		return ROOT_SIG_ERR_DODAGID_MISMATCH;
	}
	if (sig->payload.instance != dio_instance) {
		return ROOT_SIG_ERR_INSTANCE_MISMATCH;
	}
	if (sig->payload.version != dio_version) {
		return ROOT_SIG_ERR_VERSION_MISMATCH;
	}
	if (sig->payload.rank != dio_rank) {
		return ROOT_SIG_ERR_RANK_MISMATCH;
	}
	if (sig->payload.mop != dio_mop) {
		return ROOT_SIG_ERR_MOP_MISMATCH;
	}
	return ROOT_SIG_OK;
}
