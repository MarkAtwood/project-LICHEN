// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
/** @file
 *  COSE_Sign1 Root DIO Signature decode and structural validation
 *  (spec/06-security.md 8.10.1).
 *
 *  Mirrors python/src/lichen/crypto/root_dio_signature.py (from_cose_sign1 +
 *  the structural subset of verify_root_dio_signature) and the committed
 *  vector oracle test/vectors/root_dio_signature.json. Transport is the
 *  byte-transparent option layer (OPT_ROOT_DIO_SIGNATURE); signature
 *  verification and replay consumption are layered on top (bead
 *  b7z9.37.2.2(b)).
 */

#ifndef LICHEN_RPL_ROOT_DIO_SIG_H
#define LICHEN_RPL_ROOT_DIO_SIG_H

#include <stddef.h>
#include <stdint.h>

/* Validation failure reasons; strings mirror the vector expected.error
 * fields (test/vectors/root_dio_signature.json). */
#define ROOT_SIG_OK 0
#define ROOT_SIG_ERR_DECODE 1
#define ROOT_SIG_ERR_ALGORITHM 2
#define ROOT_SIG_ERR_KID_MISMATCH 3
#define ROOT_SIG_ERR_DODAGID_MISMATCH 4
#define ROOT_SIG_ERR_EXPIRED 5
#define ROOT_SIG_ERR_INSTANCE_MISMATCH 6
#define ROOT_SIG_ERR_VERSION_MISMATCH 7
#define ROOT_SIG_ERR_RANK_MISMATCH 8
#define ROOT_SIG_ERR_MOP_MISMATCH 9
#define ROOT_SIG_ERR_SIGNATURE 10

/** Decoded Root DIO Signature payload (CBOR map keys 1-7). */
struct root_dio_sig_payload {
	uint8_t dodag_id[16];
	uint8_t instance;
	uint8_t version;
	uint16_t rank;
	uint64_t expiry;
	uint64_t root_seq;
	uint8_t mop;
};

/** Decoded COSE_Sign1 Root DIO Signature. */
struct root_dio_sig {
	/** kid from the unprotected header (root's 8-byte IID). */
	uint8_t root_iid[8];
	struct root_dio_sig_payload payload;
	/** 48-byte Schnorr48 signature. */
	uint8_t signature[48];
};

/**
 * @brief Decode a CBOR-encoded COSE_Sign1 Root DIO Signature.
 *
 * Enforces the decode-time rules of the Python oracle from_cose_sign1:
 * tag-18 4-element array, protected-header algorithm -65537, 8-byte kid,
 * 48-byte signature, payload keys 1-7 with strict types, no trailing bytes.
 *
 * @param data  COSE_Sign1 wire bytes
 * @param len   Length of data
 * @param out   Output structure
 * @return ROOT_SIG_OK, or -ROOT_SIG_ERR_DECODE / -ROOT_SIG_ERR_ALGORITHM
 */
int root_dio_sig_decode(const uint8_t *data, size_t len,
			struct root_dio_sig *out);

/**
 * @brief Structural checks that need only the signer pubkey and the clock.
 *
 * kid-to-IID binding, DODAGID-to-pubkey binding, expiry, and DIO header
 * cross-checks. Signature verification and replay consumption layer on top
 * (bead b7z9.37.2.2(b)).
 *
 * @param sig             Decoded signature
 * @param pubkey          32-byte signer public key
 * @param pubkey_len      Must be 32
 * @param now_unix        Current Unix timestamp
 * @param dio_dodag_id    DODAGID from the carrying DIO
 * @param dio_instance    RPLInstanceID from the carrying DIO
 * @param dio_version     DODAGVersionNumber from the carrying DIO
 * @param dio_rank        Rank from the carrying DIO
 * @param dio_mop         MOP from the carrying DIO
 * @return ROOT_SIG_OK, or a ROOT_SIG_ERR_* failure reason
 */

/**
 * @brief Verify the Schnorr48 signature over the rebuilt COSE Sig_structure.
 *
 * Rebuilds Sig_structure with the CANONICAL protected header
 * (a1013a00010000), hashes it with the injected sha256 (digest = SHA-256 of
 * the structure, matching python sha256(sig_structure)), and verifies via
 * schnorr48_verify. Byte-parity with the committed vectors' sig_structure
 * field.
 *
 * @param sig      Decoded signature
 * @param pubkey   32-byte signer public key
 * @param sha256   Hash function: (input, len, out[32]) returning 0 on success
 * @return ROOT_SIG_OK, or -ROOT_SIG_ERR_SIGNATURE on verification failure
 */
int root_dio_sig_verify_signature(const struct root_dio_sig *sig,
				  const uint8_t *pubkey,
				  int (*sha256)(const uint8_t *input,
						size_t len, uint8_t out[32]));
int root_dio_sig_verify_structural(
	const struct root_dio_sig *sig, const uint8_t *pubkey, size_t pubkey_len,
	uint64_t now_unix, const uint8_t *dio_dodag_id, uint8_t dio_instance,
	uint8_t dio_version, uint16_t dio_rank, uint8_t dio_mop);

#endif /* LICHEN_RPL_ROOT_DIO_SIG_H */
