/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/schnorr48.h
 * @brief Schnorr-48 link signatures per draft-lichen-schnorr-00
 *
 * 48-byte deterministic Schnorr signatures over Ed25519:
 *   16-byte truncated challenge (e) || 32-byte response (s)
 *
 * Provides 128-bit security against forgery while saving 16 bytes
 * compared to standard Ed25519 signatures.
 */

#ifndef LICHEN_SCHNORR48_H_
#define LICHEN_SCHNORR48_H_

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Schnorr-48 signature length */
#define SCHNORR48_SIG_LEN 48

/** Ed25519 private key length */
#define SCHNORR48_PRIVKEY_LEN 32

/** Ed25519 public key length */
#define SCHNORR48_PUBKEY_LEN 32

/** Seed length for key derivation */
#define SCHNORR48_SEED_LEN 32

/**
 * @brief Derive an Ed25519 keypair from a 32-byte seed.
 *
 * @param[in]  seed    32-byte random seed
 * @param[out] privkey 32-byte private key (clamped scalar)
 * @param[out] pubkey  32-byte public key (compressed point)
 */
void schnorr48_derive_keypair(const uint8_t seed[32],
			      uint8_t privkey[32],
			      uint8_t pubkey[32]);

/**
 * @brief Sign a message with Schnorr-48.
 *
 * @param[in]  privkey  32-byte private key
 * @param[in]  pubkey   32-byte public key
 * @param[in]  msg      Message to sign
 * @param[in]  msg_len  Message length
 * @param[out] sig      48-byte signature output
 */
void schnorr48_sign(const uint8_t privkey[32],
		    const uint8_t pubkey[32],
		    const uint8_t *msg, size_t msg_len,
		    uint8_t sig[48]);

/**
 * @brief Verify a Schnorr-48 signature.
 *
 * @param[in] pubkey   32-byte public key
 * @param[in] msg      Signed message
 * @param[in] msg_len  Message length
 * @param[in] sig      48-byte signature
 * @return true if valid, false if invalid
 */
bool schnorr48_verify(const uint8_t pubkey[32],
		      const uint8_t *msg, size_t msg_len,
		      const uint8_t sig[48]);

/**
 * @brief Sign a LICHEN link-layer frame.
 *
 * Builds the signable data (epoch || seqnum || dst_addr || inner_payload)
 * and produces a 48-byte signature.
 *
 * @param[in]  epoch         Epoch byte
 * @param[in]  seqnum        Sequence number (big-endian in signable data)
 * @param[in]  dst_addr      Destination address
 * @param[in]  dst_addr_len  Address length
 * @param[in]  payload       Inner payload (without signature)
 * @param[in]  payload_len   Payload length
 * @param[in]  privkey       32-byte private key
 * @param[in]  pubkey        32-byte public key
 * @param[out] sig           48-byte signature output
 */
void schnorr48_sign_frame(uint8_t epoch, uint16_t seqnum,
			  const uint8_t *dst_addr, size_t dst_addr_len,
			  const uint8_t *payload, size_t payload_len,
			  const uint8_t privkey[32],
			  const uint8_t pubkey[32],
			  uint8_t sig[48]);

/**
 * @brief Verify a signed LICHEN link-layer frame.
 *
 * @param[in] epoch        Epoch byte
 * @param[in] seqnum       Sequence number
 * @param[in] dst_addr     Destination address
 * @param[in] dst_addr_len Address length
 * @param[in] payload      Full payload (inner || signature)
 * @param[in] payload_len  Full payload length (must be >= 48)
 * @param[in] pubkey       32-byte sender public key
 * @return true if valid, false if invalid
 */
bool schnorr48_verify_frame(uint8_t epoch, uint16_t seqnum,
			    const uint8_t *dst_addr, size_t dst_addr_len,
			    const uint8_t *payload, size_t payload_len,
			    const uint8_t pubkey[32]);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_SCHNORR48_H_ */
