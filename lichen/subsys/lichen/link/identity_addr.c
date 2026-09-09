/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file identity_addr.c
 * @brief Key-derived LICHEN identity address helpers
 *
 * Defined in the link module so they are built for every LICHEN image,
 * independent of CONFIG_LICHEN_IPV6 (whose l2/ipv6_addr.c hosted one
 * definition) and CONFIG_LICHEN_COAP_KEYS (whose coap_keys_format.c
 * hosted the other). App identity and similar non-CoAP, non-IPv6 images
 * link these derivations without either optional subsystem.
 *
 * Prototypes are repeated locally instead of including <lichen/link_ctx.h>
 * or <lichen/coap_keys.h>, per the hash32.c pattern: keep this TU buildable
 * with only Monocypher on the include path.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <monocypher.h>
#include <monocypher-ed25519.h>

int lichen_key_pubkey_to_iid(const uint8_t pubkey[32], uint8_t iid[8]);

int lichen_key_pubkey_to_iid(const uint8_t pubkey[32], uint8_t iid[8])
{
	uint8_t hash[64];

	if (pubkey == NULL || iid == NULL) {
		return -EINVAL;
	}

	/* IID = SHA-512(pubkey)[0:8], with the U/L bit cleared.  This is the
	 * canonical LICHEN/Yggdrasil identity derivation from spec 8.5/8.7 and
	 * test/vectors/yggdrasil-derivation.json.  It must not silently fall back
	 * to raw key bytes or SHA-256 when a crypto Kconfig option is absent.
	 *
	 * QUARANTINED-PENDING-UPSTREAM-MIGRATION: this SHA-512 profile is rejected
	 * by the upstream-yggdrasil-addressing decision in spec/decisions.jsonl
	 * (routable address MUST equal upstream AddrForKey); pinned only until the
	 * C derivation migrates.  Do not extend.  Bead project-LICHEN-worker6-q6ko.
	 */
	crypto_sha512(hash, pubkey, 32);
	memcpy(iid, hash, 8);
	iid[0] &= (uint8_t)~0x02U;
	crypto_wipe(hash, sizeof(hash));

	return 0;
}

int lichen_identity_ygg_addr_from_ed25519(const uint8_t *pubkey,
					  uint8_t ygg_addr[16]);

int lichen_identity_ygg_addr_from_ed25519(const uint8_t *pubkey,
					  uint8_t ygg_addr[16])
{
	uint8_t inv[32];
	uint8_t temp[32];
	size_t temp_len = 0;
	size_t copy_len;
	uint16_t ones = 0;
	uint8_t bits = 0;
	unsigned int nbits = 0;
	bool done = false;
	size_t i;

	if (pubkey == NULL || ygg_addr == NULL) {
		return -EINVAL;
	}

	/* Upstream Yggdrasil AddrForKey (yggdrasil-go@422836ee
	 * src/address/address.go), per spec/decisions.jsonl
	 * upstream-yggdrasil-addressing. NO hashing:
	 *   1. Invert all 32 pubkey bytes.
	 *   2. addr[0] = 0x02; addr[1] = count of leading 1 bits in the
	 *      inverted key (uint8 wrap at 256, as upstream's byte counter).
	 *   3. Skip those 1s and the first 0 bit; pack the remaining bits
	 *      MSB-first into WHOLE bytes, discarding the trailing partial
	 *      byte; copy into addr[2:16], zero tail.
	 * The SHA-512 IID does NOT appear in the routable address; the IID
	 * stays link-local-only (lichen_key_pubkey_to_iid, unchanged).
	 */
	for (i = 0; i < sizeof(inv); i++) {
		inv[i] = (uint8_t)~pubkey[i];
	}
	for (i = 0; i < 8 * sizeof(inv); i++) {
		uint8_t bit = (uint8_t)((inv[i / 8] >> (7 - (i % 8))) & 0x01U);

		if (!done && bit != 0U) {
			ones++;
			continue;
		}
		if (!done) {
			done = true;
			continue;
		}
		bits = (uint8_t)((bits << 1) | bit);
		nbits++;
		if (nbits == 8U) {
			nbits = 0;
			temp[temp_len++] = bits;
		}
	}

	ygg_addr[0] = 0x02;
	ygg_addr[1] = (uint8_t)ones;
	copy_len = temp_len < 14 ? temp_len : 14;
	memcpy(&ygg_addr[2], temp, copy_len);
	memset(&ygg_addr[2 + copy_len], 0, 14 - copy_len);
	crypto_wipe(inv, sizeof(inv));
	crypto_wipe(temp, sizeof(temp));
	return 0;
}
