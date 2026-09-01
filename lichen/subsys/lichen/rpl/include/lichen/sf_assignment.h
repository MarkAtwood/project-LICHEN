/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_RPL_SF_ASSIGNMENT_H_
#define LICHEN_RPL_SF_ASSIGNMENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Valid assigned SF range (spec 3.4: SF7..SF12). */
#define LICHEN_SF_MIN 7u
#define LICHEN_SF_MAX 12u

/**
 * @brief Parse an ASSIGNED_SF DIO option from a TLV buffer.
 *
 * Layout: [type=0x14, length=1, sf]. Mirrors Rust
 * sf_assignment.rs parse_assigned_sf_option.
 *
 * @param[in]  data TLV buffer (>= 3 bytes)
 * @param[in]  len  Buffer length
 * @param[out] sf   Assigned SF on success
 * @return true if a valid ASSIGNED_SF option was parsed
 */
bool lichen_sf_assignment_parse_option(const uint8_t *data, size_t len,
				       uint8_t *sf);

/**
 * @brief Resolve the effective TX SF per spec 3.4 priority.
 *
 * 1. Gateway-assigned SF in 7..12 -> MUST use.
 * 2. Hash-based fallback -> 7 + (hash_32(iid) % 6).
 * 3. Otherwise -> SF10.
 *
 * @param[in] assigned_sf Stored assignment (0 = none)
 * @param[in] joined      Whether the node has joined the DODAG
 * @param[in] iid         8-byte IID for the hash fallback
 * @return Effective spreading factor (7..12)
 */
uint8_t lichen_sf_assignment_effective(uint8_t assigned_sf, bool joined,
				       const uint8_t iid[8]);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_RPL_SF_ASSIGNMENT_H_ */
