/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file rpl_sf_assignment.h
 * @brief ASSIGNED_SF (DIO option 0x14) TLV codec and effective-TX-SF
 *	  resolution (C port of rust lichen-core sf_assignment.rs,
 *	  spec/02-physical-link.md 3.4 R-02-008; bead skab.1).
 *
 * Priority per spec 3.4:
 *   1. Gateway-assigned ASSIGNED_SF (7..=12) -> MUST use
 *   2. Stateless hash fallback (joined): 7 + (hash_32(IID) % 6)
 *   3. No assignment -> SF10 (join-based initial default)
 */

#ifndef LICHEN_RPL_SF_ASSIGNMENT_H_
#define LICHEN_RPL_SF_ASSIGNMENT_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define LICHEN_DIO_OPTION_ASSIGNED_SF 0x14u
#define LICHEN_SF_MIN 7u
#define LICHEN_SF_MAX 12u

/** Per-node SF assignment state (Rust SfAssignmentState parity). */
struct lichen_rpl_sf_assignment {
	/* Gateway-assigned SF from the latest ASSIGNED_SF DIO option;
	 * 0 when absent. */
	uint8_t assigned_sf_dio;
	bool joined;
};

/** Initialize to the no-assignment, not-joined state. */
void lichen_rpl_sf_assignment_init(struct lichen_rpl_sf_assignment *s);

/** True when sf is an assignable spreading factor (7..=12). */
bool lichen_rpl_sf_is_valid(uint8_t sf);

/**
 * Build an ASSIGNED_SF DIO option TLV: out = [0x14, 1, sf].
 * Returns false when sf is not in 7..=12 or out is NULL.
 */
bool lichen_rpl_sf_assignment_make(uint8_t sf, uint8_t out[3]);

/**
 * Parse an ASSIGNED_SF DIO option TLV. Returns the SF (7..=12) when
 * data is [0x14, 1, valid_sf]; 0 otherwise (wrong type, length, or SF).
 */
uint8_t lichen_rpl_sf_assignment_parse(const uint8_t *data, size_t len);

/**
 * Resolve the effective TX SF per spec 3.4 priority (see header top).
 */
uint8_t lichen_rpl_sf_effective(const struct lichen_rpl_sf_assignment *s,
				const uint8_t iid[8]);

#endif /* LICHEN_RPL_SF_ASSIGNMENT_H_ */
