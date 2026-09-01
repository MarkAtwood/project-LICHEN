/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file tdma.c
 * @brief LICHEN TDMA slot scheduling (gateway-centric mode)
 *
 * Implements hash-based slot computation and TDMA context management
 * for coordinated capacity protocol (CCP). Enabled via CONFIG_LICHEN_TDMA.
 */

#include <lichen/link_ctx.h>
#include <lichen/link.h>
#include <lichen/errno.h>
#include <string.h>
#include <stdbool.h>

#ifdef CONFIG_LICHEN_TDMA

static bool guard_budget_add(uint64_t *total, uint64_t value)
{
	if (UINT64_MAX - *total < value) {
		return false;
	}

	*total += value;
	return true;
}

bool lichen_tdma_guard_budget_sufficient(uint64_t guard,
					 uint64_t local_bound,
					 uint64_t peer_bound,
					 uint64_t local_jitter,
					 uint64_t peer_jitter,
					 uint64_t propagation,
					 uint64_t margin)
{
	uint64_t required = 0U;

	/* Add each independent uncertainty term explicitly.  Saturating or
	 * wrapping the requirement could incorrectly approve an unsafe schedule,
	 * so any overflow rejects the budget. */
	return guard_budget_add(&required, local_bound) &&
	       guard_budget_add(&required, peer_bound) &&
	       guard_budget_add(&required, local_jitter) &&
	       guard_budget_add(&required, peer_jitter) &&
	       guard_budget_add(&required, propagation) &&
	       guard_budget_add(&required, margin) && guard >= required;
}

uint8_t lichen_tdma_compute_slot(const uint8_t eui64[8], uint32_t sfn, uint8_t num_slots)
{
	if (num_slots == 0) num_slots = 8;
	return (uint8_t)((lichen_hash_32(eui64, 8) + sfn) % num_slots);
}

bool lichen_slot_map_validate(const uint8_t *slots, size_t len,
			      uint8_t num_slots)
{
	if (slots == NULL && len > 0) {
		return false;
	}
	for (size_t i = 0; i < len; i++) {
		/* Bounds: every entry must name a real slot. */
		if (slots[i] >= num_slots) {
			return false;
		}
		/* Strictly ascending: sorted, no duplicates. */
		if (i > 0 && slots[i] <= slots[i - 1]) {
			return false;
		}
	}
	return true;
}

int lichen_tdma_init(struct lichen_tdma_ctx *tdma, struct lichen_link_ctx *ctx)
{
	if (tdma == NULL || ctx == NULL) return -EINVAL;
	/* Spec/02a §2a.2: Slot = (fnv1a32(EUI64) + u32(SFN)) mod n over the
	 * beacon SFN.  ctx->epoch is the key-rotation counter and MUST NOT
	 * enter the slot hash.  No SFN exists before sync, so derive the
	 * placeholder from the SFN-0 baseline, consistent with the
	 * superframe = 0 default set below; peers that also lack SFN
	 * information converge on the same schedule position.  On the first
	 * valid beacon lichen_link_set_slot() installs the real
	 * hash(EUI64) + SFN derived slot. */
	uint8_t slot = lichen_tdma_compute_slot(ctx->eui64, 0u, 8);
	tdma->slot = slot;
	tdma->n_slots = 8;
	tdma->superframe = 0;
	tdma->slot_duration = LICHEN_TDMA_SLOT_MS;
	memcpy(tdma->eui64, ctx->eui64, sizeof(tdma->eui64));
	tdma->synced = false;
	tdma->ccp_state = LICHEN_CCP_UNJOINED;
	tdma->missed_beacons = 0;
	tdma->desync_state = LICHEN_DESYNC_SYNCED;
	tdma->desync_consecutive_valid = 0;
	tdma->desync_missed_superframes = 0;
	return 0;
}

enum lichen_desync_state
lichen_desync_on_sfn_wrap(struct lichen_tdma_ctx *tdma, bool time_valid)
{
	if (tdma == NULL) return LICHEN_DESYNC_DESYNCED;

	/* Spec/09 14.7: SFN wrap with an invalid time provider drops a
	 * SYNCED node to DESYNCED. No-op in DESYNCED/RECOVERING. */
	if (!time_valid && tdma->desync_state == LICHEN_DESYNC_SYNCED) {
		tdma->desync_state = LICHEN_DESYNC_DESYNCED;
		tdma->desync_consecutive_valid = 0;
		tdma->desync_missed_superframes = 0;
	}
	return tdma->desync_state;
}

enum lichen_desync_state lichen_desync_on_beacon(struct lichen_tdma_ctx *tdma,
						  bool valid)
{
	if (tdma == NULL) return LICHEN_DESYNC_DESYNCED;

	if (tdma->desync_state == LICHEN_DESYNC_DESYNCED && valid) {
		tdma->desync_state = LICHEN_DESYNC_RECOVERING;
		tdma->desync_consecutive_valid = 1;
		tdma->desync_missed_superframes = 0;
	} else if (tdma->desync_state == LICHEN_DESYNC_RECOVERING) {
		if (valid) {
			tdma->desync_consecutive_valid++;
			tdma->desync_missed_superframes = 0;
			if (tdma->desync_consecutive_valid >=
			    LICHEN_DESYNC_RECOVERY_BEACONS) {
				tdma->desync_state = LICHEN_DESYNC_SYNCED;
				tdma->desync_consecutive_valid = 0;
			}
		} else {
			tdma->desync_state = LICHEN_DESYNC_DESYNCED;
			tdma->desync_consecutive_valid = 0;
			tdma->desync_missed_superframes = 0;
		}
	}
	return tdma->desync_state;
}

enum lichen_desync_state
lichen_desync_on_missed_superframe(struct lichen_tdma_ctx *tdma)
{
	if (tdma == NULL) return LICHEN_DESYNC_DESYNCED;

	/* Bounded RECOVERING listen timeout: 3 superframes (RECOMMENDED,
	 * spec/09 14.7). No-op outside RECOVERING. */
	if (tdma->desync_state != LICHEN_DESYNC_RECOVERING) {
		return tdma->desync_state;
	}
	tdma->desync_missed_superframes++;
	if (tdma->desync_missed_superframes >=
	    LICHEN_TDMA_BEACON_TIMEOUT_SUPERFRAMES) {
		tdma->desync_state = LICHEN_DESYNC_DESYNCED;
		tdma->desync_consecutive_valid = 0;
		tdma->desync_missed_superframes = 0;
	}
	return tdma->desync_state;
}

int lichen_ccp_fsm_event(struct lichen_tdma_ctx *tdma, enum lichen_ccp_event event, uint8_t missed)
{
	if (tdma == NULL) return -EINVAL;

	/* CCP FSM per spec/09-packets-timing.md section 14.8 and tdma_ccp_fsm.json */
	switch (tdma->ccp_state) {
	case LICHEN_CCP_UNJOINED:
		if (event == LICHEN_CCP_EVENT_INIT) {
			tdma->ccp_state = LICHEN_CCP_ACQUIRING;
			tdma->missed_beacons = 0;
		}
		break;

	case LICHEN_CCP_ACQUIRING:
		if (event == LICHEN_CCP_EVENT_VALID_BEACON) {
			tdma->ccp_state = LICHEN_CCP_SYNCED;
			tdma->synced = true;
			tdma->missed_beacons = 0;
		}
		break;

	case LICHEN_CCP_SYNCED:
		if (event == LICHEN_CCP_EVENT_BEACON_IN_SLOT) {
			/* Stay SYNCED, reset missed counter */
			tdma->missed_beacons = 0;
		} else if (event == LICHEN_CCP_EVENT_MISSED_BEACON) {
			tdma->missed_beacons = missed;
			/* >3 missed beacons triggers DRIFTING */
			if (missed > LICHEN_TDMA_MISSED_BEACON_THRESHOLD) {
				tdma->ccp_state = LICHEN_CCP_DRIFTING;
				tdma->synced = false;
			}
		} else if (event == LICHEN_CCP_EVENT_RPL_VERSION) {
			tdma->ccp_state = LICHEN_CCP_DRIFTING;
			tdma->synced = false;
			/* Spec/02a 2a.5.4 R-02a-045/022: an RPL version change
			 * MUST reset the SFN relative to the new root
			 * (python on_version_change sfn_reset=True). The
			 * SFN-0 placeholder slot (own EUI64, copied at init)
			 * is the retained baseline; the real hash(EUI64) +
			 * SFN slot is installed by the next valid beacon.
			 * Also clear desync recovery counters that depended
			 * on the prior version (2a.5.4 step 2). */
			tdma->superframe = 0;
			tdma->slot =
				lichen_tdma_compute_slot(tdma->eui64, 0u, tdma->n_slots);
			tdma->desync_consecutive_valid = 0;
			tdma->desync_missed_superframes = 0;
		}
		break;

	case LICHEN_CCP_DRIFTING:
		if (event == LICHEN_CCP_EVENT_VALID_BEACON) {
			tdma->ccp_state = LICHEN_CCP_ACQUIRING;
			tdma->missed_beacons = 0;
		} else if (event == LICHEN_CCP_EVENT_INVALID_BEACON) {
			/* Stay DRIFTING */
		}
		break;

	case LICHEN_CCP_REJOINING:
		if (event == LICHEN_CCP_EVENT_DAO_ACK_SLOT) {
			tdma->ccp_state = LICHEN_CCP_SYNCED;
			tdma->synced = true;
			tdma->missed_beacons = 0;
		}
		break;
	}

	return 0;
}

int lichen_link_set_slot(struct lichen_link_ctx *ctx, struct lichen_tdma_ctx *tdma, uint8_t slot_id, uint8_t n_slots, uint32_t sfn)
{
	if (tdma == NULL) return -EINVAL;
	/* Sentinel 0xff requests auto-derivation below, which requires a
	 * context to hash; storing the raw sentinel would leave
	 * tdma_tx_allowed() computing offsets against slot 0xff forever. */
	if (slot_id == 0xff && ctx == NULL) return -EINVAL;
	if (slot_id == 0xff) {
		/* Spec/02a §2a.2: auto-derivation hashes the beacon SFN
		 * carried by the sfn argument, never ctx->epoch (the u8
		 * key-rotation counter) — substituting epoch desynchronizes
		 * this node's slot from every peer deriving per the spec
		 * formula from the same beacon. */
		slot_id = lichen_tdma_compute_slot(ctx->eui64, sfn, n_slots ? n_slots : 8);
	}
	tdma->slot = slot_id;
	tdma->n_slots = n_slots ? n_slots : 8;
	tdma->superframe = sfn;
	tdma->slot_duration = LICHEN_TDMA_SLOT_MS;
	tdma->synced = true;
	return 0;
}

bool lichen_slot_map_tx_allowed(const uint8_t *slot_map, size_t len,
				uint8_t current_slot, uint8_t num_slots)
{
	if (current_slot >= num_slots) {
		return false;
	}
	if (slot_map == NULL) {
		return false;
	}
	for (size_t i = 0; i < len; i++) {
		if (slot_map[i] == current_slot) {
			return true;
		}
	}
	return false;
}

bool tdma_tx_allowed(const struct lichen_tdma_ctx *tdma, uint32_t now_ms)
{
	if (tdma == NULL || !tdma->synced) return true;
	uint32_t d = tdma->slot_duration;

	/* Compute the schedule position in uint64_t so the superframe
	 * * n_slots * d product never silently truncates mid-expression,
	 * then reduce back into the uint32_t domain per spec/02a §2a.2
	 * ("for SFN wrap-around, all nodes MUST compute using unsigned
	 * 32-bit arithmetic, modulo 0x100000000").  Reduction is exact:
	 * unsigned multiply/add are homomorphic modulo 2^32, so the low 32
	 * bits equal the wrapped in-register result for every input,
	 * including SFNs whose true position far exceeds 2^32 ms.  Keeping
	 * the widened intermediates only removes the overflow-ordering
	 * hazard if slot constants ever grow past what one register holds.
	 * The offset compare below deliberately stays mod 2^32 across the
	 * clock transition; no clamping is applied to either side. */
	uint64_t sched_pos = (uint64_t)tdma->superframe *
			     (uint64_t)(uint8_t)tdma->n_slots * (uint64_t)d +
			     (uint64_t)tdma->slot * (uint64_t)d;
	uint32_t slot_start = (uint32_t)sched_pos;

	/* Spec/02a §2a.4: the data window begins at the slot start and ends
	 * before the single trailing guard — TX window is
	 * [slot_start, slot_start + d - g), no leading-edge tolerance.
	 * Offset arithmetic modulo 2^32 keeps this wrap-safe across u32
	 * clock / superframe transitions: times before slot_start map to
	 * huge unsigned offsets and are rejected, which is exactly the
	 * current<start rejection the Python sim (TDMAScheduler.is_tx_allowed)
	 * and Rust (tdma_clock::tx_allowed) perform with unbounded /
	 * saturating arithmetic. */
	if (d <= LICHEN_TDMA_GUARD_MS) {
		return false; /* degenerate timing: window is entirely guard */
	}
	return ((uint32_t)(now_ms - slot_start)) < (d - LICHEN_TDMA_GUARD_MS);
}

#endif /* CONFIG_LICHEN_TDMA */
