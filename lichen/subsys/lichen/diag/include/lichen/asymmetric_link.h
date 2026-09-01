/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file asymmetric_link.h
 * @brief Fleet asymmetric-link detector (diag.10, spec 02a 2a.10.5 family).
 *
 * Tracks per-peer TX and RX frame counts over a rolling window. When the
 * TX:RX ratio exceeds 10:1 with at least 10 TX frames over the full 5-minute
 * evaluation window, the peer's link is asymmetric: our frames reach them
 * but theirs rarely return (or vice versa). Non-reciprocal links break RPL
 * parent selection, so the detector reports both IIDs for operator action.
 *
 * Freestanding (no kernel dependencies): time is injected by the caller.
 */

#ifndef LICHEN_ASYMMETRIC_LINK_H_
#define LICHEN_ASYMMETRIC_LINK_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Evaluation window (ms). Spec diag.10: 5 minutes. */
#define LICHEN_ASYM_WINDOW_MS 300000U

/** Minimum TX count before the ratio test is meaningful. */
#define LICHEN_ASYM_MIN_TX 10U

/** TX:RX ratio threshold that flags an asymmetric link. */
#define LICHEN_ASYM_RATIO 10U

/** Maximum simultaneously tracked peers (bounded, no_std-safe). */
#define LICHEN_ASYM_MAX_PEERS 16

/** One peer's TX/RX counters. */
struct lichen_asym_peer {
	uint8_t iid[8];   /**< Peer link-local IID */
	uint32_t tx;      /**< Frames we sent to this peer */
	uint32_t rx;      /**< Frames we received from this peer */
	uint64_t first_ms; /**< Window start for this peer */
};

/** Asymmetric-link detector state. */
struct lichen_asym_link_detector {
	struct lichen_asym_peer peers[LICHEN_ASYM_MAX_PEERS];
	size_t count;
	uint32_t tx_threshold;   /**< LICHEN_ASYM_MIN_TX */
	uint32_t ratio;          /**< LICHEN_ASYM_RATIO */
	uint64_t window_ms;      /**< LICHEN_ASYM_WINDOW_MS */
};

/** Reset all counters (call at init). */
void lichen_asym_link_init(struct lichen_asym_link_detector *det);

/** Record one frame transmitted TO @p iid. */
void lichen_asym_link_record_tx(struct lichen_asym_link_detector *det,
				const uint8_t iid[8], int64_t now_ms);

/** Record one frame received FROM @p iid. */
void lichen_asym_link_record_rx(struct lichen_asym_link_detector *det,
				const uint8_t iid[8], int64_t now_ms);

/**
 * @brief Evaluate all tracked peers.
 *
 * A peer is asymmetric when tx >= tx_threshold and rx * ratio < tx over the
 * evaluation window (i.e. we transmit 10x more than we receive). Returns
 * the number of asymmetric peers found (0..count); their IIDs are copied
 * into @p out_iids (up to @p out_cap entries).
 */
size_t lichen_asym_link_evaluate(const struct lichen_asym_link_detector *det,
				 uint8_t out_iids[][8], size_t out_cap,
				 int64_t now_ms);

#endif /* LICHEN_ASYMMETRIC_LINK_H_ */
