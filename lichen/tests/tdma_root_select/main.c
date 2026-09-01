/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/tdma_root_select.h>

#include <math.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			printf("FAIL: %s\n", msg);                             \
			failures++;                                            \
		}                                                              \
	} while (0)

static struct lichen_tdma_root_candidate make(const uint8_t eui64[8])
{
	struct lichen_tdma_root_candidate c;

	lichen_tdma_root_candidate_init(&c, eui64);
	return c;
}

int main(void)
{
	const uint8_t iid_a[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };
	const uint8_t iid_b[8] = { 0, 0, 0, 0, 0, 0, 0, 2 };
	const uint8_t iid_z[8] = { 0, 0, 0, 0, 0, 0, 0, 0 };

	/* Defaults are fail-closed. */
	struct lichen_tdma_root_candidate dflt = make(iid_a);
	CHECK(dflt.stratum == 255 && !dflt.signature_valid &&
		      dflt.rssi_ema == -120.0f && dflt.snr_ema == -20.0f,
	      "defaults match reference");
	CHECK(lichen_tdma_select_root(&dflt, 1) == NULL,
	      "invalid-signature-only candidate set selects NULL (R-02a-031)");

	/* IID comparison (R-02a-036/037/039). */
	struct lichen_tdma_root_candidate iid_z_cand = make(iid_z);
	struct lichen_tdma_root_candidate iid_a_cand = make(iid_a);
	CHECK(lichen_tdma_root_iid(&dflt) == 1, "iid big-endian decode");
	CHECK(lichen_tdma_root_compare(&iid_z_cand, &iid_a_cand) < 0,
	      "smaller IID wins tiebreak");
	CHECK(lichen_tdma_root_compare(&dflt, &dflt) == 0,
	      "identical candidates tie");

	/* DODAG preference dominates stratum and score (R-02a-032). */
	struct lichen_tdma_root_candidate hi_pref = make(iid_a);
	hi_pref.dodag_preference = 1;
	hi_pref.stratum = 200;
	hi_pref.rssi_ema = -100.0f;
	hi_pref.signature_valid = true;
	struct lichen_tdma_root_candidate lo_pref = make(iid_b);
	lo_pref.signature_valid = true;
	struct lichen_tdma_root_candidate cands_pref[] = { hi_pref, lo_pref };
	CHECK(lichen_tdma_select_root(cands_pref, 2) == &cands_pref[0],
	      "higher DODAG preference wins despite worse stratum/rssi");

	/* Stratum dominates score (R-02a-033). */
	struct lichen_tdma_root_candidate low_stratum = make(iid_a);
	low_stratum.stratum = 0;
	low_stratum.rssi_ema = -110.0f;
	low_stratum.signature_valid = true;
	struct lichen_tdma_root_candidate high_stratum = make(iid_b);
	high_stratum.stratum = 200;
	high_stratum.rssi_ema = -50.0f;
	high_stratum.signature_valid = true;
	struct lichen_tdma_root_candidate cands_stratum[] = { low_stratum,
							      high_stratum };
	CHECK(lichen_tdma_select_root(cands_stratum, 2) == &cands_stratum[0],
	      "lower stratum wins despite worse RSSI");

	/* Combined score: RSSI weighted 2:1 over SNR (R-02a-035). */
	struct lichen_tdma_root_candidate better_score = make(iid_a);
	better_score.rssi_ema = -80.0f;
	better_score.snr_ema = 0.0f; /* 2*-80 + 0 = -160 */
	better_score.signature_valid = true;
	struct lichen_tdma_root_candidate worse_score = make(iid_b);
	worse_score.rssi_ema = -70.0f; /* 2*-70 + -30 = -170 */
	worse_score.snr_ema = -30.0f;
	worse_score.signature_valid = true;
	struct lichen_tdma_root_candidate cands_score[] = { worse_score,
							    better_score };
	CHECK(lichen_tdma_select_root(cands_score, 2) == &cands_score[1],
	      "combined score 2:1 weighting decides");
	CHECK(lichen_tdma_root_combined_score(&better_score) == -160.0f,
	      "combined score formula");

	/* Score tie -> IID tiebreak (R-02a-036/037/039). */
	struct lichen_tdma_root_candidate tie_hi_iid = make(iid_a);
	tie_hi_iid.rssi_ema = -80.0f;
	tie_hi_iid.snr_ema = 0.0f; /* scores now tie at -160 */
	tie_hi_iid.signature_valid = true;
	struct lichen_tdma_root_candidate tie_lo_iid = make(iid_z);
	tie_lo_iid.rssi_ema = -80.0f;
	tie_lo_iid.snr_ema = 0.0f;
	tie_lo_iid.signature_valid = true;
	struct lichen_tdma_root_candidate cands_tie[] = { tie_hi_iid,
							  tie_lo_iid };
	CHECK(lichen_tdma_select_root(cands_tie, 2) == &cands_tie[1],
	      "equal score resolves to smaller IID");

	/* Invalid signature is discarded even when otherwise best
	 * (R-02a-031..034: verified BEFORE criteria, no state transition). */
	tie_hi_iid.signature_valid = false;
	struct lichen_tdma_root_candidate cands_sig[] = { tie_hi_iid,
							  tie_lo_iid };
	CHECK(lichen_tdma_select_root(cands_sig, 2) == &cands_sig[1],
	      "invalid-signature candidate skipped");

	/* Empty candidate list. */
	CHECK(lichen_tdma_select_root(NULL, 0) == NULL, "empty list -> NULL");

	/* NaN RF metrics sanitize to worst-case defaults (Rust parity). */
	struct lichen_tdma_root_candidate nan_cand = make(iid_a);
	nan_cand.rssi_ema = NAN;
	nan_cand.snr_ema = NAN;
	nan_cand.signature_valid = true;
	struct lichen_tdma_root_candidate nan_cand_raw = nan_cand;
	struct lichen_tdma_root_candidate nan_rival = make(iid_b);
	nan_rival.rssi_ema = -119.0f; /* better than sanitized -120/-20 */
	nan_rival.signature_valid = true;
	lichen_tdma_root_candidate_sanitize(&nan_cand);
	struct lichen_tdma_root_candidate cands_nan[] = { nan_cand, nan_rival };
	CHECK(lichen_tdma_select_root(cands_nan, 2) == &cands_nan[1],
	      "NaN metrics sanitized to worst case, not selected");
	/* Non-finite (inf) poisoning also sanitizes to worst case. */
	struct lichen_tdma_root_candidate inf_cand = make(iid_a);
	inf_cand.rssi_ema = INFINITY;
	inf_cand.signature_valid = true;
	lichen_tdma_root_candidate_sanitize(&inf_cand);
	CHECK(inf_cand.rssi_ema == -120.0f, "inf RSSI sanitized");
	struct lichen_tdma_root_candidate inf_rival = make(iid_b);
	inf_rival.rssi_ema = -119.0f;
	inf_rival.signature_valid = true;
	struct lichen_tdma_root_candidate cands_inf[] = { inf_cand, inf_rival };
	CHECK(lichen_tdma_select_root(cands_inf, 2) == &cands_inf[1],
	      "inf-poisoned candidate not selected");
	struct lichen_tdma_root_candidate inf_cand_raw = inf_cand;
	inf_cand_raw.rssi_ema = INFINITY;
	struct lichen_tdma_root_candidate cands_inf_raw[] = { inf_cand_raw,
							      inf_rival };
	CHECK(lichen_tdma_select_root(cands_inf_raw, 2) == &cands_inf_raw[1],
	      "inf metrics lose the comparison even unsanitized");

	/* Defensively, compare() also treats NaN as worst-case (Rust
	 * sanitizes at construction; both paths yield the same outcome). */
	struct lichen_tdma_root_candidate cands_nan_raw[] = { nan_cand_raw,
							      nan_rival };
	CHECK(lichen_tdma_select_root(cands_nan_raw, 2) == &cands_nan_raw[1],
	      "NaN metrics lose the comparison even unsanitized");

	if (failures == 0) {
		printf("PASS: tdma_root_select\n");
		return 0;
	}
	printf("FAILURES: %d\n", failures);
	return 1;
}
