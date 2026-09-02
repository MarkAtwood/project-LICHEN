/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Multi-root conflict resolution tests (spec 02a 2a.5, bead b7z9.24.3):
 * RootCandidate selection precedence and the signature fail-closed filter.
 * Reference implementations: python slot_coordination.py select_root,
 * rust multi_instance.rs RootCandidate. */

#include <lichen/multi_root.h>

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

static struct lichen_root_candidate cand(uint8_t iid_last, int32_t pref,
					 uint32_t stratum, float rssi,
					 float snr, bool sig)
{
	struct lichen_root_candidate c = {
		.dodag_preference = pref,
		.stratum = stratum,
		.rssi_ema = rssi,
		.snr_ema = snr,
		.signature_valid = sig,
	};

	memset(c.eui64, 0, sizeof(c.eui64));
	c.eui64[7] = iid_last;
	return c;
}

int main(void)
{
	/* 1. Empty candidate list -> NULL. */
	CHECK(lichen_multi_root_select(NULL, 0U) == NULL,
	      "empty list selects no root");

	/* 2. All candidates signature-invalid -> NULL (2a.5.1 fail-closed). */
	struct lichen_root_candidate all_bad[] = {
		cand(0x10, 5, 0, -50.0f, 10.0f, false),
		cand(0x11, 5, 0, -50.0f, 10.0f, false),
	};
	CHECK(lichen_multi_root_select(all_bad, 2U) == NULL,
	      "all-invalid signatures select no root");

	/* 3. Single valid candidate -> itself. */
	struct lichen_root_candidate solo[] = {
		cand(0x20, 0, 3, -80.0f, 5.0f, true),
	};
	CHECK(lichen_multi_root_select(solo, 1U) == &solo[0],
	      "single valid candidate wins");

	/* 4. Preference decides: higher preference wins even with a worse
	 * stratum, worse link, and larger IID. */
	struct lichen_root_candidate pref[] = {
		cand(0x01, 1, 0, -50.0f, 20.0f, true), /* better tiebreak etc */
		cand(0x02, 2, 4, -110.0f, -15.0f, true), /* higher pref wins */
	};
	CHECK(lichen_multi_root_select(pref, 2U) == &pref[1],
	      "higher DODAG preference wins");

	/* 5. Stratum decides when preference ties: lower stratum wins. */
	struct lichen_root_candidate strat[] = {
		cand(0x01, 3, 4, -50.0f, 20.0f, true),
		cand(0x02, 3, 1, -110.0f, -15.0f, true), /* lower stratum wins */
	};
	CHECK(lichen_multi_root_select(strat, 2U) == &strat[1],
	      "lower stratum wins on preference tie");

	/* 6. Combined link score decides: RSSI weighted 2:1 over SNR.
	 * A: 2*(-70) + (-30) = -170. B: 2*(-80) + 0 = -160. B has the
	 * LOWER rssi but the higher weighted score, so B wins. */
	struct lichen_root_candidate link[] = {
		cand(0x01, 3, 1, -70.0f, -30.0f, true),
		cand(0x02, 3, 1, -80.0f, 0.0f, true),
	};
	CHECK(lichen_multi_root_select(link, 2U) == &link[1],
	      "combined RSSI+SNR score (2:1) decides");

	/* 7. EUI-64 tiebreak: equal everything -> numerically smaller IID. */
	struct lichen_root_candidate tie[] = {
		cand(0x42, 3, 1, -70.0f, -20.0f, true),
		cand(0x17, 3, 1, -70.0f, -20.0f, true),
	};
	CHECK(lichen_multi_root_select(tie, 2U) == &tie[1],
	      "smaller IID wins the tiebreak");

	/* 8. Signature filter: an invalid candidate with a winning key
	 * loses to a valid candidate. */
	struct lichen_root_candidate spoof[] = {
		cand(0x01, 9, 0, -30.0f, 30.0f, false), /* best key, invalid */
		cand(0x02, 0, 7, -120.0f, -20.0f, true), /* only valid one */
	};
	CHECK(lichen_multi_root_select(spoof, 2U) == &spoof[1],
	      "invalid signature is discarded before selection (2a.5.1)");

	/* 9. compare_iid: numeric big-endian ordering. */
	static const uint8_t small[8] = {0, 0, 0, 0, 0, 0, 0, 0x01};
	static const uint8_t large[8] = {0, 0, 0, 0, 0, 0, 0, 0x02};
	CHECK(lichen_multi_root_compare_iid(small, large) == -1,
	      "compare_iid orders numerically");
	CHECK(lichen_multi_root_compare_iid(large, small) == 1,
	      "compare_iid orders numerically (reverse)");
	CHECK(lichen_multi_root_compare_iid(small, small) == 0,
	      "compare_iid equality");

	if (failures == 0) {
		printf("PASS: multi_root selection\n");
	}
	return failures == 0 ? 0 : 1;
}
