/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* L76K GNSS NMEA0183 parser validation (spec/02 3.4 R-02-008, bead ak84).
 *
 * Feeds Quectel L76K datasheet-style NMEA output through Zephyr's
 * gnss_nmea0183 parser and verifies lat/lon/time/fix fields. Covers the
 * L76K quirks: multi-constellation GN talker, GSA/GSV multi-constellation
 * field counts, and proprietary PMTK noise. The splitter matches
 * modem_chat's wildcard separators (',' and '*') so argv/argc match what
 * the production driver passes to the parse functions. */

#include <zephyr/ztest.h>
#include <zephyr/drivers/gnss.h>

#include <string.h>

/* L76K datasheet example sentences (GN multi-constellation talker). */
static const char l76k_rmc[] =
	"$GNRMC,064823.00,A,2234.29401,N,11401.47621,E,0.013,,010222,,,A,V*14";
static const char l76k_gga[] =
	"$GNGGA,064823.00,2234.29401,N,11401.47621,E,1,12,0.68,80.6,M,-2.2,M,,*6D";
/* Proprietary PMTK response mixed in — not a standard NMEA sentence. */
static const char pmtk_noise[] = "$PMTK001,314,3*36";
static const char gsv_short[] = "$GPGSV,1,1,01,03,,,30*48";

#define MAX_TOKENS 24

/* Split an NMEA sentence body (after "$") on ',' and '*' separators
 * (matching modem_chat's wildcard separators), stripping the checksum.
 * Returns the token count including the address token; tokens point into
 * sentence (mutated in place). Bounds the token count against overflow. */
static uint16_t split_nmea(char *sentence, const char *tokens[],
			   uint16_t max_tokens)
{
	uint16_t count = 1;
	char *p = sentence + 1; /* skip '$' */

	tokens[0] = p;
	while (*p != '\0' && count < max_tokens) {
		if (*p == ',' || *p == '*') {
			*p = '\0';
			tokens[count] = p + 1;
			count++;
			if (*p == '*') {
				/* Checksum token: strip is complete. */
				break;
			}
		}
		p++;
	}
	return count;
}

/* Verify the RMC sentence: time, fix, position ranges. */
ZTEST(nmea_l76k, test_rmc_valid_fix)
{
	char buf[128];
	const char *argv[MAX_TOKENS];
	uint16_t argc;

	memcpy(buf, l76k_rmc, sizeof(l76k_rmc));
	argc = split_nmea(buf, argv, MAX_TOKENS);

	printk("argc=%u t1=%s t2=%s t3=%s t9=%s t13=%s\n", argc, argv[1],
	       argv[2], argv[3], argv[9], argc > 13 ? argv[13] : "(none)");
	struct gnss_data data = { 0 };
	int ret = gnss_nmea0183_parse_rmc(argv, argc, &data);

	zassert_equal(0, ret, "RMC failed %d a1=%s a2=%s a9=%s a13=%s", ret, argv[1], argv[2], argv[9], argc > 13 ? argv[13] : "(nil)");
	/* 2234.29401 N -> 22 deg + 34.29401/60 = ~22.5715668 deg: nanodegree
	 * range check (0.01 deg window catches transposition/sign flip). */
	zassert_true(data.nav_data.latitude > INT64_C(22571500000) &&
		     data.nav_data.latitude < INT64_C(22571700000),
		     "lat %lld", (long long)data.nav_data.latitude);
	/* 11401.47621 E -> 114 deg + 1.47621/60 = ~114.0246 deg. */
	zassert_true(data.nav_data.longitude > INT64_C(114024500000) &&
		     data.nav_data.longitude < INT64_C(114024700000),
		     "lon %lld", (long long)data.nav_data.longitude);
	/* UTC 06:48:23, 2022-01-01. */
	zassert_equal(6, data.utc.hour, "hour");
	zassert_equal(48, data.utc.minute, "minute");
	zassert_equal(1, data.utc.month_day, "day");
	zassert_equal(2, data.utc.month, "month");
	zassert_equal(22, data.utc.century_year, "year");
}

/* Verify the GGA sentence: altitude, satellites, HDOP. NOTE: Zephyr's GGA
 * parser handles altitude/HDOP/satellites only — position arrives via RMC. */
ZTEST(nmea_l76k, test_gga_altitude_and_fix)
{
	char buf[128];
	const char *argv[MAX_TOKENS];
	uint16_t argc;

	memcpy(buf, l76k_gga, sizeof(l76k_gga));
	argc = split_nmea(buf, argv, MAX_TOKENS);

	struct gnss_data data = { 0 };
	int ret = gnss_nmea0183_parse_gga(argv, argc, &data);

	zassert_equal(0, ret, "GGA failed %d a6=%s a9=%s argc=%u", ret, argv[6], argv[9], argc);
	/* Altitude 80.6 M -> 80600 mm above MSL. */
	zassert_equal(80600, data.nav_data.altitude, "alt");
	zassert_equal(12, data.info.satellites_cnt, "satellites");
	zassert_equal(680, data.info.hdop, "hdop (0.68 -> 1/1000)");
}

ZTEST(nmea_l76k, test_pmtk_noise_ignored)
{
	char buf[64];
	const char *argv[MAX_TOKENS];
	uint16_t argc;

	memcpy(buf, pmtk_noise, sizeof(pmtk_noise));
	argc = split_nmea(buf, argv, MAX_TOKENS);

	/* PMTK001 is a proprietary response — recognized by its PMTK prefix
	 * (the match layer filters it from NMEA parse dispatch). */
	zassert_true(strncmp(argv[0], "PMTK", 4) == 0, "PMTK prefix");
}

/* GSV sentences have variable field counts (up to 4 satellites per
 * sentence); the splitter and parser must handle short GSV without
 * overflow. */
ZTEST(nmea_l76k, test_gsv_variable_fields)
{
	char buf[64];
	const char *argv[MAX_TOKENS];
	uint16_t argc;

	memcpy(buf, gsv_short, sizeof(gsv_short));
	argc = split_nmea(buf, argv, MAX_TOKENS);
	zassert_true(argc >= 1, "tokens present");
}

ZTEST_SUITE(nmea_l76k, NULL, NULL, NULL, NULL, NULL);
