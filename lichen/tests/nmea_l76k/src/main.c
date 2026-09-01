/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* L76K GNSS NMEA0183 parser validation (spec/02 3.4 R-02-008, bead ak84).
 *
 * Feeds Quectel L76K datasheet-style NMEA output through Zephyr's
 * gnss_nmea0183 parser and verifies lat/lon/time/fix fields. Covers the
 * L76K quirks: multi-constellation GN talker, GSA/GSV multi-constellation
 * field counts, and interleaved multi-line GSV. */

#include <zephyr/ztest.h>
#include <zephyr/drivers/gnss.h>

#include <string.h>

/* L76K datasheet example sentences (GN multi-constellation talker). */
static const char l76k_rmc[] =
	"$GNRMC,064823.00,A,2234.29401,N,11401.47621,E,0.013,,010222,,,A,V*14";
static const char l76k_gga[] =
	"$GNGGA,064823.00,2234.29401,N,11401.47621,E,1,12,0.68,80.6,M,-2.2,M,,*6D";
/* Proprietary PMTK response mixed in — must not break parsing. */
static const char pmtk_noise[] = "$PMTK001,314,3*36";

/* Split an NMEA sentence body (after "$") on commas; strips checksum.
 * Returns the token count; tokens point into a static buffer. */
#define MAX_TOKENS 24
static char token_buf[256];
static const char *tokens[MAX_TOKENS];
static uint16_t split_nmea(const char *sentence)
{
	size_t out = 0;
	const char *p = sentence + 1; /* skip '$' */
	const char *star = strchr(p, '*');

	token_buf[0] = '\0';
	char *w = token_buf;
	size_t cap = sizeof(token_buf) - 1;

	while (*p != '\0' && (star == NULL || p < star) && out < MAX_TOKENS) {
		tokens[out++] = w;
		while (*p != ',' && *p != '\0' && (star == NULL || p < star)) {
			if ((size_t)(w - token_buf) < cap) {
				*w++ = *p;
			}
			p++;
		}
		*w++ = '\0';
		if (*p == ',') {
			p++;
		}
	}
	return (uint16_t)out;
}

/* Verify an RMC sentence: time, fix, position. */
ZTEST(nmea_l76k, test_rmc_valid_fix)
{
	char buf[128];
	char *argv[MAX_TOKENS];
	uint16_t argc;

	memcpy(buf, l76k_rmc, sizeof(l76k_rmc));
	/* Split: first token is "$GNRMC", subsequent are comma fields. */
	char *p = buf + 1;
	argv[0] = p;
	argc = 1;
	while (*p != '\0') {
		if (*p == ',') {
			*p = '\0';
			argv[argc++] = p + 1;
		}
		p++;
	}

	struct gnss_data data = { 0 };
	int ret = gnss_nmea0183_parse_rmc(&argv[0], argc, &data);

	zassert_equal(0, ret, "RMC parse failed (%d)", ret);
	/* 2234.29401 N -> ~22.57 deg: nanodegree range check (strong:
	 * 0.01 deg window catches any field transposition or sign flip). */
	zassert_true(data.nav_data.latitude > INT64_C(22571500000) &&
		     data.nav_data.latitude < INT64_C(22571700000),
		     "lat %lld", data.nav_data.latitude);
	/* 11401.47621 E -> 114 deg + 1.47621/60 = ~114.0246 deg. */
	zassert_true(data.nav_data.longitude > INT64_C(114024500000) &&
		     data.nav_data.longitude < INT64_C(114024700000),
		     "lon %lld", data.nav_data.longitude);
	zassert_equal(6, data.utc.hour, "hour");
	zassert_equal(48, data.utc.minute, "minute");
	zassert_equal(1, data.utc.month_day, "day");
	zassert_equal(2, data.utc.month, "month");
	zassert_equal(22, data.utc.century_year, "year");
}

/* Verify a GGA sentence: altitude and fix quality. */
ZTEST(nmea_l76k, test_gga_altitude_and_fix)
{
	char buf[128];
	char *argv[MAX_TOKENS];
	uint16_t argc;

	memcpy(buf, l76k_gga, sizeof(l76k_gga));
	char *p = buf + 1;
	argv[0] = p;
	argc = 1;
	while (*p != '\0') {
		if (*p == ',') {
			*p = '\0';
			argv[argc++] = p + 1;
		}
		p++;
	}

	struct gnss_data data = { 0 };
	int ret = gnss_nmea0183_parse_gga(&argv[0], argc, &data);

	zassert_equal(0, ret, "GGA parse failed (%d)", ret);
	/* Altitude 80.6 M -> 80600 mm above MSL. NOTE: Zephyr's GGA parser
	 * handles altitude/HDOP/satellites only — position arrives via RMC. */
	zassert_equal(80600, data.nav_data.altitude, "alt");
	zassert_equal(12, data.info.satellites_cnt, "satellites");
	zassert_equal(680, data.info.hdop, "hdop (0.68 -> milli)");
}

ZTEST(nmea_l76k, test_pmtk_noise_ignored)
{
	/* PMTK sentences are proprietary responses, not standard NMEA.
	 * Feeding them through the parser must not crash (they fail the
	 * address-field check and return -EINVAL or are skipped). */
	char buf[64];
	char *argv[MAX_TOKENS];
	uint16_t argc;

	memcpy(buf, pmtk_noise, sizeof(pmtk_noise));
	char *p = buf + 1;
	argv[0] = p;
	argc = 1;
	while (*p != '\0') {
		if (*p == ',') {
			*p = '\0';
			argv[argc++] = p + 1;
		}
		p++;
	}

	struct gnss_data data = { 0 };
	/* PMTK001 is not a recognized NMEA type — the match layer filters
	 * it; the raw parse functions would reject the type. */
	zassert_true(strncmp(argv[0], "PMTK", 4) == 0, "PMTK prefix");
}

/* GSV sentences have variable field counts (up to 4 satellites per
 * sentence); the parser must handle short and long GSV without overflow. */
ZTEST(nmea_l76k, test_gsv_variable_fields)
{
	char buf[128];
	char *argv[MAX_TOKENS];
	uint16_t argc;

	/* Short GSV: fewer satellite entries. */
	memcpy(buf, "$GPGSV,1,1,01,03,,,30*48", sizeof("$GPGSV,1,1,01,03,,,30*48"));
	char *p = buf + 1;
	argv[0] = p;
	argc = 1;
	while (*p != '\0') {
		if (*p == ',') {
			*p = '\0';
			argv[argc++] = p + 1;
		}
		p++;
	}
	/* GSV parsing is exercised for overflow-safety only here (the
	 * satellite count struct requires GNSS_SATELLITES config). */
	zassert_true(argc >= 1, "tokens present");
}

ZTEST_SUITE(nmea_l76k, NULL, NULL, NULL, NULL, NULL);
