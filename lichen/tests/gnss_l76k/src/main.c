/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <zephyr/device.h>
#include <zephyr/drivers/gnss.h>
#include <zephyr/ztest.h>

/* Build-validation smoke test for the L76K driver (bead jtl6): the
 * l76k DT node must instantiate and the GNSS API must be reachable.
 * Real NMEA traffic validation is a hardware follow-up
 * (project-LICHEN-2h1i.1.2.2). */
ZTEST(gnss_l76k, test_l76k_device_present)
{
	const struct device *dev = DEVICE_DT_GET(DT_NODELABEL(l76k));

	zassert_true(device_is_ready(dev), "l76k device not ready");
}

ZTEST_SUITE(gnss_l76k, NULL, NULL, NULL, NULL, NULL);
