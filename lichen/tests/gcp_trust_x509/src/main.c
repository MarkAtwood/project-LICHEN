/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/ztest.h>

#include <lichen/gcp_trust.h>

ZTEST(gcp_trust_x509, test_rejects_null_leaf)
{
	static const uint8_t anchor[] = {0x30};

	zassert_equal(gcp_trust_validate_x509_chain(NULL, 0, NULL, NULL, 0,
							 anchor, sizeof(anchor)),
				      -EINVAL, "null leaf must be rejected");
}

ZTEST(gcp_trust_x509, test_rejects_null_chain_arrays)
{
	static const uint8_t leaf[] = {0x30};
	static const uint8_t anchor[] = {0x30};

	zassert_equal(gcp_trust_validate_x509_chain(leaf, sizeof(leaf), NULL, NULL,
							 1, anchor, sizeof(anchor)),
				      -EINVAL, "missing chain arrays must be rejected");
}

ZTEST_SUITE(gcp_trust_x509, NULL, NULL, NULL, NULL, NULL);
