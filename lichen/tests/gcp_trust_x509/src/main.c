/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include <zephyr/ztest.h>

#include <lichen/gcp_trust.h>

extern unsigned char root_der[];
extern unsigned int root_der_len;
extern unsigned char intermediate_der[];
extern unsigned int intermediate_der_len;
extern unsigned char leaf_der[];
extern unsigned int leaf_der_len;
extern unsigned char wrong_root_der[];
extern unsigned int wrong_root_der_len;
extern unsigned char bad_signature_der[];
extern unsigned int bad_signature_der_len;
extern unsigned char ca_leaf_der[];
extern unsigned int ca_leaf_der_len;
extern unsigned char no_digital_signature_der[];
extern unsigned int no_digital_signature_der_len;

static int validate_leaf(const uint8_t *leaf, size_t leaf_len,
			 const uint8_t *anchor, size_t anchor_len)
{
	const uint8_t *chain[] = {intermediate_der};
	const size_t chain_lens[] = {intermediate_der_len};

	return gcp_trust_validate_x509_chain(leaf, leaf_len, chain, chain_lens, 1,
					    anchor, anchor_len);
}

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

ZTEST(gcp_trust_x509, test_accepts_valid_chain)
{
	zassert_equal(validate_leaf(leaf_der, leaf_der_len, root_der, root_der_len),
			      0, "valid chain must verify");
}

ZTEST(gcp_trust_x509, test_rejects_wrong_anchor)
{
	zassert_not_equal(validate_leaf(leaf_der, leaf_der_len, wrong_root_der,
						wrong_root_der_len),
					 0, "wrong anchor must be rejected");
}

ZTEST(gcp_trust_x509, test_rejects_bad_signature)
{
	zassert_not_equal(validate_leaf(bad_signature_der, bad_signature_der_len,
						root_der, root_der_len),
					 0, "bad signature must be rejected");
}

ZTEST(gcp_trust_x509, test_rejects_leaf_constraint_failures)
{
	zassert_not_equal(validate_leaf(ca_leaf_der, ca_leaf_der_len, root_der,
						root_der_len),
					 0, "CA leaf must be rejected");
	zassert_not_equal(validate_leaf(no_digital_signature_der,
						no_digital_signature_der_len, root_der,
						root_der_len),
					 0, "leaf without digitalSignature must be rejected");
}

ZTEST_SUITE(gcp_trust_x509, NULL, NULL, NULL, NULL, NULL);
