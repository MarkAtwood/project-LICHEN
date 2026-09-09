/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/* Host-test stub: mirrors Zephyr 4.1 coap_link_format.h's
 * struct coap_core_metadata shape (attributes only; user_data unused
 * by the host path). */
#ifndef ZEPHYR_HOST_TEST_SLOT_CLAIM_COAP_LINK_FORMAT_H_
#define ZEPHYR_HOST_TEST_SLOT_CLAIM_COAP_LINK_FORMAT_H_

struct coap_core_metadata {
	const char * const *attributes;
	void *user_data;
};

#endif
