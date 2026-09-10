/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/l2_payload.h>

#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { \
	if (!(condition)) { \
		printf("FAIL line %d: %s\n", __LINE__, #condition); \
		return 1; \
	} \
} while (0)

static int test_sos_wrapper(void)
{
	/* Canonical sos_alert CBOR fixture: {"type":"sos","seq":1}. */
	static const uint8_t cbor[] = {
		0xa2, 0x64, 't', 'y', 'p', 'e', 0x63, 's', 'o', 's',
		0x63, 's', 'e', 'q', 0x01,
	};
	uint8_t wrapped[sizeof(cbor) + 1U];
	size_t written = 0U;

	CHECK(lichen_l2_wrap_sos_payload(cbor, sizeof(cbor), wrapped,
					 sizeof(wrapped), &written) == 0);
	CHECK(written == sizeof(wrapped));
	CHECK(wrapped[0] == LICHEN_L2_DISPATCH_SOS);
	CHECK(lichen_l2_payload_classify(wrapped, written) ==
	      LICHEN_L2_PAYLOAD_SOS);
	CHECK(memcmp(&wrapped[1], cbor, sizeof(cbor)) == 0);

	size_t body_len = 0U;
	CHECK(lichen_l2_payload_body(wrapped, written, &body_len) == &wrapped[1]);
	CHECK(body_len == sizeof(cbor));
	CHECK(memcmp(lichen_l2_payload_body(wrapped, written, NULL), cbor,
		     sizeof(cbor)) == 0);
	return 0;
}

static int test_invalid_inputs_are_atomic(void)
{
	static const uint8_t cbor[] = {0xa0};
	uint8_t out[sizeof(cbor) + 1U];
	size_t written = 77U;

	memset(out, 0xa5, sizeof(out));
	CHECK(lichen_l2_wrap_sos_payload(cbor, sizeof(cbor), out, sizeof(cbor),
					 &written) < 0);
	CHECK(written == 77U);
	for (size_t i = 0U; i < sizeof(out); ++i) CHECK(out[i] == 0xa5);

	CHECK(lichen_l2_wrap_sos_payload(NULL, 1U, out, sizeof(out), &written) < 0);
	CHECK(lichen_l2_wrap_sos_payload(NULL, 0U, out, sizeof(out), &written) < 0);
	CHECK(lichen_l2_wrap_sos_payload(cbor, sizeof(cbor), out, sizeof(out),
					 NULL) < 0);
	CHECK(lichen_l2_payload_classify(out, 1U) == LICHEN_L2_PAYLOAD_UNKNOWN);
	CHECK(lichen_l2_payload_classify(NULL, 2U) == LICHEN_L2_PAYLOAD_UNKNOWN);
	return 0;
}

int main(void)
{
	CHECK(test_sos_wrapper() == 0);
	CHECK(test_invalid_inputs_are_atomic() == 0);
	puts("L2 SOS payload: PASS");
	return 0;
}
