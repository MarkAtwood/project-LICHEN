/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_session.c
 * @brief Authenticated SCHC session authority: identity and direction core.
 */

#include <lichen/schc_session.h>

#include <string.h>

int lichen_schc_identity_cmp(const struct lichen_schc_identity *a,
			     const struct lichen_schc_identity *b)
{
	if (a == NULL || b == NULL) {
		/* Defensive: identity comparison with no identity is
		 * meaningless. Treat NULL as lesser so callers that forgot a
		 * NULL check get a deterministic, non-equal result rather than
		 * a crash; endpoint_role rejects on equality separately. */
		return (a == b) ? 0 : ((a == NULL) ? -1 : 1);
	}
	return memcmp(a->pubkey, b->pubkey, LICHEN_SCHC_IDENTITY_LEN);
}

int lichen_schc_endpoint_role(const struct lichen_schc_identity *local,
			      const struct lichen_schc_identity *remote,
			      enum lichen_schc_endpoint *role)
{
	if (local == NULL || remote == NULL || role == NULL) {
		return -EINVAL;
	}

	int cmp = memcmp(local->pubkey, remote->pubkey,
			 LICHEN_SCHC_IDENTITY_LEN);

	if (cmp == 0) {
		/* Equal keys do not identify a peer pair (spec 5.6). */
		return -EINVAL;
	}
	*role = (cmp < 0) ? LICHEN_SCHC_ENDPOINT_A : LICHEN_SCHC_ENDPOINT_B;
	return 0;
}

int lichen_schc_directional_rule(enum lichen_schc_endpoint data_sender_role,
				 enum lichen_schc_msg_class cls,
				 uint8_t *rule_id)
{
	if (rule_id == NULL) {
		return -EINVAL;
	}
	if (data_sender_role != LICHEN_SCHC_ENDPOINT_A &&
	    data_sender_role != LICHEN_SCHC_ENDPOINT_B) {
		return -EINVAL;
	}

	switch (cls) {
	case LICHEN_SCHC_MSG_DATA:
	case LICHEN_SCHC_MSG_ACK_REQ:
	case LICHEN_SCHC_MSG_SENDER_ABORT:
	case LICHEN_SCHC_MSG_ACK:
	case LICHEN_SCHC_MSG_RECEIVER_ABORT:
		/* Every class in this profile carries the data sender's
		 * directional Rule ID. Data-plane messages use it because the
		 * data sender transmits them; control-plane ACK/Receiver-Abort
		 * travel in reverse but RETAIN the data transfer's Rule ID. */
		*rule_id = (data_sender_role == LICHEN_SCHC_ENDPOINT_A)
				   ? LICHEN_SCHC_RULE_A_TO_B
				   : LICHEN_SCHC_RULE_B_TO_A;
		return 0;
	default:
		return -EINVAL;
	}
}

bool lichen_schc_direction_valid(enum lichen_schc_endpoint data_sender_role,
				 enum lichen_schc_msg_class cls,
				 uint8_t rule_id)
{
	uint8_t expected = 0U;

	if (lichen_schc_directional_rule(data_sender_role, cls, &expected) != 0) {
		return false;
	}
	return rule_id == expected;
}
