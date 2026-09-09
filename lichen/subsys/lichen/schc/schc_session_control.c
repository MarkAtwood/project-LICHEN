/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_session_control.c
 * @brief Control authorization + terminal hold-down for the SCHC session
 *        authority (spec 5.6; bead l1qw.3.7.6.5).
 */

#include <lichen/schc_session_control.h>

#include <string.h>

/* ── Internal helpers ──────────────────────────────────────────────────────*/

static struct lichen_schc_ctl_session *
session_find(struct lichen_schc_control *ctl,
	     const struct lichen_schc_ctx_key *key)
{
	for (size_t i = 0; i < LICHEN_SCHC_MAX_CONTEXTS; i++) {
		if (ctl->sessions[i].occupied &&
		    lichen_schc_ctx_key_equal(&ctl->sessions[i].key, key)) {
			return &ctl->sessions[i];
		}
	}
	return NULL;
}

/* Gate: authenticated + current generation. True iff the slice-3 authority
 * admits this message for this key. */
static bool gate_admits(const struct lichen_schc_control *ctl,
			const struct lichen_schc_ctx_key *key)
{
	return lichen_schc_authority_current(&ctl->auth, &key->remote,
					     key->generation);
}

/* ── Lifecycle ─────────────────────────────────────────────────────────────*/

void lichen_schc_control_init(struct lichen_schc_control *ctl)
{
	if (ctl == NULL) {
		return;
	}
	memset(ctl, 0, sizeof(*ctl));
	lichen_schc_authority_init(&ctl->auth);
	lichen_schc_table_init(&ctl->table);
}

int lichen_schc_control_install(struct lichen_schc_control *ctl,
				const struct lichen_schc_identity *remote,
				lichen_schc_generation_t *generation)
{
	if (ctl == NULL) {
		return -EINVAL;
	}
	return lichen_schc_authority_install(&ctl->auth, &ctl->table, remote,
					     generation);
}

int lichen_schc_control_revoke(struct lichen_schc_control *ctl,
			       const struct lichen_schc_identity *remote)
{
	if (ctl == NULL || remote == NULL) {
		return -EINVAL;
	}
	/* Free this module's session records for every generation of the
	 * revoked remote, then let the authority retire the trust record and
	 * atomically invalidate the slice-2 tables. */
	for (size_t i = 0; i < LICHEN_SCHC_MAX_CONTEXTS; i++) {
		if (ctl->sessions[i].occupied &&
		    memcmp(ctl->sessions[i].key.remote.pubkey, remote->pubkey,
			   LICHEN_SCHC_IDENTITY_LEN) == 0) {
			ctl->sessions[i].occupied = false;
			ctl->session_count--;
		}
	}
	return lichen_schc_authority_revoke(&ctl->auth, &ctl->table, remote);
}

/* ── Classification (spec 5.6 ambiguity rule) ──────────────────────────────*/

enum lichen_schc_control_class
lichen_schc_control_classify(enum lichen_schc_endpoint data_sender_role,
			     enum lichen_schc_endpoint sender_role,
			     uint8_t rule_id)
{
	uint8_t data_rule;

	/* Directional rule of the data transfer; rejects out-of-range roles. */
	if (lichen_schc_directional_rule(data_sender_role,
					 LICHEN_SCHC_MSG_DATA,
					 &data_rule) != 0) {
		return LICHEN_SCHC_CLASS_INVALID;
	}
	if (rule_id != data_rule) {
		/* The ambiguous blob retains the data transfer's Rule ID;
		 * anything else is not this session's control. */
		return LICHEN_SCHC_CLASS_INVALID;
	}
	if (sender_role != LICHEN_SCHC_ENDPOINT_A &&
	    sender_role != LICHEN_SCHC_ENDPOINT_B) {
		return LICHEN_SCHC_CLASS_INVALID;
	}
	/* Same Rule ID on both legs: the authenticated sender role alone
	 * resolves the direction. The data sender issues ACK REQ; the data
	 * receiver issues the ACK. */
	if (sender_role == data_sender_role) {
		return LICHEN_SCHC_CLASS_ACK_REQ;
	}
	return LICHEN_SCHC_CLASS_ACK;
}

/* ── Session open (admission) ──────────────────────────────────────────────*/

int lichen_schc_control_open(struct lichen_schc_control *ctl,
			     const struct lichen_schc_ctx_key *key,
			     uint8_t w, uint8_t fcn, uint32_t counter,
			     enum lichen_schc_control_response *resp)
{
	if (ctl == NULL || key == NULL || resp == NULL) {
		return -EINVAL;
	}
	*resp = LICHEN_SCHC_RESP_NONE;

	/* 1. Authority gate: authenticated + current generation. */
	if (!gate_admits(ctl, key)) {
		return 0;
	}

	/* 2. T=0: one active session per key. A second opener is a duplicate,
	 * not a new session. */
	if (session_find(ctl, key) != NULL) {
		return 0;
	}

	/* 3. Admission: canonical opener strictly above the durable floor. */
	uint32_t floor = 0;
	const struct lichen_schc_floor *recorded =
		lichen_schc_floor_find(&ctl->table, key);

	if (recorded != NULL) {
		floor = recorded->high_water;
	}
	if (lichen_schc_rx_admit(w, fcn, counter, floor) !=
	    LICHEN_SCHC_RX_OPEN) {
		return 0;
	}

	/* 4. Bounded allocations, both checked before any write (atomic).
	 * Context allocation failure on an authenticated opener issues ONE
	 * Receiver-Abort for the rejected key and MUST NOT evict or mutate
	 * an active context (spec 5.6). */
	size_t free_slot = LICHEN_SCHC_MAX_CONTEXTS;

	for (size_t i = 0; i < LICHEN_SCHC_MAX_CONTEXTS; i++) {
		if (!ctl->sessions[i].occupied) {
			free_slot = i;
			break;
		}
	}
	if (free_slot == LICHEN_SCHC_MAX_CONTEXTS) {
		*resp = LICHEN_SCHC_RESP_RECEIVER_ABORT;
		return 0;
	}

	struct lichen_schc_context *ctx = NULL;
	int ret = lichen_schc_ctx_alloc(&ctl->table, key, &ctx);

	if (ret != 0) {
		*resp = LICHEN_SCHC_RESP_RECEIVER_ABORT;
		return 0;
	}

	ctl->sessions[free_slot].key = *key;
	ctl->sessions[free_slot].high_water = counter;
	ctl->sessions[free_slot].ack_count = 0U;
	ctl->sessions[free_slot].occupied = true;
	ctl->session_count++;
	return 0;
}

/* ── In-session counter advance ────────────────────────────────────────────*/

int lichen_schc_control_accept(struct lichen_schc_control *ctl,
			       const struct lichen_schc_ctx_key *key,
			       uint32_t counter)
{
	if (ctl == NULL || key == NULL) {
		return -EINVAL;
	}
	if (!gate_admits(ctl, key)) {
		return -EAGAIN;
	}
	struct lichen_schc_ctl_session *session = session_find(ctl, key);

	if (session == NULL) {
		return -EAGAIN;
	}
	if (counter > LICHEN_SCHC_COUNTER_MAX ||
	    session->high_water == LICHEN_SCHC_COUNTER_MAX ||
	    counter <= session->high_water) {
		return -EAGAIN;
	}
	session->high_water = counter;
	return 0;
}

/* ── 4-ACK-then-abort ──────────────────────────────────────────────────────*/

int lichen_schc_control_ack_request(struct lichen_schc_control *ctl,
				    const struct lichen_schc_ctx_key *key,
				    uint32_t counter, uint32_t now_s,
				    enum lichen_schc_control_response *resp)
{
	if (ctl == NULL || key == NULL || resp == NULL) {
		return -EINVAL;
	}
	*resp = LICHEN_SCHC_RESP_NONE;

	if (!gate_admits(ctl, key)) {
		return 0;
	}
	struct lichen_schc_ctl_session *session = session_find(ctl, key);

	if (session == NULL) {
		/* No active session: maybe a late replay against a tombstone. */
		enum lichen_schc_terminal ignored;

		return lichen_schc_control_late(ctl, key, counter, now_s, resp,
						&ignored);
	}
	/* The control must strictly exceed the session counter. */
	if (counter > LICHEN_SCHC_COUNTER_MAX ||
	    session->high_water == LICHEN_SCHC_COUNTER_MAX ||
	    counter <= session->high_water) {
		return 0;
	}
	session->high_water = counter;

	if (session->ack_count < LICHEN_SCHC_MAX_ACK_RESPONSES) {
		session->ack_count++;
		*resp = LICHEN_SCHC_RESP_ACK;
		return 0;
	}
	/* 5th otherwise-valid request: Receiver-Abort + terminal hold-down. */
	(void)lichen_schc_control_terminate(ctl, key,
					    LICHEN_SCHC_TERMINAL_RECEIVER_ABORT,
					    now_s);
	*resp = LICHEN_SCHC_RESP_RECEIVER_ABORT;
	return 0;
}

/* ── Termination + hold-down ───────────────────────────────────────────────*/

int lichen_schc_control_terminate(struct lichen_schc_control *ctl,
				  const struct lichen_schc_ctx_key *key,
				  enum lichen_schc_terminal outcome,
				  uint32_t now_s)
{
	if (ctl == NULL || key == NULL) {
		return -EINVAL;
	}
	struct lichen_schc_ctl_session *session = session_find(ctl, key);

	if (session == NULL) {
		return -ENOENT;
	}
	uint32_t high_water = session->high_water;

	/* Tombstone + durable floor (both bounded-eviction, cannot fail on
	 * capacity), then free the session slot: all-or-nothing. */
	(void)lichen_schc_tombstone_put(&ctl->table, key, outcome, high_water,
					now_s);
	(void)lichen_schc_floor_put(&ctl->table, key, high_water);
	session->occupied = false;
	ctl->session_count--;
	return 0;
}

int lichen_schc_control_late(struct lichen_schc_control *ctl,
			     const struct lichen_schc_ctx_key *key,
			     uint32_t counter, uint32_t now_s,
			     enum lichen_schc_control_response *resp,
			     enum lichen_schc_terminal *outcome)
{
	if (ctl == NULL || key == NULL || resp == NULL) {
		return -EINVAL;
	}
	*resp = LICHEN_SCHC_RESP_NONE;

	if (!gate_admits(ctl, key)) {
		return 0;
	}
	struct lichen_schc_tombstone *tomb =
		lichen_schc_tombstone_find(&ctl->table, key);

	if (tomb == NULL) {
		return 0;
	}
	/* Hold-down window: strictly-greater counter replays the terminal
	 * response idempotently and advances the tombstone high-water. */
	if (now_s - tomb->terminal_time >= LICHEN_SCHC_HOLDDOWN_SECONDS) {
		return 0;
	}
	if (counter > LICHEN_SCHC_COUNTER_MAX ||
	    tomb->high_water == LICHEN_SCHC_COUNTER_MAX ||
	    counter <= tomb->high_water) {
		return 0;
	}
	tomb->high_water = counter;
	/* The floor follows the generation-scoped high-water even during the
	 * hold-down: it is monotonic, so this can only raise it. */
	(void)lichen_schc_floor_put(&ctl->table, key, counter);
	*resp = LICHEN_SCHC_RESP_REPLAY;
	if (outcome != NULL) {
		*outcome = tomb->outcome;
	}
	return 0;
}

/* ── Read-only metadata for Link/L2 ────────────────────────────────────────*/

bool lichen_schc_control_session_active(struct lichen_schc_control *ctl,
					const struct lichen_schc_ctx_key *key)
{
	if (ctl == NULL || key == NULL) {
		return false;
	}
	return session_find(ctl, key) != NULL;
}

bool lichen_schc_control_high_water(struct lichen_schc_control *ctl,
				    const struct lichen_schc_ctx_key *key,
				    uint32_t *high_water)
{
	if (ctl == NULL || key == NULL || high_water == NULL) {
		return false;
	}
	struct lichen_schc_ctl_session *session = session_find(ctl, key);

	if (session != NULL) {
		*high_water = session->high_water;
		return true;
	}
	struct lichen_schc_tombstone *tomb =
		lichen_schc_tombstone_find(&ctl->table, key);

	if (tomb != NULL) {
		*high_water = tomb->high_water;
		return true;
	}
	return false;
}

bool lichen_schc_control_ack_count(struct lichen_schc_control *ctl,
				   const struct lichen_schc_ctx_key *key,
				   uint8_t *ack_count)
{
	if (ctl == NULL || key == NULL || ack_count == NULL) {
		return false;
	}
	struct lichen_schc_ctl_session *session = session_find(ctl, key);

	if (session == NULL) {
		return false;
	}
	*ack_count = session->ack_count;
	return true;
}

bool lichen_schc_control_floor(struct lichen_schc_control *ctl,
			       const struct lichen_schc_ctx_key *key,
			       uint32_t *floor)
{
	if (ctl == NULL || key == NULL || floor == NULL) {
		return false;
	}
	struct lichen_schc_floor *recorded =
		lichen_schc_floor_find(&ctl->table, key);

	if (recorded == NULL) {
		return false;
	}
	*floor = recorded->high_water;
	return true;
}
