/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_authority.c
 * @brief SCHC session authority: trust-record lifecycle and
 *        generation-currentness gate (spec 5.6; bead l1qw.3.7.6.3).
 */

#include <lichen/schc_authority.h>

#include <string.h>

static const struct lichen_schc_trust_record *
find_record(const struct lichen_schc_authority *auth,
	    const struct lichen_schc_identity *remote)
{
	for (size_t i = 0; i < LICHEN_SCHC_MAX_TRUST_RECORDS; i++) {
		if (auth->records[i].occupied &&
		    memcmp(auth->records[i].remote.pubkey, remote->pubkey,
			   LICHEN_SCHC_IDENTITY_LEN) == 0) {
			return &auth->records[i];
		}
	}
	return NULL;
}

static struct lichen_schc_trust_record *
find_record_mut(struct lichen_schc_authority *auth,
		const struct lichen_schc_identity *remote)
{
	for (size_t i = 0; i < LICHEN_SCHC_MAX_TRUST_RECORDS; i++) {
		if (auth->records[i].occupied &&
		    memcmp(auth->records[i].remote.pubkey, remote->pubkey,
			   LICHEN_SCHC_IDENTITY_LEN) == 0) {
			return &auth->records[i];
		}
	}
	return NULL;
}

static int mint_generation(struct lichen_schc_authority *auth,
			   lichen_schc_generation_t *out)
{
	if (auth->next_generation == UINT64_MAX) {
		/* Fail closed rather than wrap a token. */
		return -EOVERFLOW;
	}
	auth->next_generation++;
	*out = auth->next_generation;
	return 0;
}

void lichen_schc_authority_init(struct lichen_schc_authority *auth,
				struct lichen_schc_session_table *table)
{
	if (auth == NULL) {
		return;
	}
	memset(auth, 0, sizeof(*auth));
	auth->table = table;
}

int lichen_schc_authority_install(struct lichen_schc_authority *auth,
				  const struct lichen_schc_identity *remote,
				  lichen_schc_generation_t *out_generation)
{
	if (auth == NULL || remote == NULL || out_generation == NULL ||
	    auth->table == NULL) {
		return -EINVAL;
	}
	*out_generation = LICHEN_SCHC_GENERATION_INVALID;

	struct lichen_schc_trust_record *rec = find_record_mut(auth, remote);
	struct lichen_schc_trust_record *slot = rec;

	if (slot == NULL) {
		if (auth->record_count >= LICHEN_SCHC_MAX_TRUST_RECORDS) {
			/* Fail closed WITHOUT evicting a current trust
			 * record: silently invalidating a peer's sessions is
			 * worse than refusing a new one. */
			return -ENOBUFS;
		}
		for (size_t i = 0; i < LICHEN_SCHC_MAX_TRUST_RECORDS; i++) {
			if (!auth->records[i].occupied) {
				slot = &auth->records[i];
				break;
			}
		}
		if (slot == NULL) {
			/* Unreachable: count < MAX implies a free slot. */
			return -ENOBUFS;
		}
	}

	lichen_schc_generation_t new_gen;
	int ret = mint_generation(auth, &new_gen);

	if (ret != 0) {
		return ret;
	}

	if (rec != NULL) {
		/* Replacement/rotation: retire the old generation FIRST so the
		 * transition is all-or-nothing; only then publish the new
		 * token. Invalidate can only fail on NULL args, which are
		 * pre-validated above. */
		ret = lichen_schc_table_invalidate_generation(auth->table, remote,
							      rec->generation);
		if (ret < 0) {
			return ret;
		}
	} else {
		auth->record_count++;
	}

	slot->remote = *remote;
	slot->generation = new_gen;
	slot->occupied = true;
	*out_generation = new_gen;
	return 0;
}

int lichen_schc_authority_revoke(struct lichen_schc_authority *auth,
				 const struct lichen_schc_identity *remote)
{
	if (auth == NULL || remote == NULL || auth->table == NULL) {
		return -EINVAL;
	}

	struct lichen_schc_trust_record *rec = find_record_mut(auth, remote);

	if (rec == NULL) {
		/* Idempotent: revoking an unknown signer retires nothing. */
		return 0;
	}

	int ret = lichen_schc_table_invalidate_generation(auth->table, remote,
							  rec->generation);

	if (ret < 0) {
		return ret;
	}
	rec->occupied = false;
	auth->record_count--;
	return 0;
}

bool lichen_schc_authority_generation_current(
	const struct lichen_schc_authority *auth,
	const struct lichen_schc_identity *remote,
	lichen_schc_generation_t generation)
{
	if (auth == NULL || remote == NULL ||
	    generation == LICHEN_SCHC_GENERATION_INVALID) {
		return false;
	}

	const struct lichen_schc_trust_record *rec = find_record(auth, remote);

	return rec != NULL && rec->generation == generation;
}

bool lichen_schc_authority_key_current(
	const struct lichen_schc_authority *auth,
	const struct lichen_schc_ctx_key *key)
{
	if (key == NULL) {
		return false;
	}
	return lichen_schc_authority_generation_current(auth, &key->remote,
							key->generation);
}
