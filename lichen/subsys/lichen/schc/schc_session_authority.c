/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file schc_session_authority.c
 * @brief Authenticated SCHC session authority lifecycle (spec 5.6; bead
 *        l1qw.3.7.6.3).
 */

#include <lichen/schc_session_authority.h>

#include <string.h>

void lichen_schc_authority_init(struct lichen_schc_authority *auth)
{
	if (auth == NULL) {
		return;
	}
	memset(auth, 0, sizeof(*auth));
	/* Token 0 never identifies an installed record. */
	auth->next_generation = 1U;
}

static struct lichen_schc_authority_entry *
authority_find(struct lichen_schc_authority *auth,
	       const struct lichen_schc_identity *remote)
{
	for (size_t i = 0; i < LICHEN_SCHC_MAX_AUTHORITIES; i++) {
		if (auth->entries[i].occupied &&
		    memcmp(auth->entries[i].remote.pubkey, remote->pubkey,
			   LICHEN_SCHC_IDENTITY_LEN) == 0) {
			return &auth->entries[i];
		}
	}
	return NULL;
}

static const struct lichen_schc_authority_entry *
authority_find_const(const struct lichen_schc_authority *auth,
		     const struct lichen_schc_identity *remote)
{
	for (size_t i = 0; i < LICHEN_SCHC_MAX_AUTHORITIES; i++) {
		if (auth->entries[i].occupied &&
		    memcmp(auth->entries[i].remote.pubkey, remote->pubkey,
			   LICHEN_SCHC_IDENTITY_LEN) == 0) {
			return &auth->entries[i];
		}
	}
	return NULL;
}

static int authority_issue(struct lichen_schc_authority *auth,
			   lichen_schc_generation_t *token)
{
	if (auth->next_generation == 0U) {
		/* u64 wrapped: the token space is exhausted; fail closed
		 * rather than reissue a retired generation. */
		return -EOVERFLOW;
	}
	*token = auth->next_generation;
	auth->next_generation++;
	return 0;
}

int lichen_schc_authority_install(struct lichen_schc_authority *auth,
				  struct lichen_schc_session_table *table,
				  const struct lichen_schc_identity *remote,
				  lichen_schc_generation_t *generation)
{
	if (auth == NULL || table == NULL || remote == NULL ||
	    generation == NULL) {
		return -EINVAL;
	}

	struct lichen_schc_authority_entry *entry =
		authority_find(auth, remote);

	if (entry != NULL) {
		/* Replacement/rotation of an installed key: retire the old
		 * generation FIRST (the gate fails it from this instruction
		 * on), then atomically invalidate every class of state the
		 * retired generation issued. */
		lichen_schc_generation_t retired = entry->generation;
		lichen_schc_generation_t fresh;

		int ret = authority_issue(auth, &fresh);

		if (ret != 0) {
			return ret;
		}
		entry->generation = fresh;
		(void)lichen_schc_table_invalidate_generation(table, remote,
							      retired);
		*generation = fresh;
		return 0;
	}

	/* First install: bounded, fail-closed (never evict a live record). */
	if (auth->count >= LICHEN_SCHC_MAX_AUTHORITIES) {
		return -ENOBUFS;
	}
	for (size_t i = 0; i < LICHEN_SCHC_MAX_AUTHORITIES; i++) {
		if (!auth->entries[i].occupied) {
			lichen_schc_generation_t fresh;

			int ret = authority_issue(auth, &fresh);

			if (ret != 0) {
				return ret;
			}
			auth->entries[i].remote = *remote;
			auth->entries[i].generation = fresh;
			auth->entries[i].occupied = true;
			auth->count++;
			*generation = fresh;
			return 0;
		}
	}
	/* Unreachable: count < MAX implies a free slot (defense in depth,
	 * mirrors the slice-2 context allocator). */
	return -ENOBUFS;
}

int lichen_schc_authority_revoke(struct lichen_schc_authority *auth,
				 struct lichen_schc_session_table *table,
				 const struct lichen_schc_identity *remote)
{
	if (auth == NULL || table == NULL || remote == NULL) {
		return -EINVAL;
	}

	struct lichen_schc_authority_entry *entry =
		authority_find(auth, remote);

	if (entry == NULL) {
		/* Idempotent: a replayed revocation invalidates nothing. */
		return 0;
	}

	/* Retire the generation at the trust record first, then atomically
	 * invalidate every context, tombstone, cached response, and floor it
	 * issued (all-or-nothing, single serialized call). The record itself
	 * is freed so a later install starts a fresh isolated generation. */
	lichen_schc_generation_t retired = entry->generation;

	entry->occupied = false;
	auth->count--;
	return lichen_schc_table_invalidate_generation(table, remote,
						       retired);
}

bool lichen_schc_authority_current(
	const struct lichen_schc_authority *auth,
	const struct lichen_schc_identity *remote,
	lichen_schc_generation_t generation)
{
	if (auth == NULL || remote == NULL) {
		return false;
	}
	const struct lichen_schc_authority_entry *entry =
		authority_find_const(auth, remote);

	return entry != NULL && entry->generation == generation;
}

enum lichen_schc_gate_verdict
lichen_schc_authority_gate(const struct lichen_schc_authority *auth,
			   const struct lichen_schc_identity *remote,
			   lichen_schc_generation_t generation,
			   bool authenticated)
{
	if (auth == NULL || remote == NULL) {
		return LICHEN_SCHC_GATE_DROP_SILENT;
	}
	if (!authenticated) {
		/* Spec 5.6: silently dropped, no control response. */
		return LICHEN_SCHC_GATE_DROP_SILENT;
	}
	if (!lichen_schc_authority_current(auth, remote, generation)) {
		/* Retired or never-installed generation: dropped identically,
		 * no control response (a response would bind retired state). */
		return LICHEN_SCHC_GATE_DROP_STALE;
	}
	return LICHEN_SCHC_GATE_ADMIT;
}
