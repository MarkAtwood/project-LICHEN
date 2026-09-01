// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
/** @file
 *  Root DIO Signature verification and anti-replay consumption
 *  (spec/06-security.md 8.10.1) — second half of the C receiver: signature
 *  verification over the rebuilt COSE Sig_structure and strictly-increasing
 *  root_seq consumption keyed by (dodag_id, instance).
 *
 *  Mirrors python verify_root_dio_signature steps 1 (signature) and 4
 *  (root_seq > cached), and rust RootSeqCache. Decode and structural checks
 *  live in root_dio_sig.c (bead b7z9.37.2.2(a)).
 */

#include <lichen/root_dio_replay.h>

#include <string.h>

void root_dio_replay_cache_init(struct root_dio_replay_cache *cache)
{
	memset(cache, 0, sizeof(*cache));
}

int root_dio_replay_cache_check_and_admit(struct root_dio_replay_cache *cache,
					  const uint8_t dodag_id[16],
					  uint8_t instance, uint64_t root_seq)
{
	for (size_t i = 0; i < cache->count; i++) {
		struct root_dio_replay_entry *e = &cache->entries[i];
		if (memcmp(e->dodag_id, dodag_id, 16U) == 0 &&
		    e->instance == instance) {
			if (root_seq <= e->root_seq) {
				return -ROOT_SIG_ERR_REPLAY_DETECTED;
			}
			e->root_seq = root_seq;
			return ROOT_SIG_OK;
		}
	}
	if (cache->count >= LICHEN_ROOT_DIO_REPLAY_MAX_KEYS) {
		return -ROOT_SIG_ERR_REPLAY_DETECTED;
	}
	memcpy(cache->entries[cache->count].dodag_id, dodag_id, 16U);
	cache->entries[cache->count].instance = instance;
	cache->entries[cache->count].root_seq = root_seq;
	cache->count++;
	return ROOT_SIG_OK;
}

bool root_dio_replay_cache_seen(const struct root_dio_replay_cache *cache,
				const uint8_t dodag_id[16], uint8_t instance,
				uint64_t root_seq)
{
	for (size_t i = 0; i < cache->count; i++) {
		const struct root_dio_replay_entry *e = &cache->entries[i];
		if (memcmp(e->dodag_id, dodag_id, 16U) == 0 &&
		    e->instance == instance) {
			return root_seq <= e->root_seq;
		}
	}
	return false;
}
