// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project
/** @file
 *  Anti-replay consumption for root DIO Signature sequence numbers
 *  (spec/06-security.md 8.10.1: root_seq strictly increasing per
 *  (dodag_id, instance); MUST NOT wrap — a post-wrap counter appears as a
 *  lower value and is rejected). Mirrors rust RootSeqCache and the python
 *  oracle is_valid_dao_sequence / verify_root_dio_signature cached_seq.
 */

#ifndef LICHEN_RPL_ROOT_DIO_REPLAY_H
#define LICHEN_RPL_ROOT_DIO_REPLAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Maximum tracked (dodag_id, instance) keys. */
#define LICHEN_ROOT_DIO_REPLAY_MAX_KEYS 16

/** Replay failure reason. */
#define ROOT_SIG_OK 0
#define ROOT_SIG_ERR_REPLAY_DETECTED 1

/** One tracked key: highest accepted root_seq. */
struct root_dio_replay_entry {
	uint8_t dodag_id[16];
	uint8_t instance;
	uint64_t root_seq;
};

/** Anti-replay cache for root DIO signature sequence numbers. */
struct root_dio_replay_cache {
	size_t count;
	struct root_dio_replay_entry entries[LICHEN_ROOT_DIO_REPLAY_MAX_KEYS];
};

/**
 * @brief Reset the cache to empty.
 *
 * @param cache Cache to reset
 */
void root_dio_replay_cache_init(struct root_dio_replay_cache *cache);

/**
 * @brief Check-and-admit a root_seq for the key.
 *
 * Accepted iff strictly greater than the cached value for the key; first
 * observations are admitted while the table has room. A full table rejects
 * NEW keys fail closed without evicting live high-water marks.
 *
 * @param cache     Cache
 * @param dodag_id  DODAGID (16 bytes)
 * @param instance  RPL instance id
 * @param root_seq  Sequence number to admit
 * @return ROOT_SIG_OK, or -ROOT_SIG_ERR_REPLAY_DETECTED
 */
int root_dio_replay_cache_check_and_admit(struct root_dio_replay_cache *cache,
					  const uint8_t dodag_id[16],
					  uint8_t instance, uint64_t root_seq);

/**
 * @brief True when this exact (key, seq) was already admitted (replay).
 *
 * @param cache     Cache
 * @param dodag_id  DODAGID (16 bytes)
 * @param instance  RPL instance id
 * @param root_seq  Sequence number to test
 * @return true if seen at an equal-or-higher value (replay)
 */
bool root_dio_replay_cache_seen(const struct root_dio_replay_cache *cache,
				const uint8_t dodag_id[16], uint8_t instance,
				uint64_t root_seq);

#endif /* LICHEN_RPL_ROOT_DIO_REPLAY_H */
