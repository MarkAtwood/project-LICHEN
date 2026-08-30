/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/coap_slot_coord.h>

#include <errno.h>
#include <string.h>
#include <sys/types.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/settings/settings.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

LOG_MODULE_REGISTER(lichen_slot_claim_settings,
		    CONFIG_LICHEN_COAP_SLOT_COORD_LOG_LEVEL);

#define SETTINGS_ROOT "lichen/slot_claim"
#define SEQ_NAME_LEN (2U * LICHEN_IID_LEN)

struct seq_entry {
	uint8_t iid[LICHEN_IID_LEN];
	uint32_t seq;
	bool valid;
};

/* RAM cache of per-gateway claim_seq high-water marks, rebuilt from NV
 * at first use (lazy settings_load_subtree) and kept monotonic thereafter.
 * Capacity matches the coordination table: at most
 * CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS gateways can ever be accepted per
 * boot; stored entries beyond capacity are dropped from the cache (their
 * NV copy remains and is re-read on the next boot). */
static struct seq_entry s_cache[CONFIG_LICHEN_SLOT_COORD_MAX_GATEWAYS];
static bool s_loaded;
static K_MUTEX_DEFINE(s_lock);

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static void iid_to_name(const uint8_t iid[LICHEN_IID_LEN],
			char name[SEQ_NAME_LEN + 1U])
{
	static const char hex[] = "0123456789abcdef";

	for (size_t i = 0; i < LICHEN_IID_LEN; i++) {
		name[2U * i] = hex[iid[i] >> 4];
		name[2U * i + 1U] = hex[iid[i] & 0x0FU];
	}
	name[SEQ_NAME_LEN] = '\0';
}

static int name_to_iid(const char *name, uint8_t iid[LICHEN_IID_LEN])
{
	if (strlen(name) != SEQ_NAME_LEN) {
		return -ENOENT;
	}
	for (size_t i = 0; i < LICHEN_IID_LEN; i++) {
		int hi = hex_nibble(name[2U * i]);
		int lo = hex_nibble(name[2U * i + 1U]);

		if (hi < 0 || lo < 0) {
			return -ENOENT;
		}
		iid[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

static struct seq_entry *cache_find(const uint8_t iid[LICHEN_IID_LEN])
{
	for (size_t i = 0; i < ARRAY_SIZE(s_cache); i++) {
		if (s_cache[i].valid &&
		    memcmp(s_cache[i].iid, iid, LICHEN_IID_LEN) == 0) {
			return &s_cache[i];
		}
	}
	return NULL;
}

static struct seq_entry *cache_alloc(const uint8_t iid[LICHEN_IID_LEN])
{
	struct seq_entry *free_slot = NULL;

	for (size_t i = 0; i < ARRAY_SIZE(s_cache); i++) {
		if (!s_cache[i].valid) {
			free_slot = &s_cache[i];
			break;
		}
	}
	if (free_slot == NULL) {
		return NULL;
	}
	memcpy(free_slot->iid, iid, LICHEN_IID_LEN);
	free_slot->valid = true;
	return free_slot;
}

static int slot_claim_settings_set(const char *name, size_t len,
				   settings_read_cb read_cb, void *cb_arg)
{
	uint8_t iid[LICHEN_IID_LEN];
	uint8_t value[sizeof(uint32_t)];
	struct seq_entry *entry;
	ssize_t ret;

	/* Serialize cache mutation: Zephyr may dispatch the handler from a
	 * global settings_load() concurrent with lookup/commit. Safe under
	 * the recursive-load path (cache_load_locked holds s_lock and
	 * Zephyr k_mutex re-locks for the same thread). */
	k_mutex_lock(&s_lock, K_FOREVER);

	if (name_to_iid(name, iid) != 0) {
		k_mutex_unlock(&s_lock);
		return -ENOENT;
	}
	if (len != sizeof(value)) {
		goto out_badmsg;
	}
	ret = read_cb(cb_arg, value, sizeof(value));
	if (ret < 0) {
		k_mutex_unlock(&s_lock);
		return (int)ret;
	}
	if ((size_t)ret != sizeof(value)) {
		goto out_badmsg;
	}

	entry = cache_find(iid);
	if (entry == NULL) {
		entry = cache_alloc(iid);
		if (entry == NULL) {
			LOG_WRN("claim_seq cache full; entry %s not cached",
				name);
			goto out_ok;
		}
	}
	entry->seq = sys_get_le32(value);
	k_mutex_unlock(&s_lock);
	return 0;

out_badmsg:
	k_mutex_unlock(&s_lock);
	return -EBADMSG;
out_ok:
	k_mutex_unlock(&s_lock);
	return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(lichen_slot_claim, SETTINGS_ROOT, NULL,
			       slot_claim_settings_set, NULL, NULL);

static int cache_load_locked(void)
{
	int ret;

	if (s_loaded) {
		return 0;
	}
	ret = settings_subsys_init();
	if (ret == 0) {
		ret = settings_load_subtree(SETTINGS_ROOT);
	}
	if (ret == 0) {
		s_loaded = true;
	}
	return ret;
}

int lichen_slot_claim_seq_lookup(const uint8_t iid[LICHEN_IID_LEN],
				 uint32_t *cached)
{
	const struct seq_entry *entry;
	int ret;

	if (iid == NULL || cached == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_lock, K_FOREVER);
	ret = cache_load_locked();
	if (ret == 0) {
		entry = cache_find(iid);
		if (entry != NULL) {
			*cached = entry->seq;
		} else {
			ret = -ENOENT;
		}
	}
	k_mutex_unlock(&s_lock);
	return ret;
}

int lichen_slot_claim_seq_commit(const uint8_t iid[LICHEN_IID_LEN],
				 uint32_t seq)
{
	char name[sizeof(SETTINGS_ROOT) + SEQ_NAME_LEN + 1U];
	uint8_t value[sizeof(uint32_t)];
	struct seq_entry *entry;
	bool reserved = false;
	int ret;

	if (iid == NULL) {
		return -EINVAL;
	}

	k_mutex_lock(&s_lock, K_FOREVER);
	ret = cache_load_locked();
	if (ret != 0) {
		goto unlock;
	}

	entry = cache_find(iid);
	if (entry != NULL && entry->seq >= seq) {
		/* Monotonic high-water: never regress the floor, even if a
		 * concurrent gate check raced past an older lookup. */
		ret = 0;
		goto unlock;
	}

	if (entry == NULL) {
		/* Reserve cache capacity BEFORE the NV write: with no
		 * cached floor there is nothing to compare seq against, so
		 * a cached-miss commit could regress the persisted floor
		 * of a gateway whose entry was dropped at load. Fail
		 * closed instead: the caller turns this into
		 * LICHEN_CLAIM_REJECT_PERSIST and NV stays untouched. */
		entry = cache_alloc(iid);
		if (entry == NULL) {
			LOG_WRN("claim_seq cache full; seq %u not persisted",
				seq);
			ret = -ENOBUFS;
			goto unlock;
		}
		reserved = true;
	}

	strcpy(name, SETTINGS_ROOT "/");
	iid_to_name(iid, &name[sizeof(SETTINGS_ROOT)]);
	sys_put_le32(seq, value);
	ret = settings_save_one(name, value, sizeof(value));
	if (ret != 0) {
		/* Roll back the reservation so a transient NV failure does
		 * not leave a stale seq-0 entry shadowing a real floor. */
		if (reserved) {
			entry->valid = false;
		}
		goto unlock;
	}
	entry->seq = seq;
	ret = 0;

unlock:
	k_mutex_unlock(&s_lock);
	return ret;
}

#ifdef CONFIG_LICHEN_SLOT_CLAIM_REPLAY_TEST_HOOKS
void lichen_slot_claim_seq_test_reset(void)
{
	k_mutex_lock(&s_lock, K_FOREVER);
	memset(s_cache, 0, sizeof(s_cache));
	s_loaded = false;
	k_mutex_unlock(&s_lock);
}
#endif
