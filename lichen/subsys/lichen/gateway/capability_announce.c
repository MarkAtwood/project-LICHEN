/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <string.h>

#include <lichen/gateway/capability_announce.h>

#ifdef __ZEPHYR__
#include <tinycrypt/sha256.h>
#include <tinycrypt/constants.h>
#include <lichen/link_ctx.h>
#include <lichen/schnorr48.h>
#endif

static const uint8_t protected_header[] = { 0xa1, 0x01, 0x3a, 0x00, 0x01, 0x00, 0x00 };

struct cursor {
	const uint8_t *p;
	size_t left;
};

static struct lichen_capability_result denial(enum lichen_capability_denial why)
{
	return (struct lichen_capability_result){ false, why };
}

static struct lichen_capability_result verified(void)
{
	return (struct lichen_capability_result){ true, LICHEN_CAPABILITY_DENIAL_NONE };
}

static bool crypto_valid(const struct lichen_capability_crypto *c)
{
	return c != NULL && c->sha256 != NULL && c->derive_iid != NULL && c->verify != NULL;
}

static bool prefix_valid(const uint8_t prefix[16], uint8_t bits)
{
	uint8_t rem;
	size_t first;

	if (bits > 128U) {
		return false;
	}
	first = (size_t)((bits + 7U) / 8U);
	rem = bits & 7U;
	if (rem != 0U && first != 0U && (prefix[first - 1U] & ((1U << (8U - rem)) - 1U)) != 0U) {
		return false;
	}
	for (size_t i = first; i < 16U; i++) {
		if (prefix[i] != 0U) {
			return false;
		}
	}
	return true;
}

static size_t put_bstr(uint8_t *out, const uint8_t *data, size_t len)
{
	size_t n;
	if (len < 24U) {
		out[0] = (uint8_t)(0x40U | len);
		n = 1;
	} else if (len <= UINT8_MAX) {
		out[0] = 0x58;
		out[1] = (uint8_t)len;
		n = 2;
	} else {
		return 0;
	}
	memcpy(out + n, data, len);
	return n + len;
}

static bool take(struct cursor *c, uint8_t expected)
{
	if (c->left == 0U || *c->p != expected) return false;
	c->p++; c->left--;
	return true;
}

static bool get_uint(struct cursor *c, uint8_t major, uint64_t *value)
{
	uint8_t ai;
	size_t bytes;
	uint64_t v = 0;

	if (c->left == 0U || (*c->p >> 5) != major) return false;
	ai = *c->p++ & 31U; c->left--;
	if (ai < 24U) { *value = ai; return true; }
	if (ai == 24U) bytes = 1; else if (ai == 25U) bytes = 2;
	else if (ai == 26U) bytes = 4; else if (ai == 27U) bytes = 8; else return false;
	if (c->left < bytes) return false;
	for (size_t i = 0; i < bytes; i++) v = (v << 8) | c->p[i];
	if ((bytes == 1 && v < 24U) || (bytes == 2 && v <= UINT8_MAX) ||
	    (bytes == 4 && v <= UINT16_MAX) || (bytes == 8 && v <= UINT32_MAX)) return false;
	c->p += bytes; c->left -= bytes; *value = v;
	return true;
}

static bool get_bstr(struct cursor *c, const uint8_t **data, size_t *len)
{
	uint64_t n;
	if (!get_uint(c, 2, &n) || n > SIZE_MAX || c->left < (size_t)n) return false;
	*data = c->p; *len = (size_t)n; c->p += (size_t)n; c->left -= (size_t)n;
	return true;
}

/* Payload map, canonical integer keys 1..6 in order, no trailing bytes. */
static bool decode_payload(const uint8_t *data, size_t len, struct lichen_capability_payload *payload)
{
	struct cursor c = { data, len };
	const uint8_t *p;
	size_t n;
	uint64_t v;
	struct lichen_capability_payload tmp = { 0 };

	if (!take(&c, 0xa6) || !take(&c, 0x01) || !get_uint(&c, 0, &v) || v > UINT32_MAX) return false;
	tmp.capabilities = (uint32_t)v;
	/* Prefix bytes: at most 16, carrying at least the significant
	 * (prefix_len+7)/8 bytes; any trailing zero-extension up to 16 is
	 * accepted and validated by prefix_valid (the shared corpus
	 * zero-pads prefixes to 16 bytes, matching the Rust decoder). */
	if (!take(&c, 0x02) || !get_bstr(&c, &p, &n) || n > 16U) return false;
	memcpy(tmp.prefix, p, n);
	if (!take(&c, 0x03) || !get_uint(&c, 0, &v) || v > 128U || n < (v + 7U) / 8U) return false;
	tmp.prefix_len = (uint8_t)v;
	if (!prefix_valid(tmp.prefix, tmp.prefix_len)) return false;
	if (!take(&c, 0x04) || !get_uint(&c, 0, &tmp.expiry)) return false;
	if (!take(&c, 0x05) || !get_uint(&c, 0, &tmp.seq)) return false;
	if (!take(&c, 0x06) || !get_bstr(&c, &p, &n) || n != 8U || c.left != 0U) return false;
	memcpy(tmp.announcer_iid, p, 8); *payload = tmp;
	return true;
}

static int signature_digest(const struct lichen_capability_crypto *crypto,
			    const uint8_t header[7], const uint8_t *payload,
			    size_t payload_len, uint8_t digest[32])
{
	uint8_t structure[112];
	size_t n = 0;
	static const uint8_t context[] = "Signature1";
	int rc;

	/* verify() is a public entry point: bound the payload up front so a
	 * caller-built announcement can neither overflow the buffer nor
	 * silently drop the payload from the hashed transcript (21 bytes of
	 * fixed structure + 2-byte payload bstr head worst case). */
	if (payload_len > 255U || 21U + 2U + payload_len > sizeof(structure)) return -EIO;
	structure[n++] = 0x84;
	structure[n++] = 0x6a;
	memcpy(structure + n, context, sizeof(context) - 1U);
	n += sizeof(context) - 1U;
	n += put_bstr(structure + n, header, 7U);
	structure[n++] = 0x40;
	n += put_bstr(structure + n, payload, payload_len);
	rc = crypto->sha256(structure, n, digest);
	memset(structure, 0, sizeof(structure));
	return rc;
}

bool lichen_capability_announce_decode(const uint8_t *body, size_t body_len,
				       struct lichen_capability_announcement *out,
				       enum lichen_capability_denial *why)
{
	struct cursor c;
	const uint8_t *p;
	size_t n;
	uint8_t kid[8];

	if (why != NULL) *why = LICHEN_CAPABILITY_DENIAL_MALFORMED;
	if (out == NULL || body == NULL) return false;

	c = (struct cursor){ body, body_len };
	if (!take(&c, 0x84) || !get_bstr(&c, &p, &n)) return false;
	if (n != sizeof(protected_header) || memcmp(p, protected_header, n) != 0) {
		/* A canonical one-entry alg map with another value is an
		 * unsupported algorithm.  All other encodings (including
		 * duplicate alg keys) are malformed rather than an
		 * algorithm oracle. */
		if (n >= 2U && p[0] == 0xa1U && p[1] == 0x01U) {
			if (why != NULL) *why = LICHEN_CAPABILITY_DENIAL_ALGORITHM;
		}
		return false;
	}
	memcpy(out->protected_header, p, sizeof(protected_header));
	if (!take(&c, 0xa1) || !take(&c, 0x04) || !get_bstr(&c, &p, &n) || n != 8U) {
		if (why != NULL) *why = LICHEN_CAPABILITY_DENIAL_KID_MISMATCH;
		return false;
	}
	memcpy(kid, p, 8);
	if (!get_bstr(&c, &p, &n)) return false;
	out->payload_bytes = p;
	out->payload_len = n;
	if (!decode_payload(p, n, &out->payload)) return false;
	if (!get_bstr(&c, &p, &n) || n != 48U || c.left != 0U) return false;
	memcpy(out->signature, p, 48);
	if (memcmp(kid, out->payload.announcer_iid, 8) != 0) {
		if (why != NULL) *why = LICHEN_CAPABILITY_DENIAL_KID_MISMATCH;
		return false;
	}
	if (why != NULL) *why = LICHEN_CAPABILITY_DENIAL_NONE;
	return true;
}

struct lichen_capability_result lichen_capability_announce_verify(
	const struct lichen_capability_crypto *crypto,
	const struct lichen_capability_announcement *announcement,
	const uint8_t announcer_pubkey[32], uint64_t now, const uint64_t *cached_seq)
{
	uint8_t digest[32], derived[8];
	struct lichen_capability_result result;

	if (!crypto_valid(crypto) || announcement == NULL || announcer_pubkey == NULL) {
		return denial(LICHEN_CAPABILITY_DENIAL_MALFORMED);
	}
	if ((announcement->payload.capabilities & LICHEN_CAPABILITY_RESERVED_MASK) != 0U) {
		return denial(LICHEN_CAPABILITY_DENIAL_RESERVED_BITS);
	}
	if (crypto->derive_iid(announcer_pubkey, derived) != 0 ||
	    memcmp(derived, announcement->payload.announcer_iid, 8) != 0) {
		memset(derived, 0, sizeof(derived));
		return denial(LICHEN_CAPABILITY_DENIAL_IID_MISMATCH);
	}
	if (signature_digest(crypto, announcement->protected_header, announcement->payload_bytes,
			     announcement->payload_len, digest) != 0 ||
	    !crypto->verify(announcer_pubkey, digest, announcement->signature)) {
		memset(digest, 0, sizeof(digest));
		return denial(LICHEN_CAPABILITY_DENIAL_SIGNATURE);
	}
	memset(digest, 0, sizeof(digest));
	if (announcement->payload.expiry <= now) {
		return denial(LICHEN_CAPABILITY_DENIAL_EXPIRED);
	}
	if (cached_seq != NULL && announcement->payload.seq <= *cached_seq) {
		return denial(LICHEN_CAPABILITY_DENIAL_REPLAY);
	}
	result = verified();
	return result;
}

#ifdef __ZEPHYR__
static int default_sha256(const uint8_t *input, size_t len, uint8_t out[32])
{
	struct tc_sha256_state_struct s;
	return tc_sha256_init(&s) == TC_CRYPTO_SUCCESS && tc_sha256_update(&s, input, len) == TC_CRYPTO_SUCCESS &&
	       tc_sha256_final(out, &s) == TC_CRYPTO_SUCCESS ? 0 : -EIO;
}
static bool default_verify(const uint8_t pk[32], const uint8_t d[32], const uint8_t s[48])
{ return schnorr48_verify(pk, d, 32, s, 48); }
int lichen_capability_announce_default_crypto(struct lichen_capability_crypto *crypto)
{
	if (crypto == NULL) return -EINVAL;
	*crypto = (struct lichen_capability_crypto){ default_sha256, lichen_key_pubkey_to_iid, default_verify };
	return 0;
}
#else
int lichen_capability_announce_default_crypto(struct lichen_capability_crypto *crypto)
{ (void)crypto; return -ENOTSUP; }
#endif

/* ---------------------------------------------------------------------------
 * Capability table (spec 8.12)
 *
 * Bounded LRU cache of accepted announcements keyed by announcer IID, with a
 * monotone per-IID seq floor captured at eviction.  Semantics mirror the
 * Python CapabilityTable and Rust CapabilityTable so all three stacks agree
 * on supersession, egress reservation, and rollback resistance.
 */

static void table_lock(struct lichen_capability_table *t)
{
	while (atomic_flag_test_and_set_explicit(&t->lock, memory_order_acquire)) {
	}
}

static void table_unlock(struct lichen_capability_table *t)
{
	atomic_flag_clear_explicit(&t->lock, memory_order_release);
}

static int entry_find(struct lichen_capability_table *t, const uint8_t iid[8])
{
	for (size_t i = 0; i < CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY; i++)
		if (t->entries[i].used && memcmp(t->entries[i].announcer_iid, iid, 8) == 0)
			return (int)i;
	return -1;
}

static int floor_find(struct lichen_capability_table *t, const uint8_t iid[8])
{
	for (size_t i = 0; i < CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY; i++)
		if (t->floors[i].used && memcmp(t->floors[i].announcer_iid, iid, 8) == 0)
			return (int)i;
	return -1;
}

/* Pick the floor slot to reclaim when the ledger is full: the lowest-IID
 * floor whose IID is no longer a live entry.  Floors for active entries
 * are redundant (their entry.seq already pins the floor) and always
 * retained; if every floor is live-pinned nothing can be reclaimed.  A
 * pending raiser whose entry does not exist yet participates as a virtual
 * candidate — its floor would be redundant with the entry about to go
 * live, so when it is the lowest candidate the references' raise-then-
 * bound order drops the fresh floor again, i.e. no floor is created.
 * Mirrors Python CapabilityTable._bound_floors / Rust bound_seq_floors so
 * a dead announcer's floor cannot permanently starve eviction-captured
 * floors for newly evicted IIDs.  Returns the slot index, or -1.
 * O(capacity^2) worst case, bounded by
 * CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY. */
static int floor_prune(struct lichen_capability_table *t, const uint8_t pending[8],
		       bool pending_eligible)
{
	int victim = -1;

	for (size_t i = 0; i < CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY; i++) {
		if (!t->floors[i].used) continue;
		if (entry_find(t, t->floors[i].announcer_iid) >= 0) continue;
		if (victim < 0 ||
		    memcmp(t->floors[i].announcer_iid,
			   t->floors[victim].announcer_iid, 8) < 0) {
			victim = (int)i;
		}
	}
	if (!pending_eligible) return victim;
	if (victim < 0 || memcmp(pending, t->floors[victim].announcer_iid, 8) < 0) return -1;
	return victim;
}

static void floor_raise(struct lichen_capability_table *t, const uint8_t iid[8], uint64_t seq)
{
	int fi = floor_find(t, iid);
	if (fi < 0) {
		int slot = -1;
		for (size_t i = 0; i < CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY; i++)
			if (!t->floors[i].used) { slot = (int)i; break; }
		if (slot < 0) {
			slot = floor_prune(t, iid, entry_find(t, iid) < 0);
			if (slot < 0) return; /* all floors live-pinned, or a
						 pending raiser that is itself
						 the lowest prune candidate */
			t->floors[slot].used = false;
		}
		t->floors[slot].used = true;
		memcpy(t->floors[slot].announcer_iid, iid, 8);
		t->floors[slot].floor = seq;
		return;
	}
	if (seq > t->floors[fi].floor) t->floors[fi].floor = seq;
}

void lichen_capability_table_init(struct lichen_capability_table *table)
{
	if (table == NULL) return;
	memset(table, 0, sizeof(*table));
	atomic_flag_clear(&table->lock);
}

int64_t lichen_capability_table_cached_seq(struct lichen_capability_table *table,
					   const uint8_t announcer_iid[8])
{
	if (table == NULL || announcer_iid == NULL) return -1;
	table_lock(table);
	int64_t best = -1;
	int fi = floor_find(table, announcer_iid);
	if (fi >= 0) best = (int64_t)table->floors[fi].floor;
	int ei = entry_find(table, announcer_iid);
	if (ei >= 0) {
		if ((int64_t)table->entries[ei].seq > best) best = (int64_t)table->entries[ei].seq;
		table->entries[ei].last_used = ++table->tick;
	}
	table_unlock(table);
	return best;
}

bool lichen_capability_table_record(struct lichen_capability_table *table,
				    const struct lichen_capability_payload *payload)
{
	if (table == NULL || payload == NULL) return false;
	bool egress = (payload->capabilities & LICHEN_CAPABILITY_EGRESS) != 0U;
	size_t effective = egress ? CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY
				  : CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY - LICHEN_CAPABILITY_EGRESS_RESERVED;
	table_lock(table);
	int ei = entry_find(table, payload->announcer_iid);
	if (ei >= 0) {
		struct lichen_capability_table_entry *e = &table->entries[ei];
		e->capabilities = payload->capabilities;
		e->expiry = payload->expiry;
		e->seq = payload->seq;
		e->last_used = ++table->tick;
		floor_raise(table, payload->announcer_iid, payload->seq);
		table_unlock(table);
		return true;
	}
	if (table->entry_count >= effective) {
		/* Table full for this class.  Only an egress insert may reclaim
		 * the reserved tail by evicting the LRU entry; a non-egress
		 * insert is refused so egress announcements always have room. */
		if (!egress) { table_unlock(table); return false; }
		int lru = -1; uint64_t oldest = UINT64_MAX;
		for (size_t i = 0; i < CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY; i++)
			if (table->entries[i].used && table->entries[i].last_used < oldest) {
				oldest = table->entries[i].last_used; lru = (int)i;
			}
		if (lru < 0) { table_unlock(table); return false; }
		floor_raise(table, table->entries[lru].announcer_iid, table->entries[lru].seq);
		table->entries[lru].used = false;
		table->entry_count--;
	}
	int slot = -1;
	for (size_t i = 0; i < CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY; i++)
		if (!table->entries[i].used) { slot = (int)i; break; }
	if (slot < 0) { table_unlock(table); return false; }
	/* Raise and bound the announcer's floor BEFORE the entry goes live
	 * (mirrors Python record() / Rust insert()): while the entry is
	 * still absent the fresh floor is prune-eligible, so the prune
	 * never sacrifices a lower-IID dead floor for a floor the live
	 * entry makes redundant. */
	floor_raise(table, payload->announcer_iid, payload->seq);
	struct lichen_capability_table_entry *e = &table->entries[slot];
	e->used = true;
	memcpy(e->announcer_iid, payload->announcer_iid, 8);
	e->capabilities = payload->capabilities;
	e->expiry = payload->expiry;
	e->seq = payload->seq;
	e->last_used = ++table->tick;
	table->entry_count++;
	table_unlock(table);
	return true;
}

size_t lichen_capability_table_purge_expired(struct lichen_capability_table *table,
					     uint64_t now)
{
	if (table == NULL) return 0;
	size_t purged = 0;
	table_lock(table);
	for (size_t i = 0; i < CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY; i++) {
		if (table->entries[i].used && table->entries[i].expiry <= now) {
			/* No floor capture at purge: Python purge_expired (the
			 * only reference with expiry) just deletes the entry —
			 * floors there are already >= entry.seq, and capturing
			 * a floor for a floorless entry here would diverge. */
			table->entries[i].used = false;
			table->entry_count--;
			purged++;
		}
	}
	table_unlock(table);
	return purged;
}
