/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <lichen/errno.h>
#include <lichen/link_ctx.h>
#include <string.h>

/* The CCA gate propagates the link layer's -EBUSY (plain <errno.h>, as in
 * csma.c). Do NOT include a system <errno.h> here: lichen/errno.h pins the
 * LICHEN portable values (e.g. EOVERFLOW 75) and a system header included
 * first would shadow them with Darwin's (EOVERFLOW 84), breaking
 * cross-translation-unit comparisons. EBUSY is absent from lichen/errno.h;
 * 16 is its value on both Linux and Darwin. */
#ifndef EBUSY
#define EBUSY 16
#endif

static bool entropy_fails;
static uint8_t entropy_byte;

int getentropy(void *buffer, size_t length)
{
	if (entropy_fails) {
		return -1;
	}

	memset(buffer, entropy_byte, length);
	return 0;
}

static int test_entropy_failure_preserves_context(void)
{
	const uint8_t eui64[LICHEN_EUI64_LEN] = { 0 };
	struct lichen_link_ctx ctx;
	struct lichen_link_ctx before;

	memset(&ctx, 0xa5, sizeof(ctx));
	memcpy(&before, &ctx, sizeof(before));
	entropy_fails = true;
	if (lichen_link_init(&ctx, eui64) != -EIO) {
		return 1;
	}
	return memcmp(&ctx, &before, sizeof(ctx)) != 0;
}

static int test_entropy_success_maps_epoch(void)
{
	const uint8_t eui64[LICHEN_EUI64_LEN] = {
		0x02, 0x00, 0x5e, 0x10, 0x20, 0x30, 0x40, 0x50
	};
	struct lichen_link_ctx ctx;

	entropy_fails = false;
	entropy_byte = 0x42;
	if (lichen_link_init(&ctx, eui64) != 0) {
		return 1;
	}
	int failed = ctx.epoch != 0xc2 || ctx.tx_seq != 0 || ctx.has_key ||
		ctx.has_link_key || ctx.nonce_exhausted ||
		memcmp(ctx.eui64, eui64, sizeof(eui64)) != 0;
	struct lichen_csma_snapshot csma;
	failed |= lichen_csma_snapshot(&ctx.csma, &csma) != 0 ||
		  csma.phase != LICHEN_CSMA_IDLE || csma.backoff_exponent != 0U ||
		  csma.retries != 0U || csma.cancel_requested;
	lichen_link_cleanup(&ctx);
	return failed;
}

static int test_terminal_epoch_never_wraps(void)
{
	const uint8_t eui64[LICHEN_EUI64_LEN] = { 0 };
	struct lichen_link_ctx ctx;
	uint8_t epoch = 0;
	uint16_t sequence = 0;

	entropy_fails = false;
	if (lichen_link_init(&ctx, eui64) != 0) {
		return 1;
	}
	ctx.epoch = UINT8_MAX;
	ctx.tx_seq = UINT16_MAX;
	int failed = lichen_link_next_tx(&ctx, &epoch, &sequence) != 0 ||
		epoch != UINT8_MAX || sequence != UINT16_MAX ||
		ctx.epoch != UINT8_MAX || ctx.tx_seq != UINT16_MAX ||
		!ctx.nonce_exhausted;
	failed |= lichen_link_next_tx(&ctx, &epoch, &sequence) != -EOVERFLOW;
	lichen_link_cleanup(&ctx);
	return failed;
}

/* --- CCA gate (CCP-15 2a.10.5, test/vectors/ccp15.json category `cca`) --- */

struct cca_fake {
	int cad_status;      /* negative driver error, or 0 */
	bool busy;           /* verdict written by the fake CAD */
	unsigned cad_calls;
	unsigned rng_calls;
	uint32_t rng_value;
};

static int fake_rng(void *user, uint32_t *value)
{
	struct cca_fake *f = user;

	f->rng_calls++;
	*value = f->rng_value;
	return 0;
}

static int fake_cad(void *user, uint8_t timeout_symbols, bool *channel_busy)
{
	struct cca_fake *f = user;

	(void)timeout_symbols;
	f->cad_calls++;
	*channel_busy = f->busy;
	return f->cad_status;
}

static int cca_ctx_init(struct lichen_link_ctx *ctx, struct cca_fake *fake)
{
	const uint8_t eui64[LICHEN_EUI64_LEN] = {
		0x02, 0x00, 0x5e, 0x10, 0x20, 0x30, 0x40, 0x50
	};

	entropy_fails = false;
	entropy_byte = 0x42;
	memset(fake, 0, sizeof(*fake));
	fake->cad_status = 0;
	if (lichen_link_init(ctx, eui64) != 0) {
		return -1;
	}
	struct lichen_link_cca_ops ops = {
		.rng = fake_rng,
		.cad = fake_cad,
		.user = fake,
	};
	if (lichen_link_set_cca_ops(ctx, &ops) != 0) {
		lichen_link_cleanup(ctx);
		return -1;
	}
	return 0;
}

static int test_cca_setter_validation(void)
{
	const uint8_t eui64[LICHEN_EUI64_LEN] = { 0 };
	struct lichen_link_ctx ctx;
	struct lichen_link_cca_ops both = { .rng = fake_rng, .cad = fake_cad };
	struct lichen_link_cca_ops cad_only = { .cad = fake_cad };
	struct lichen_link_cca_ops rng_only = { .rng = fake_rng };

	entropy_fails = false;
	if (lichen_link_init(&ctx, eui64) != 0) {
		return 1;
	}
	int failed = lichen_link_set_cca_ops(NULL, &both) != -EINVAL ||
		     lichen_link_set_cca_ops(&ctx, &cad_only) != -EINVAL ||
		     lichen_link_set_cca_ops(&ctx, &rng_only) != -EINVAL;
	/* A rejected partial install must leave the gate unregistered. */
	failed |= ctx.cca_ops.cad != NULL || ctx.cca_ops.rng != NULL;
	failed |= lichen_link_set_cca_ops(&ctx, &both) != 0 ||
		  ctx.cca_ops.cad != fake_cad || ctx.cca_ops.rng != fake_rng;
	/* NULL clears the probe (fail-open pass-through restored). */
	failed |= lichen_link_set_cca_ops(&ctx, NULL) != 0 ||
		  ctx.cca_ops.cad != NULL || ctx.cca_ops.rng != NULL;
	lichen_link_cleanup(&ctx);
	return failed;
}

static int test_cca_gate_clear_resets_and_closes_cycle(void)
{
	struct lichen_link_ctx ctx;
	struct cca_fake fake;

	if (cca_ctx_init(&ctx, &fake) != 0) {
		return 1;
	}
	/* Drive the machine mid-cycle first (one busy observation). */
	fake.busy = true;
	int failed = lichen_link_cca_gate(&ctx) != -EBUSY;
	/* ccp15.json cca_clear_resets_contention: any busy state + clear CAD
	 * -> tx_success with contention state fully reset. */
	fake.busy = false;
	failed |= lichen_link_cca_gate(&ctx) != 0;
	struct lichen_csma_snapshot snap;
	failed |= lichen_csma_snapshot(&ctx.csma, &snap) != 0 ||
		  snap.phase != LICHEN_CSMA_IDLE ||
		  snap.backoff_exponent != 0U || snap.retries != 0U;
	/* Clear CAD draws no contention window at exponent 0: the only RNG
	 * use so far is the single busy completion above. */
	failed |= fake.rng_calls != 1U || fake.cad_calls != 2U;
	/* Gate is repeatable: each call is one fresh transmit opportunity. */
	failed |= lichen_link_cca_gate(&ctx) != 0;
	failed |= lichen_csma_snapshot(&ctx.csma, &snap) != 0 ||
		  snap.phase != LICHEN_CSMA_IDLE;
	lichen_link_cleanup(&ctx);
	return failed;
}

static int test_cca_gate_busy_advances_per_ccp15(void)
{
	struct lichen_link_ctx ctx;
	struct cca_fake fake;

	if (cca_ctx_init(&ctx, &fake) != 0) {
		return 1;
	}
	fake.busy = true;
	/* ccp15.json cca_busy_advances_contention: busy CAD -> cad_busy with
	 * BackoffExp+1 and Retries+1, TxAllowed=false. From the initial
	 * (exp 0, retries 0) the first busy lands on (1, 1). */
	int failed = lichen_link_cca_gate(&ctx) != -EBUSY;
	struct lichen_csma_snapshot snap;
	failed |= lichen_csma_snapshot(&ctx.csma, &snap) != 0 ||
		  snap.phase != LICHEN_CSMA_BACKOFF ||
		  snap.backoff_exponent != 1U || snap.retries != 1U;
	failed |= lichen_link_cca_gate(&ctx) != -EBUSY ||
		  lichen_link_cca_gate(&ctx) != -EBUSY;
	failed |= lichen_csma_snapshot(&ctx.csma, &snap) != 0 ||
		  snap.backoff_exponent != 3U || snap.retries != 3U;
	/* ccp15.json cca_retry_limit_exhausted: busy past CSMA_RETRY_LIMIT
	 * (3) -> retry_exhausted, retries incremented one final time, fail
	 * closed. The stored retries (4) exceeds the limit (3). */
	failed |= lichen_link_cca_gate(&ctx) != -EBUSY;
	failed |= lichen_csma_snapshot(&ctx.csma, &snap) != 0 ||
		  snap.phase != LICHEN_CSMA_EXHAUSTED || snap.retries != 4U;
	/* A fresh opportunity after exhaustion opens a new contention cycle
	 * (deferral is the caller's retry policy), so a clear channel is
	 * usable again instead of wedging TX permanently. */
	fake.busy = false;
	failed |= lichen_link_cca_gate(&ctx) != 0;
	failed |= lichen_csma_snapshot(&ctx.csma, &snap) != 0 ||
		  snap.phase != LICHEN_CSMA_IDLE || snap.retries != 0U;
	lichen_link_cleanup(&ctx);
	return failed;
}

static int test_cca_gate_driver_error_fails_closed(void)
{
	struct lichen_link_ctx ctx;
	struct cca_fake fake;

	if (cca_ctx_init(&ctx, &fake) != 0) {
		return 1;
	}
	fake.cad_status = -EIO;
	int failed = lichen_link_cca_gate(&ctx) != -EIO;
	struct lichen_csma_snapshot snap;
	failed |= lichen_csma_snapshot(&ctx.csma, &snap) != 0 ||
		  snap.phase != LICHEN_CSMA_ERROR;
	/* Recovery: the next opportunity opens a fresh cycle. */
	fake.cad_status = 0;
	fake.busy = false;
	failed |= lichen_link_cca_gate(&ctx) != 0;
	failed |= lichen_csma_snapshot(&ctx.csma, &snap) != 0 ||
		  snap.phase != LICHEN_CSMA_IDLE;
	lichen_link_cleanup(&ctx);
	return failed;
}

static int test_cca_gate_unregistered_passes_untouched(void)
{
	struct lichen_link_ctx ctx;
	struct cca_fake fake;

	if (cca_ctx_init(&ctx, &fake) != 0) {
		return 1;
	}
	/* Leave the machine mid-cycle, then clear the probe. */
	fake.busy = true;
	int failed = lichen_link_cca_gate(&ctx) != -EBUSY;
	failed |= lichen_link_set_cca_ops(&ctx, NULL) != 0;
	/* No probe registered: the gate passes without observing or
	 * mutating contention state (radio-boundary CSMA remains the
	 * enforcing fail-closed CCA). */
	failed |= lichen_link_cca_gate(&ctx) != 0;
	struct lichen_csma_snapshot snap;
	failed |= lichen_csma_snapshot(&ctx.csma, &snap) != 0 ||
		  snap.phase != LICHEN_CSMA_BACKOFF ||
		  snap.backoff_exponent != 1U || snap.retries != 1U;
	failed |= fake.cad_calls != 1U;
	lichen_link_cleanup(&ctx);
	return failed;
}

int main(void)
{
	if (test_entropy_failure_preserves_context() != 0) {
		return 1;
	}
	if (test_entropy_success_maps_epoch() != 0) {
		return 2;
	}
	if (test_terminal_epoch_never_wraps() != 0) {
		return 3;
	}
	if (test_cca_setter_validation() != 0) {
		return 4;
	}
	if (test_cca_gate_clear_resets_and_closes_cycle() != 0) {
		return 5;
	}
	if (test_cca_gate_busy_advances_per_ccp15() != 0) {
		return 6;
	}
	if (test_cca_gate_driver_error_fails_closed() != 0) {
		return 7;
	}
	if (test_cca_gate_unregistered_passes_untouched() != 0) {
		return 8;
	}
	return 0;
}
