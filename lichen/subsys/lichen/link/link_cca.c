/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file link_cca.c
 * @brief Link-layer pre-TX CCA gate (CCP-15)
 *
 * spec/02a-coordinated-capacity.md 2a.10.5: one CAD per transmit
 * opportunity, result fed to CcaUpdate, fail closed on RETRY_EXHAUSTED.
 * The CAD probe is injected per context (lichen_link_set_cca_ops()) so
 * this dependency-free link layer never calls the radio L2 directly
 * (project-LICHEN-i0t6). Contention state lives in ctx->csma and advances
 * across calls exactly per test/vectors/ccp15.json category `cca`.
 */

#include <lichen/link_ctx.h>

#include <lichen/csma.h>
#include <lichen/link.h>

#include <errno.h>

int lichen_link_set_cca_ops(struct lichen_link_ctx *ctx,
			    const struct lichen_link_cca_ops *ops)
{
	if (ctx == NULL) {
		return -EINVAL;
	}

	if (ops == NULL) {
		/* Clear: the gate reverts to its fail-open pass-through. */
		ctx->cca_ops.rng = NULL;
		ctx->cca_ops.cad = NULL;
		ctx->cca_ops.user = NULL;
		return 0;
	}

	/* A probe without a CSPRNG cannot price the next contention window
	 * after a busy CAD (csma_backoff_ms needs rng once the exponent is
	 * nonzero), and a CSPRNG without a probe gates on nothing. Reject
	 * partial installations instead of failing open mid-cycle. */
	if (ops->rng == NULL || ops->cad == NULL) {
		return -EINVAL;
	}

	ctx->cca_ops.rng = ops->rng;
	ctx->cca_ops.cad = ops->cad;
	ctx->cca_ops.user = ops->user;
	return 0;
}

int lichen_link_cca_gate(struct lichen_link_ctx *ctx)
{
#if defined(CONFIG_LICHEN_LINK_CCA)
	uint32_t backoff_ms;
	bool channel_busy;
	int cad_status;
	int cca;

	if (ctx == NULL) {
		return -EINVAL;
	}

	if (ctx->cca_ops.cad == NULL || ctx->cca_ops.rng == NULL) {
		/* No probe registered: pass through. The enforcing
		 * fail-closed CSMA/CA for the Zephyr net path runs at the
		 * radio boundary (lichen_lora_l2_tx() ->
		 * lichen_csma_acquire(), CONFIG_LICHEN_LORA_CCA) under the
		 * modem mutex, so this pass-through cannot bypass CCA
		 * there. */
		return 0;
	}

	/* Open a contention cycle unless one is already in progress.
	 * Exponent 0 costs no RNG draw and no wait. -EALREADY from
	 * BACKOFF continues the current cycle (state carried across
	 * opportunities per 2a.10.5); ERROR/CANCELLED/EXHAUSTED start a
	 * fresh cycle so a wedged radio or a cancelled shutdown cannot
	 * wedge TX permanently — deferral is the caller's retry policy. */
	cca = lichen_csma_start(&ctx->csma, 0U, ctx->cca_ops.rng,
				ctx->cca_ops.user, &backoff_ms);
	if (cca < 0 && cca != -EALREADY) {
		return cca;
	}

	cca = lichen_csma_cad_begin(&ctx->csma);
	if (cca < 0) {
		return cca;
	}

	/* Fail closed if a probe forgets to write its verdict. */
	channel_busy = true;
	cad_status = ctx->cca_ops.cad(ctx->cca_ops.user,
				      LICHEN_CSMA_CAD_TIMEOUT_SYMBOLS,
				      &channel_busy);
	cca = lichen_csma_cad_complete(&ctx->csma, cad_status, channel_busy,
				       ctx->cca_ops.rng, ctx->cca_ops.user,
				       &backoff_ms);

	/* backoff_ms prices the wait BEFORE the next opportunity; in this
	 * per-opportunity gate the wait belongs to the caller's retry
	 * policy, so the value is intentionally discarded here. */
	(void)backoff_ms;

	switch (cca) {
	case LICHEN_CSMA_RESULT_TX_ALLOWED:
		/* The gate owns the whole opportunity lifecycle: a clear CAD
		 * already reset contention state, so close the cycle now and
		 * leave the machine IDLE for the next call — an abandoned TX
		 * after the gate must not strand TX_ALLOWED phase. */
		(void)lichen_csma_tx_complete(&ctx->csma, 0);
		return 0;
	case LICHEN_CSMA_RESULT_CAD_BUSY:
	case LICHEN_CSMA_RESULT_CAD_TIMEOUT:
	case LICHEN_CSMA_RESULT_RETRY_EXHAUSTED:
		/* Defer this opportunity; CcaState advanced for the next
		 * call (2a.10.5: busy/defer, fail closed on exhaustion). */
		return -EBUSY;
	case LICHEN_CSMA_RESULT_CANCELLED:
		return -ECANCELED;
	default:
		return cca < 0 ? cca : -EIO;
	}
#else
	(void)ctx;
	return 0;
#endif /* CONFIG_LICHEN_LINK_CCA */
}
