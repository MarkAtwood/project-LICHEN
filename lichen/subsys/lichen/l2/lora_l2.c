/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2.c
 * @brief LICHEN LoRa L2 network interface driver - main module
 *
 * This module provides the bridge between Zephyr's IPv6 stack and LoRa radio.
 * It's structured as a service that can be attached to the default interface
 * rather than creating its own network device (which requires more complex
 * devicetree integration).
 *
 * Architecture:
 *   Application calls lichen_lora_l2_start()
 *       -> Configures LoRa radio
 *       -> Arms asynchronous RX (driver ISR -> workqueue)
 *       -> TX is called directly via lichen_lora_l2_tx(data, len, channel)
 *
 * Threading model:
 * - TX is synchronous (called from application context)
 * - RX is interrupt-driven: the driver ISR callback stages packets and the
 *   system workqueue processes them (see lora_l2_rx.c)
 *
 * Module split:
 * - lora_l2.c: Global state, init/start/stop/deinit, status queries
 * - lora_l2_state.c: State machine transitions
 * - lora_l2_identity.c: EUI-64 generation and access
 * - lora_l2_rx.c: Interrupt-driven RX (arm/re-arm, staging, work handler)
 * - lora_l2_tx.c: Transmit functions
 * - lora_l2_internal.h: Shared definitions
 */

#include "lora_l2_internal.h"
#include "lichen_l2.h"

#include <zephyr/drivers/lora.h>
#include <zephyr/logging/log.h>

#include <lichen/hal.h>

LOG_MODULE_REGISTER(lichen_lora_l2, CONFIG_LICHEN_LORA_L2_LOG_LEVEL);

/* --------------------------------------------------------------------------
 * Global state definitions
 *
 * These are declared extern in lora_l2_internal.h and defined here so there
 * is exactly one copy across all split files.
 * -------------------------------------------------------------------------- */

/*
 * ARCHITECTURAL LIMITATION (project-LICHEN-tvfm.110): This module uses static
 * global state (lora_mutex, tx_buf, lora_data) and supports only one LoRa
 * radio instance per system. The selected device is provided by the HAL's
 * zephyr,lora boundary; multi-radio support would require per-instance
 * context structs, instance enumeration, RX ownership, and API changes to
 * accept an instance handle.
 */
BUILD_ASSERT(DT_NODE_EXISTS(DT_ALIAS(lora0)),
             "lora_l2 requires a 'lora0' devicetree alias for single-radio operation");

/* Mutex protecting state transitions and callback registration */
K_MUTEX_DEFINE(lora_mutex);

/* Mutex protecting TX buffer access - serializes concurrent transmissions.
 * Separate from lora_mutex because TX may block for ~500ms at SF10/255 bytes;
 * holding lora_mutex that long would starve RX callback registration. */
K_MUTEX_DEFINE(tx_buf_mutex);

/*
 * TX/RX modem arbitration (half-duplex radio, non-blocking driver acquire).
 *
 * The sx12xx driver's modem_acquire() is non-blocking: whichever of
 * lora_recv_async()/lora_send() finds the modem held fails immediately with
 * -EBUSY. Interrupt-driven RX re-arms lora_recv_async() back-to-back from
 * the work handler, so it holds the modem near-continuously and TX
 * essentially never wins the race.
 *
 * Fix: TX raises tx_pending before sending. The RX re-arm path checks it
 * before re-arming and defers (delayable retry) while set, so TX acquires
 * the modem as soon as the outstanding RX delivery drains. RX re-arm also
 * uses a non-blocking modem_mutex lock and retries while TX owns the modem.
 * Both sides treat -EBUSY as the expected "other side owns the modem"
 * signal, not an error.
 */
atomic_t tx_pending;

/*
 * Hard mutual exclusion for driver calls (modem_mutex).
 *
 * tx_pending alone only stops the RX path from RE-ARMING lora_recv_async();
 * it does nothing about a delivery already in flight. Drivers do not
 * tolerate concurrent recv+send: the LR1110 driver has no internal locking
 * at all, so a send() issued while an RX delivery is mid-processing
 * interleaves SPI transactions on the same chip - corrupting radio state,
 * spinning both sides in error/retry storms (heavy enough SPIM traffic to
 * wedge nRF52840 USB enumeration as collateral), and putting nothing on the
 * air. The sx12xx driver merely returns -EBUSY. Wrap every
 * lora_recv_async()/lora_send() in modem_mutex so a send waits out the
 * re-arm window and a re-arm yields to an in-flight send (k_mutex priority
 * inheritance protects against inversion).
 */
K_MUTEX_DEFINE(modem_mutex);

/*
 * Internal TX buffer - copied before lora_send() to protect caller's data.
 * Zephyr's lora_send() takes a non-const pointer because some radio drivers
 * may modify the buffer (e.g., for DMA alignment or in-place encryption).
 */
uint8_t tx_buf[LICHEN_LORA_MAX_PHY_PAYLOAD];

/*
 * TX queue for bufferbloat avoidance (spec/appendix-bufferbloat.md).
 * Provides priority queuing, deadline expiry, and explicit backpressure.
 * Protected by tx_buf_mutex (same mutex as tx_buf since they're used together).
 */
struct tx_queue tx_queue;

/*
 * Module data (not state - state is managed by current_state atomic).
 *
 * Access patterns:
 *   - Mutex-protected fields (lora_dev, eui64, rx_callback, rx_callback_user_data):
 *     Must hold lora_mutex for both read and write. Callers read callback pair
 *     atomically via snapshot under lock (see the RX work handler).
 */
struct lora_l2_data lora_data;

/* --------------------------------------------------------------------------
 * Init / Start / Stop / Deinit
 * -------------------------------------------------------------------------- */

int lichen_lora_l2_init(void)
{
    int ret = 0;

    /*
     * Always acquire mutex before checking state. This ensures:
     * 1. If another thread is initializing, we wait until it completes
     * 2. We see the fully initialized state (not partial state mid-init)
     * 3. No TOCTOU race where we return success before EUI-64 is generated
     *
     * The mutex acquisition is the serialization point - we cannot use a
     * fast-path early-return check because that would return success to a
     * caller while another thread is still inside init() generating the EUI-64.
     */
    k_mutex_lock(&lora_mutex, K_FOREVER);

    enum lora_state state = lora_get_state();
    if (state == LORA_STOPPED || state == LORA_RUNNING) {
        k_mutex_unlock(&lora_mutex);
        return 0;
    }
    if (state == LORA_DEINITING) {
        k_mutex_unlock(&lora_mutex);
        return -EBUSY;
    }
    if (state == LORA_ABORTED || state == LORA_DESTROY_FAILED) {
        k_mutex_unlock(&lora_mutex);
        return -ECANCELED;
    }
    if (state != LORA_UNINIT) {
        k_mutex_unlock(&lora_mutex);
        return -EINVAL;
    }

    ret = lichen_hal_lora_device_get(&lora_data.lora_dev);
    if (ret < 0) {
        LOG_ERR("lora_l2: failed to get LoRa device from HAL (%d)", ret);
        goto out;
    }
    lora_data.rx_callback = NULL;
    lora_data.rx_callback_user_data = NULL;
    lora_data.cca_enabled = IS_ENABLED(CONFIG_LICHEN_LORA_CCA);
    lichen_csma_init(&lora_data.csma);
    if (lora_data.cca_enabled) {
        LOG_DBG("lora_l2: CCA enabled, threshold %d dBm, timeout %d ms",
                CONFIG_LICHEN_LORA_CCA_THRESHOLD_DBM,
                CONFIG_LICHEN_LORA_CCA_TIMEOUT_MS);
    }
    lora_data.rx_channel = 0;
#if IS_ENABLED(CONFIG_LICHEN_DUTY_CYCLE)
    lora_data.density = 0;
    lichen_duty_cycle_init(&lora_data.duty,
                           adaptive_duty_permille(lora_data.density,
                                                  lora_l2_duty_region()));
#endif

    if (!device_is_ready(lora_data.lora_dev)) {
        LOG_ERR("lora_l2: device not ready");
        ret = -ENODEV;
        goto out;
    }

    ret = generate_eui64(lora_data.eui64);
    if (ret < 0) {
        LOG_ERR("lora_l2: failed to generate stable EUI-64, cannot initialize");
        goto out;
    }

    /* Initialize TX queue for bufferbloat avoidance */
    ret = tx_queue_init(&tx_queue);
    if (ret < 0) {
        LOG_ERR("lora_l2: failed to initialize TX queue (%d)", ret);
        goto out;
    }

    if (lora_transition(LORA_STOPPED) != 0) {
        ret = -EIO;
        goto out;
    }
    LOG_INF("lora_l2: initialized");

out:
    k_mutex_unlock(&lora_mutex);
    return ret;
}

int lichen_lora_l2_start(void)
{
    enum lora_state state = lora_get_state();

    switch (state) {
    case LORA_UNINIT:
        LOG_ERR("lora_l2: not initialized, call lichen_lora_l2_init() first");
        return -EINVAL;
    case LORA_ABORTED:
        LOG_ERR("lora_l2: in ABORTED state, call deinit() then init()");
        return -ECANCELED;
    case LORA_DESTROY_FAILED:
        LOG_ERR("lora_l2: queue destroy incomplete, retry deinit()");
        return -ECANCELED;
    case LORA_DEINITING:
        LOG_ERR("lora_l2: deinit in progress, cannot start");
        return -EBUSY;
    case LORA_RUNNING:
        return 0;  /* Already running */
    case LORA_STOPPED:
        break;  /* Proceed */
    case LORA_STATE_COUNT:
    default:
        LOG_ERR("lora_l2: unknown state (%d), forcing ABORTED", state);
        atomic_set(&current_state, LORA_ABORTED);
        return -EINVAL;
    }

    k_mutex_lock(&lora_mutex, K_FOREVER);

    /* Double-check state under mutex */
    if (lora_get_state() != LORA_STOPPED) {
        k_mutex_unlock(&lora_mutex);
        return -EAGAIN;
    }

    /*
     * Configure LoRa radio using Kconfig options and LICHEN protocol defaults.
     * Modulation parameters (from <zephyr/drivers/lora.h> enums):
     *   - BW_125_KHZ: 125kHz bandwidth
     *   - SF_9/SF_10: conditional on CONFIG_LICHEN_SF_ASSIGNMENT_ENABLED
     *   - CR_4_5: Coding rate 4/5
     * Matches spec; preamble 8 default. New Kconfigs enable DIO/hash SF
     * assignment and gateway CAD for multi-SF (CONFIG_LICHEN_GATEWAY_MULTI_SF).
     *
     * Static struct: safe even if a driver retains the pointer, since
     * lichen_lora_l2_start() holds lora_mutex and is non-re-entrant.
     *
     * RX then TX pass programs both directions (RX config reused by recv).
     * CAD scan uses the registered CAD hook under multi-SF config (lr1110
     * IRQ extended for PREAMBLEDETECTED per ASSIGNED_SF in DIO).
     */
    static struct lora_modem_config config = {
        .frequency = CONFIG_LICHEN_LORA_FREQUENCY,
        .bandwidth = BW_125_KHZ,
        .datarate = IS_ENABLED(CONFIG_LICHEN_SF_ASSIGNMENT_ENABLED) ? SF_9 : SF_10,
        .coding_rate = CR_4_5,
        .preamble_len = 8,
        .tx_power = CONFIG_LICHEN_LORA_TX_POWER,
        .tx = false,
    };

    int ret = lora_config(lora_data.lora_dev, &config);
    if (ret < 0) {
        LOG_ERR("lora_l2: RX config failed (%d)", ret);
        k_mutex_unlock(&lora_mutex);
        return ret;
    }

    config.tx = true;              /* pass 2: program TX + airtime cache.
                                    * TX-only fields (tx_power, tx=true) configure
                                    * the sx12xx driver's shared TX/RX modem state.
                                    * Half-duplex arbitration uses modem_mutex (TX
                                    * acquires before lora_send(), RX before
                                    * lora_recv()), not the driver's tx flag. The
                                    * tx=true call is still required because
                                    * lora_config() sets per-direction registers
                                    * and the airtime/symbol-time cache used by
                                    * lora_send() internally. */
    ret = lora_config(lora_data.lora_dev, &config);
    if (ret < 0) {
        LOG_ERR("lora_l2: TX config failed (%d)", ret);
        k_mutex_unlock(&lora_mutex);
        return ret;
    }

    if (lora_transition_from(LORA_STOPPED, LORA_RUNNING) != 0) {
        k_mutex_unlock(&lora_mutex);
        return -EAGAIN;
    }

    /*
     * Arm asynchronous RX. The ISR callback only stages packets; processing
     * and re-arming run in the system workqueue (see lora_l2_rx.c).
     *
     * Fail closed: a driver without recv_async support cannot receive at
     * all, so start() reports the error and reverts to STOPPED rather than
     * running with a silently deaf radio.
     */
    ret = lora_l2_rx_start();
    if (ret < 0) {
        LOG_ERR("lora_l2: async RX arm failed (%d)", ret);
        if (lora_transition_from(LORA_RUNNING, LORA_STOPPED) != 0) {
            /* Should be impossible - start() holds lora_mutex. */
            atomic_set(&current_state, LORA_ABORTED);
            LOG_ERR("lora_l2: state corrupted after RX arm failure");
        }
        k_mutex_unlock(&lora_mutex);
        return ret;
    }

    k_mutex_unlock(&lora_mutex);

    LOG_INF("lora_l2: started (%u.%03u MHz, %d dBm, SF10)",
            CONFIG_LICHEN_LORA_FREQUENCY / 1000000, CONFIG_LICHEN_LORA_FREQUENCY % 1000000 / 1000, CONFIG_LICHEN_LORA_TX_POWER);
    return 0;
}

int lichen_lora_l2_stop(void)
{
    int ret = 0;

    /*
     * Fast-path check without mutex: if already not RUNNING, return 0 early.
     * This is intentionally idempotent - concurrent stop() calls are safe.
     * If two threads race in, one will do the work (clear callback, transition),
     * the other will hit the double-check below and return 0. Both return 0;
     * the caller cannot distinguish which one did the work, but the contract
     * only guarantees the post-state (STOPPED) and that rx_callback is NULL.
     */
    if (lora_get_state() != LORA_RUNNING) {
        return 0;  /* Not running, nothing to stop */
    }

    k_mutex_lock(&lora_mutex, K_FOREVER);

    /* Double-check state under mutex */
    if (lora_get_state() != LORA_RUNNING) {
        k_mutex_unlock(&lora_mutex);
        return 0;
    }

    /*
     * Clear RX callback BEFORE disarming. This prevents new callbacks from
     * starting after we begin shutdown. Any in-flight callback (already past
     * the snapshot in the RX work handler) will complete and release
     * rx_mutex before lichen_l2_enable's cleanup runs, since cleanup acquires
     * rx_mutex - the work flush below waits for it.
     *
     * CONTRACT (project-LICHEN-i1gk.48): stop() ALWAYS clears the RX callback.
     * lichen_l2_enable() relies on this to re-register its callback on enable.
     * If this behavior changes, update lichen_l2_enable() which assumes it must
     * call lichen_lora_l2_set_rx_callback() after every stop()/start() cycle.
     * See also lora_l2.h lichen_lora_l2_stop() documentation.
     */
    lora_data.rx_callback = NULL;
    lora_data.rx_callback_user_data = NULL;
    lichen_csma_cancel(&lora_data.csma);

    /* Transition to STOPPED before releasing mutex - RX work sees this */
    if (lora_transition(LORA_STOPPED) != 0) {
        k_mutex_unlock(&lora_mutex);
        return -EIO;
    }

    /* Release mutex before draining - allows any in-flight TX to complete */
    k_mutex_unlock(&lora_mutex);

    /*
     * Disarm the driver and drain the RX work item. When this returns, the
     * ISR is gated off, the driver is disarmed, and the work handler is
     * neither queued nor running - the same guarantee the RX thread join
     * used to provide, without the join/abort failure modes (no forced
     * abort path exists anymore; a wedged driver surfaces as arm/retry
     * errors logged by the RX path instead).
     */
    lora_l2_rx_stop();

    LOG_INF("lora_l2: stopped");
    return ret;
}

int lichen_lora_l2_deinit(void)
{
    /*
     * Declared before the DESTROY_FAILED goto so destroy_queue never reads
     * an indeterminate flag (the retry path jumps past its assignment).
     */
    bool lora_mutex_held = false;
    enum lora_state state = lora_get_state();

    /*
     * Only STOPPED or ABORTED states can transition to DEINITING.
     *
     * SECURITY: This appears to be a TOCTOU pattern (read state, then act on it),
     * but is actually safe: lora_transition_from() uses atomic CAS internally,
     * so if the state changes between lora_get_state() and the CAS, the CAS
     * fails atomically and we return -EBUSY. The initial read is merely an
     * optimization to select which expected-state to pass to the CAS. Two
     * concurrent deinit() calls racing on the same state will have exactly
     * one succeed (CAS guarantee), the other returns -EBUSY.
     */
    if (state == LORA_STOPPED) {
        if (lora_transition_from(LORA_STOPPED, LORA_DEINITING) != 0) {
            LOG_ERR("lora_l2: deinit race, state changed");
            return -EBUSY;
        }
    } else if (state == LORA_ABORTED) {
        if (lora_transition_from(LORA_ABORTED, LORA_DEINITING) != 0) {
            LOG_ERR("lora_l2: deinit race, state changed");
            return -EBUSY;
        }
    } else if (state == LORA_DESTROY_FAILED) {
        if (lora_transition_from(LORA_DESTROY_FAILED, LORA_DEINITING) != 0) {
            LOG_ERR("lora_l2: destroy retry race, state changed");
            return -EBUSY;
        }
        goto destroy_queue;
    } else if (state == LORA_DEINITING) {
        LOG_ERR("lora_l2: deinit already in progress");
        return -EBUSY;
    } else if (state == LORA_RUNNING) {
        LOG_ERR("lora_l2: still running, call stop() first");
        return -EBUSY;
    } else if (state == LORA_UNINIT) {
        return 0;  /* Already uninitialized */
    } else {
        LOG_ERR("lora_l2: unknown state (%d), forcing ABORTED", state);
        atomic_set(&current_state, LORA_ABORTED);
        return -EINVAL;
    }

    /*
     * Serialize cleanup with public accessors (EUI-64 copies, queue stats).
     * On the STOPPED path lora_mutex is in a clean state (stop() released
     * it and no RX work was left running), so it is held for the remainder of
     * teardown instead of being reinitialized mid-teardown.
     */
    if (state == LORA_STOPPED) {
        k_mutex_lock(&lora_mutex, K_FOREVER);
        lora_mutex_held = true;
    }

    /*
     * Wait for any in-flight TX to complete before cleanup. TX holds tx_buf_mutex
     * for the entire lora_send() duration (~500ms at SF10/255 bytes). By acquiring
     * this mutex here, we ensure:
     * 1. No TX is currently using tx_buf
     * 2. No new TX will start (deinit state check in tx() will fail after we
     *    transitioned to DEINITING above)
     *
     * Note: tx_buf_mutex may be legitimately held for a long time (~500ms).
     * We wait forever here because refusing to deinit leaves worse state.
     */
    k_mutex_lock(&tx_buf_mutex, K_FOREVER);
    /* tx_buf is now safe - no active TX. We'll reinitialize the mutex below. */
    k_mutex_unlock(&tx_buf_mutex);

    /*
     * Abort recovery only: drain the RX work item and disarm the driver
     * before touching mutexes or callback state. Normal STOPPED teardown
     * skips this because stop() already drained the RX path, and
     * init-without-start never armed anything.
     *
     * Unlike the RX thread join this replaced, the drain cannot fail: the
     * ISR gate and work flush guarantee no RX callback can start once this
     * returns. The best-effort modem disarm is non-blocking, so a wedged
     * driver cannot hang deinit.
     */
    if (state == LORA_ABORTED) {
        lora_l2_rx_stop();
    }

    /*
     * ABORTED recovery only: we do NOT acquire lora_mutex here. If we got
     * into the aborted state, the mutex may be left locked by an aborted
     * work handler. Attempting to lock it would deadlock. Instead, we
     * reinitialize it. On the STOPPED path the mutex is already held
     * (acquired above), so only tx_buf_mutex is reinitialized.
     *
     * This is best-effort recovery. In the rare case where the work handler
     * is in an undefined state that the drain above didn't resolve,
     * reinitializing the mutex may have undefined behavior. However:
     * - The drain above should catch all cases (the work item cannot be
     *   aborted mid-run; it either completed or was never running)
     * - Refusing to recover leaves the module permanently unusable
     * - The system is already in a degraded state if we reached this path
     */

    /*
     * SECURITY: Reinitializing a mutex that may still be held by a dead
     * thread is UNDEFINED BEHAVIOR per POSIX and Zephyr semantics. If a
     * work handler was aborted while holding lora_mutex, the mutex's internal
     * state (owner, lock count, wait queue) is corrupted. Calling
     * k_mutex_init() on such a mutex may:
     * - Appear to succeed but leave internal state inconsistent
     * - Cause subsequent lock/unlock operations to corrupt kernel data
     * - Trigger assertion failures in debug builds
     *
     * We proceed anyway because:
     * 1. The alternative (refusing to deinit) leaves the module permanently
     *    unusable until full system reset
     * 2. In practice, work handlers are not aborted; they complete and
     *    release the mutex (critical sections are pointer snapshots)
     * 3. The aborted flag forces a full deinit/init cycle, which resets all
     *    module state including this mutex
     *
     * The ONLY truly safe recovery from an abort scenario is a full
     * system reset (k_sys_reboot). Applications requiring guaranteed
     * correctness after an abort should reboot rather than attempt
     * module restart via deinit/init.
     *
     * K_MUTEX_DEFINE created it statically, so we use k_mutex_init to reset.
     *
     * Note: k_mutex_init() returns int but cannot fail in Zephyr kernel mode
     * (it only initializes fields and the wait queue). The return value check
     * is defensive against future Zephyr API changes or userspace builds.
     */
    int mutex_ret = 0;
    int mutex_ret2;

    if (state == LORA_ABORTED) {
        /* Best-effort check: trylock to detect if mutex is held. If trylock
         * succeeds, we own it and can safely reinit after unlock. If it fails,
         * we log a warning but proceed with reinit anyway (documented UB). */
        int trylock_ret = k_mutex_lock(&lora_mutex, K_NO_WAIT);
        if (trylock_ret == 0) {
            /* We acquired it - mutex was free. Unlock before reinit. */
            k_mutex_unlock(&lora_mutex);
        } else {
            /* Trylock failed - mutex is held by another context (likely dead thread).
             * SECURITY: Proceeding with k_mutex_init() is UNDEFINED BEHAVIOR.
             * Log at ERR level since this indicates the system is in a degraded
             * state where full reboot is the only guaranteed recovery. */
            LOG_ERR("lora_l2: lora_mutex held during deinit (trylock=%d), "
                    "reinit is UB - consider k_sys_reboot for guaranteed recovery",
                    trylock_ret);
        }
        mutex_ret = k_mutex_init(&lora_mutex);
        if (mutex_ret != 0) {
            LOG_ERR("lora_l2: k_mutex_init failed (%d)", mutex_ret);
        }
    }

    mutex_ret2 = k_mutex_init(&tx_buf_mutex);
    if (mutex_ret2 != 0) {
        LOG_ERR("lora_l2: k_mutex_init(tx_buf_mutex) failed (%d)", mutex_ret2);
    }

    if (mutex_ret != 0 || mutex_ret2 != 0) {
        LOG_ERR("lora_l2: mutex reinit failure, module is in unstable state");
        if (lora_mutex_held) {
            k_mutex_unlock(&lora_mutex);
        }
        atomic_set(&current_state, LORA_ABORTED);
        return -EIO;
    }

    /*
     * Clear callback state. No mutex needed: the RX work item was drained above
     * and DEINITING state blocks new operations, so no concurrent access.
     */
    lora_data.rx_callback = NULL;
    lora_data.rx_callback_user_data = NULL;
    lora_data.cca_enabled = false;
    lichen_csma_init(&lora_data.csma);
    lora_data.rx_channel = 0;

    /*
     * Reinitialize lichen_l2's rx_mutex (project-LICHEN-dq6n.22).
     *
     * If a work handler was aborted while executing lichen_l2_input(), it may
     * have been holding rx_mutex (which lives in lichen_l2.c, not here).
     * Without reinitializing that mutex, subsequent RX callbacks would deadlock.
     *
     * This call has the same UNDEFINED BEHAVIOR caveats as our lora_mutex
     * reinitialization above. See the SECURITY comment at line ~545 for the
     * full analysis.
     *
     * Only needed when CONFIG_LICHEN_L2 is enabled (lichen_l2.c is compiled).
     * In standalone mode, there's no rx_mutex to reinitialize.
     */
#if defined(CONFIG_LICHEN_L2)
    lichen_l2_reinit_after_abort();
#endif

destroy_queue:
    /*
     * Destroy TX queue only after the RX work item was drained above;
     * tx_queue_destroy() requires exclusive ownership. Holding lora_mutex
     * across destruction serializes with the public accessors (EUI-64,
     * queue stats), which cannot run underneath the teardown. Done before
     * the final state transition and propagated so a live queue cannot be
     * reinitialized.
     */
    if (!lora_mutex_held) {
        k_mutex_lock(&lora_mutex, K_FOREVER);
    }
    int qret = tx_queue_destroy(&tx_queue);
    if (qret < 0) {
        LOG_ERR("lora_l2: tx_queue_destroy failed (%d) - reinit blocked",
                qret);
        atomic_set(&current_state, LORA_DESTROY_FAILED);
        k_mutex_unlock(&lora_mutex);
        return qret;
    }

    /*
     * Final transition to UNINIT - module ready for re-initialization.
     * Use atomic CAS to ensure no state race: while DEINITING can only
     * transition to UNINIT, using lora_transition_from() guarantees the
     * state hasn't been corrupted by a bug elsewhere.
     */
    if (lora_transition_from(LORA_DEINITING, LORA_UNINIT) != 0) {
        /* Should be impossible - we hold DEINITING exclusively */
        LOG_ERR("lora_l2: deinit state corrupted, forcing ABORTED");
        atomic_set(&current_state, LORA_ABORTED);
        k_mutex_unlock(&lora_mutex);
        return -EIO;
    }

    k_mutex_unlock(&lora_mutex);
    LOG_INF("lora_l2: deinitialized");
    return 0;
}

/* --------------------------------------------------------------------------
 * Status queries
 * -------------------------------------------------------------------------- */

bool lichen_lora_l2_is_running(void)
{
    return lora_get_state() == LORA_RUNNING;
}

bool lichen_lora_l2_needs_reinit(void)
{
    return lora_get_state() == LORA_ABORTED;
}

bool lichen_lora_l2_needs_destroy_retry(void)
{
    return lora_get_state() == LORA_DESTROY_FAILED;
}
