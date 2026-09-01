/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lora_l2_internal.h
 * @brief Internal shared state for LICHEN LoRa L2 module
 *
 * This header is shared across the split lora_l2_*.c files. It contains
 * state machine definitions, shared mutexes, buffers, and internal functions
 * that are not part of the public API.
 *
 * NOT part of the public API - do not include from outside l2/.
 */

#ifndef LORA_L2_INTERNAL_H_
#define LORA_L2_INTERNAL_H_

#include "lora_l2.h"

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/sys/atomic.h>
#include <zephyr/logging/log.h>

#include <lichen/hal.h>
#include <lichen/csma.h>
#include <lichen/tx_queue.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------------
 * Configuration constants
 * -------------------------------------------------------------------------- */

/* Modem arbitration timeout budget - use Kconfig value */
#define RX_TIMEOUT_MS        CONFIG_LICHEN_LORA_L2_RX_TIMEOUT_MS

/* --------------------------------------------------------------------------
 * State machine
 * -------------------------------------------------------------------------- */

enum lora_state {
    LORA_UNINIT = 0,   /* Not initialized */
    LORA_STOPPED,      /* Initialized, not running */
    LORA_RUNNING,      /* Initialized and running */
    LORA_ABORTED,      /* Thread was forcibly aborted, needs full reinit */
    LORA_DESTROY_FAILED, /* Worker cleanup done; retry queue destruction */
    LORA_DEINITING,    /* Deinit in progress */
    LORA_STATE_COUNT
};

/* State name strings for logging */
extern const char *state_names[];

/* Valid state transitions: valid_transitions[from][to] = 1 if allowed */
extern const uint8_t valid_transitions[LORA_STATE_COUNT][LORA_STATE_COUNT];

/* Current state - atomic for lock-free reads */
extern atomic_t current_state;

/**
 * @brief Transition to a new state with validation
 *
 * Returns error and forces ABORTED state if the transition is invalid.
 * This catches state machine bugs at runtime.
 *
 * @param new_state Target state
 * @return 0 on success, -EINVAL if transition invalid (state forced to ABORTED)
 */
int lora_transition(enum lora_state new_state);

/**
 * @brief Atomically transition from expected state to new state
 *
 * @param expected Expected current state
 * @param new_state Target state
 * @return 0 on success, -EAGAIN if current state != expected, -EINVAL if transition invalid
 */
int lora_transition_from(enum lora_state expected, enum lora_state new_state);

/**
 * @brief Get current state (lock-free)
 */
static inline enum lora_state lora_get_state(void)
{
    return atomic_get(&current_state);
}

/* --------------------------------------------------------------------------
 * Shared resources
 * -------------------------------------------------------------------------- */

/* Mutex protecting state transitions and callback registration */
extern struct k_mutex lora_mutex;

/* Mutex protecting TX buffer access - serializes concurrent transmissions */
extern struct k_mutex tx_buf_mutex;

/* Mutex for modem access - hard mutual exclusion for driver calls */
extern struct k_mutex modem_mutex;

/* TX/RX modem arbitration flag */
extern atomic_t tx_pending;

/* Internal TX buffer */
extern uint8_t tx_buf[LICHEN_LORA_MAX_PHY_PAYLOAD];

/* TX queue for bufferbloat avoidance */
extern struct tx_queue tx_queue;

/*
 * Module data (not state - state is managed by current_state atomic).
 */
struct lora_l2_data {
    const struct device *lora_dev;
    uint8_t eui64[8];
    lichen_lora_rx_cb_t rx_callback;
    void *rx_callback_user_data;
    bool cca_enabled;
    struct lichen_csma csma;
    uint8_t rx_channel;
#if IS_ENABLED(CONFIG_LICHEN_DUTY_CYCLE)
    struct lichen_duty_cycle_ctx duty;
    uint8_t density;
#endif
};

extern struct lora_l2_data lora_data;

/**
 * @brief Duty region for the configured operating class (CCP-4 duty_region)
 *
 * @return 0 for strictly duty-cycle-limited regions (EU, AU/NZ),
 *         1 for lenient regions (US/CA)
 */
uint8_t lora_l2_duty_region(void);

/* --------------------------------------------------------------------------
 * Internal functions
 * -------------------------------------------------------------------------- */

/**
 * @brief Arm the first asynchronous reception (called from start())
 *
 * Requires the module to be in LORA_RUNNING. Arms the driver via
 * lora_recv_async(); the ISR callback stages packets and the system
 * workqueue processes and re-arms.
 *
 * @return 0 on success, negative errno from the driver on failure
 */
int lora_l2_rx_start(void);

/**
 * @brief Disarm the driver and drain the RX work item
 *
 * Called from stop() after the transition to STOPPED, and from the ABORTED
 * recovery path in deinit(). After this returns, no RX callback invocation
 * can start and no RX work item is queued or running.
 */
void lora_l2_rx_stop(void);

/**
 * @brief Generate stable EUI-64 from hardware device ID
 *
 * @param eui64 Output buffer for 8-byte EUI-64
 * @return 0 on success, negative errno on failure
 */
int generate_eui64(uint8_t *eui64);

/**
 * @brief Store a gateway-assigned SF override (spec 3.4 R-02-008).
 *
 * Called from the RPL layer when an ASSIGNED_SF DIO option is parsed.
 * @param sf Assigned SF (7..12 valid); 0 clears the override.
 */
void lora_l2_assign_sf(uint8_t sf);

/**
 * @brief Current assigned-SF override (0 = none).
 */
uint8_t lora_l2_assigned_sf(void);

#ifdef __cplusplus
}
#endif

#endif /* LORA_L2_INTERNAL_H_ */
