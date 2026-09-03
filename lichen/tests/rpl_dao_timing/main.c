/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <lichen/rpl_dao_timing.h>

static unsigned int tests_run;

#ifdef CONFIG_ZTEST
#include <zephyr/ztest.h>
#define CHECK(condition, ...) zassert_true(condition, __VA_ARGS__)
#else
#define CHECK(condition, ...)                                                  \
  do {                                                                         \
    if (!(condition)) {                                                        \
      fprintf(stderr, __VA_ARGS__);                                            \
      fprintf(stderr, "\n");                                                   \
      return false;                                                            \
    }                                                                          \
  } while (0)
#endif

#define ACCEPTANCE_LIMIT UINT32_C(4294966410)

struct scripted_rng {
  const uint32_t *words;
  size_t count;
  size_t next;
  int result;
};

static int scripted_random(void *user, uint32_t *value) {
  struct scripted_rng *rng = user;

  if (rng->result != 0) {
    return rng->result;
  }
  if (rng->next >= rng->count) {
    return -ENODATA;
  }
  *value = rng->words[rng->next++];
  return 0;
}

static bool test_exact_mapping_and_rejection_boundary(void) {
  uint16_t delay = UINT16_MAX;

  for (uint32_t expected = LICHEN_RPL_DAO_INITIAL_DELAY_MIN_MS;
       expected <= LICHEN_RPL_DAO_INITIAL_DELAY_MAX_MS; ++expected) {
    CHECK(lichen_rpl_dao_initial_delay_from_random(expected, &delay) == 0,
          "accepted word %u rejected", expected);
    CHECK(delay == expected, "word %u mapped to %u", expected, delay);
  }
  CHECK(lichen_rpl_dao_initial_delay_from_random(2001U, &delay) == 0 &&
            delay == 0U,
        "range did not repeat at 2001");
  CHECK(lichen_rpl_dao_initial_delay_from_random(ACCEPTANCE_LIMIT - 1U,
                                                 &delay) == 0 &&
            delay == LICHEN_RPL_DAO_INITIAL_DELAY_MAX_MS,
        "last accepted word did not map to upper bound");

  delay = UINT16_C(0x5a5a);
  for (uint64_t rejected = ACCEPTANCE_LIMIT; rejected <= UINT32_MAX;
       ++rejected) {
    CHECK(lichen_rpl_dao_initial_delay_from_random((uint32_t)rejected,
                                                   &delay) == -EAGAIN,
          "tail word %llu accepted", (unsigned long long)rejected);
    CHECK(delay == UINT16_C(0x5a5a), "rejection changed output");
  }
  CHECK(lichen_rpl_dao_initial_delay_from_random(0U, NULL) == -EINVAL,
        "NULL output accepted");
  return true;
}

static bool test_injected_rng_and_fail_closed_bounds(void) {
  const uint32_t words[] = {UINT32_MAX, 2000U};
  struct scripted_rng rng = {.words = words, .count = 2U};
  struct lichen_rpl_dao_initial_timer timer;
  uint16_t delay = UINT16_MAX;

  lichen_rpl_dao_initial_timer_init(&timer);
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 100U, scripted_random, &rng,
                                           &delay) == 0,
        "rejection retry failed");
  CHECK(rng.next == 2U && delay == 2000U && timer.armed &&
            timer.deadline_ms == 2100U,
        "deterministic injected result mismatch");

  const uint32_t rejected[LICHEN_RPL_DAO_INITIAL_RNG_MAX_DRAWS] = {
      UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX,
      UINT32_MAX, UINT32_MAX, UINT32_MAX, UINT32_MAX,
  };
  rng = (struct scripted_rng){.words = rejected,
                              .count = LICHEN_RPL_DAO_INITIAL_RNG_MAX_DRAWS};
  timer = (struct lichen_rpl_dao_initial_timer){.deadline_ms = 1234U,
                                                .armed = false};
  delay = UINT16_C(0xbeef);
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 55U, scripted_random, &rng,
                                           &delay) == -EAGAIN,
        "bounded rejection exhaustion not reported");
  CHECK(rng.next == LICHEN_RPL_DAO_INITIAL_RNG_MAX_DRAWS && !timer.armed &&
            timer.deadline_ms == 1234U && delay == UINT16_C(0xbeef),
        "rejection exhaustion mutated state");

  rng = (struct scripted_rng){.result = -EIO};
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 0U, scripted_random, &rng,
                                           &delay) == -EIO,
        "negative RNG error not propagated");
  rng.result = 1;
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 0U, scripted_random, &rng,
                                           &delay) == -EIO,
        "positive RNG error not normalized");
  CHECK(lichen_rpl_dao_initial_timer_start(NULL, 0U, scripted_random, &rng,
                                           &delay) == -EINVAL &&
            lichen_rpl_dao_initial_timer_start(&timer, 0U, NULL, NULL,
                                               &delay) == -EINVAL &&
            lichen_rpl_dao_initial_timer_start(&timer, 0U, scripted_random,
                                               &rng, NULL) == -EINVAL,
        "NULL input accepted");
  return true;
}

static bool test_one_shot_deadlines_and_wrap(void) {
  const uint32_t zero[] = {0U};
  struct scripted_rng rng = {.words = zero, .count = 1U};
  struct lichen_rpl_dao_initial_timer timer;
  uint16_t delay;

  lichen_rpl_dao_initial_timer_init(NULL);
  lichen_rpl_dao_initial_timer_init(&timer);
  CHECK(!lichen_rpl_dao_initial_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_initial_timer_take_if_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_initial_timer_is_due(NULL, 0U) &&
            !lichen_rpl_dao_initial_timer_take_if_due(NULL, 0U),
        "inactive/NULL timer became due");
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 77U, scripted_random, &rng,
                                           &delay) == 0 &&
            delay == 0U,
        "zero-delay start failed");
  CHECK(lichen_rpl_dao_initial_timer_is_due(&timer, 77U),
        "zero delay not due immediately");
  CHECK(lichen_rpl_dao_initial_timer_take_if_due(&timer, 77U),
        "due timer was not consumed");
  CHECK(!lichen_rpl_dao_initial_timer_take_if_due(&timer, 77U),
        "timer was not one-shot");

  const uint32_t upper[] = {2000U};
  rng = (struct scripted_rng){.words = upper, .count = 1U};
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, UINT32_MAX - 999U,
                                           scripted_random, &rng, &delay) == 0,
        "wrap-crossing start failed");
  CHECK(timer.deadline_ms == 1000U &&
            !lichen_rpl_dao_initial_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_initial_timer_is_due(&timer, 999U) &&
            lichen_rpl_dao_initial_timer_is_due(&timer, 1000U),
        "wrap-safe deadline boundary mismatch");
  CHECK(lichen_rpl_dao_initial_timer_start(&timer, 0U, scripted_random, &rng,
                                           &delay) == -EALREADY,
        "duplicate arm postponed timer");
  CHECK(lichen_rpl_dao_initial_timer_take_if_due(&timer, 1000U),
        "due wrapped timer not consumed");
  return true;
}

static bool test_retry_profile_and_exhaustion(void) {
  const uint32_t expected[] = {
      LICHEN_RPL_DAO_RETRY_FIRST_MS,
      LICHEN_RPL_DAO_RETRY_SECOND_MS,
      LICHEN_RPL_DAO_RETRY_THIRD_MS,
  };
  struct lichen_rpl_dao_retry_timer timer;
  uint32_t delay = UINT32_C(0x5a5a5a5a);

  CHECK(LICHEN_RPL_DAO_RETRY_LIMIT == 3U, "retry limit drifted");
  for (uint8_t attempt = 0U; attempt < LICHEN_RPL_DAO_RETRY_LIMIT; ++attempt) {
    CHECK(lichen_rpl_dao_retry_delay_ms(attempt, &delay) == 0,
          "retry attempt %u rejected", attempt);
    CHECK(delay == expected[attempt], "retry attempt %u delay mismatch",
          attempt);
  }
  delay = UINT32_C(0x5a5a5a5a);
  CHECK(lichen_rpl_dao_retry_delay_ms(LICHEN_RPL_DAO_RETRY_LIMIT, &delay) ==
                -ENOENT &&
            delay == UINT32_C(0x5a5a5a5a),
        "first exhausted attempt did not fail atomically");
  CHECK(lichen_rpl_dao_retry_delay_ms(UINT8_MAX, &delay) == -ENOENT &&
            delay == UINT32_C(0x5a5a5a5a),
        "large exhausted attempt did not saturate");
  CHECK(lichen_rpl_dao_retry_delay_ms(0U, NULL) == -EINVAL,
        "NULL retry output accepted");

  lichen_rpl_dao_retry_timer_init(NULL);
  lichen_rpl_dao_retry_timer_init(&timer);
  CHECK(!timer.armed && timer.attempts == 0U &&
            !lichen_rpl_dao_retry_timer_is_exhausted(&timer) &&
            !lichen_rpl_dao_retry_timer_is_exhausted(NULL),
        "fresh retry timer state mismatch");

  for (uint8_t attempt = 0U; attempt < LICHEN_RPL_DAO_RETRY_LIMIT; ++attempt) {
    const uint32_t now_ms = 100U + attempt;
    CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, now_ms, &delay) == 0,
          "retry attempt %u was not scheduled", attempt);
    CHECK(delay == expected[attempt] && timer.attempts == attempt + 1U &&
              timer.deadline_ms == now_ms + expected[attempt] && timer.armed,
          "retry attempt %u state mismatch", attempt);
    CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, UINT32_MAX,
                                                   &delay) == -EALREADY,
          "pending retry was silently postponed");
    CHECK(!lichen_rpl_dao_retry_timer_is_due(&timer, timer.deadline_ms - 1U) &&
              lichen_rpl_dao_retry_timer_is_due(&timer, timer.deadline_ms),
          "retry attempt %u deadline boundary mismatch", attempt);
    CHECK(lichen_rpl_dao_retry_timer_take_if_due(&timer, timer.deadline_ms),
          "retry attempt %u was not consumed", attempt);
    CHECK(!lichen_rpl_dao_retry_timer_take_if_due(&timer, timer.deadline_ms),
          "retry attempt %u was consumed twice", attempt);
  }

  CHECK(lichen_rpl_dao_retry_timer_is_exhausted(&timer),
        "three scheduled retries did not exhaust budget");
  delay = UINT32_C(0xa5a5a5a5);
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, 0U, &delay) ==
                -ENOENT &&
            timer.attempts == LICHEN_RPL_DAO_RETRY_LIMIT && !timer.armed &&
            delay == UINT32_C(0xa5a5a5a5),
        "exhaustion did not remain saturated and atomic");
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, 0U, &delay) ==
                -ENOENT &&
            timer.attempts == LICHEN_RPL_DAO_RETRY_LIMIT,
        "repeated exhaustion wrapped retry count");
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(NULL, 0U, &delay) == -EINVAL,
        "NULL timer rejected");
  /* NULL delay_ms is tolerated (returns 0, arms without reporting). */
  return true;
}

static bool test_retry_wrap_and_reset_rearm(void) {
  struct lichen_rpl_dao_retry_timer timer;
  uint32_t delay;

  lichen_rpl_dao_retry_timer_init(&timer);
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(
            &timer, UINT32_MAX - (LICHEN_RPL_DAO_RETRY_FIRST_MS - 2U),
            &delay) == 0,
        "wrap-crossing retry was not scheduled");
  CHECK(delay == LICHEN_RPL_DAO_RETRY_FIRST_MS && timer.deadline_ms == 1U,
        "wrap-crossing retry deadline mismatch");
  CHECK(!lichen_rpl_dao_retry_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_retry_timer_is_due(&timer, 0U) &&
            lichen_rpl_dao_retry_timer_is_due(&timer, 1U),
        "retry wrap boundary mismatch");

  lichen_rpl_dao_retry_timer_reset(&timer);
  CHECK(!timer.armed && timer.attempts == 0U && timer.deadline_ms == 0U,
        "reset did not clear pending retry and budget");
  CHECK(lichen_rpl_dao_retry_timer_schedule_next(&timer, 10U, &delay) == 0 &&
            delay == LICHEN_RPL_DAO_RETRY_FIRST_MS && timer.attempts == 1U,
        "reset did not rearm from the four-second slot");
  lichen_rpl_dao_retry_timer_reset(NULL);
  return true;
}

static bool test_refresh_profile_and_periodic_rearm(void) {
  struct lichen_rpl_dao_refresh_timer timer;

  CHECK(LICHEN_RPL_DAO_SOFT_STATE_LIFETIME_S == 30U * 60U,
        "soft-state lifetime drifted");
  CHECK(LICHEN_RPL_DAO_REFRESH_INTERVAL_S == 15U * 60U &&
            LICHEN_RPL_DAO_REFRESH_INTERVAL_MS == 900000U &&
            LICHEN_RPL_DAO_REFRESH_INTERVAL_S ==
                LICHEN_RPL_DAO_SOFT_STATE_LIFETIME_S / 2U,
        "refresh is not the exact route half-life");

  lichen_rpl_dao_refresh_timer_init(NULL);
  lichen_rpl_dao_refresh_timer_init(&timer);
  CHECK(!timer.armed && timer.deadline_ms == 0U &&
            !lichen_rpl_dao_refresh_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_refresh_timer_is_due(NULL, 0U) &&
            !lichen_rpl_dao_refresh_timer_take_if_due(NULL, 0U),
        "inactive/NULL refresh timer became due");

  CHECK(lichen_rpl_dao_refresh_timer_start(&timer, 12345U) == 0 &&
            timer.armed && timer.deadline_ms == 912345U,
        "exact refresh deadline mismatch");
  CHECK(!lichen_rpl_dao_refresh_timer_is_due(&timer, 912344U) &&
            lichen_rpl_dao_refresh_timer_is_due(&timer, 912345U) &&
            lichen_rpl_dao_refresh_timer_is_due(&timer, 912346U),
        "refresh due boundary mismatch");

  const uint32_t first_deadline = timer.deadline_ms;
  CHECK(lichen_rpl_dao_refresh_timer_start(&timer, 999U) == -EALREADY &&
            timer.armed && timer.deadline_ms == first_deadline,
        "duplicate refresh start postponed deadline");

  /* A successful early route update deliberately begins a fresh period. */
  CHECK(lichen_rpl_dao_refresh_timer_reschedule(&timer, 20000U) == 0 &&
            timer.armed && timer.deadline_ms == 920000U,
        "periodic refresh did not rearm from successful transmission");
  CHECK(!lichen_rpl_dao_refresh_timer_take_if_due(&timer, 919999U),
        "refresh consumed before rearmed deadline");
  CHECK(lichen_rpl_dao_refresh_timer_take_if_due(&timer, 920000U),
        "due refresh was not consumed");
  CHECK(!lichen_rpl_dao_refresh_timer_take_if_due(&timer, 920000U),
        "refresh timer was not one-shot");

  CHECK(lichen_rpl_dao_refresh_timer_reschedule(&timer, 30000U) == 0 &&
            timer.deadline_ms == 930000U,
        "inactive periodic timer did not rearm");
  lichen_rpl_dao_refresh_timer_reset(&timer);
  CHECK(!timer.armed && timer.deadline_ms == 0U,
        "route invalidation did not cancel refresh");
  CHECK(lichen_rpl_dao_refresh_timer_start(NULL, 0U) == -EINVAL &&
            lichen_rpl_dao_refresh_timer_reschedule(NULL, 0U) == -EINVAL,
        "NULL refresh timer accepted");
  lichen_rpl_dao_refresh_timer_reset(NULL);
  return true;
}

static bool test_refresh_wrap_boundary(void) {
  struct lichen_rpl_dao_refresh_timer timer;

  lichen_rpl_dao_refresh_timer_init(&timer);
  CHECK(lichen_rpl_dao_refresh_timer_start(
            &timer, UINT32_MAX - (LICHEN_RPL_DAO_REFRESH_INTERVAL_MS - 2U)) ==
            0,
        "wrap-crossing refresh was not scheduled");
  CHECK(timer.deadline_ms == 1U, "wrap-crossing refresh deadline mismatch");
  CHECK(!lichen_rpl_dao_refresh_timer_is_due(&timer, UINT32_MAX) &&
            !lichen_rpl_dao_refresh_timer_is_due(&timer, 0U) &&
            lichen_rpl_dao_refresh_timer_is_due(&timer, 1U),
        "refresh wrap boundary mismatch");
  return true;
}

/* Composite transmission loop (spec 09 14.2; bead b7z9.16(c)): initial
 * jittered window -> bounded 4/8/16 s retries -> 900 s refresh cadence,
 * driven entirely by injected time and a scripted RNG. */
static bool test_tx_loop_initial_retry_refresh(void) {
  struct scripted_rng rng = {.words = (const uint32_t[]){0U},
                             .count = 1U,
                             .next = 0U,
                             .result = 0};
  struct lichen_rpl_dao_tx_loop loop;
  uint16_t delay = 0;

  /* RNG word 0 -> delay 0 ms (0 + 0 % 2001). */
  CHECK(lichen_rpl_dao_tx_loop_init(&loop, 1000U, scripted_random, &rng,
                                    &delay) == 0,
        "loop init");
  CHECK(delay == 0U, "initial delay from scripted rng");
  CHECK(lichen_rpl_dao_tx_loop_phase(&loop) ==
            LICHEN_RPL_DAO_TX_LOOP_INITIAL,
        "phase INITIAL after init");

  /* Not due before the window elapses. */
  CHECK(!lichen_rpl_dao_tx_loop_poll(&loop, 999U), "not due at 999");
  CHECK(lichen_rpl_dao_tx_loop_poll(&loop, 1000U), "due at 1000");
  /* Gate consumed exactly once. */
  CHECK(!lichen_rpl_dao_tx_loop_poll(&loop, 1001U), "gate consumed once");

  /* Failure -> retry sequence 4/8/16 s. */
  lichen_rpl_dao_tx_loop_on_send_result(&loop, 1000U, false);
  CHECK(lichen_rpl_dao_tx_loop_phase(&loop) ==
            LICHEN_RPL_DAO_TX_LOOP_RETRYING,
        "phase RETRYING after failure");
  CHECK(!lichen_rpl_dao_tx_loop_poll(&loop, 1000U + 3999U),
        "retry 0 not due early");
  CHECK(lichen_rpl_dao_tx_loop_poll(&loop, 1000U + 4000U),
        "retry 0 due at +4 s");
  lichen_rpl_dao_tx_loop_on_send_result(&loop, 5000U, false);
  CHECK(lichen_rpl_dao_tx_loop_poll(&loop, 5000U + 8000U),
        "retry 1 due at +8 s");
  lichen_rpl_dao_tx_loop_on_send_result(&loop, 13000U, false);
  CHECK(lichen_rpl_dao_tx_loop_poll(&loop, 13000U + 16000U),
        "retry 2 due at +16 s");

  /* Success -> refresh cadence starts at the success time. */
  lichen_rpl_dao_tx_loop_on_send_result(&loop, 29000U, true);
  CHECK(lichen_rpl_dao_tx_loop_phase(&loop) ==
            LICHEN_RPL_DAO_TX_LOOP_REFRESH,
        "phase REFRESH after success");
  CHECK(!lichen_rpl_dao_tx_loop_poll(&loop, 29000U + 899999U),
        "refresh not due before 900 s");
  CHECK(lichen_rpl_dao_tx_loop_poll(&loop, 29000U + 900000U),
        "refresh due at +900 s");

  /* Refresh failure -> retries restart; success mid-retry starts a new
   * refresh period. */
  lichen_rpl_dao_tx_loop_on_send_result(&loop, 29000U + 900000U, false);
  CHECK(lichen_rpl_dao_tx_loop_phase(&loop) ==
            LICHEN_RPL_DAO_TX_LOOP_RETRYING,
        "refresh failure -> RETRYING");
  lichen_rpl_dao_tx_loop_on_send_result(&loop, 29000U + 904000U, true);
  CHECK(lichen_rpl_dao_tx_loop_phase(&loop) ==
            LICHEN_RPL_DAO_TX_LOOP_REFRESH,
        "mid-retry success -> new refresh period");
  CHECK(!lichen_rpl_dao_tx_loop_poll(&loop, 29000U + 904000U + 899999U),
        "new refresh not due early");

  /* Early successful refresh reschedules from the success time. */
  CHECK(lichen_rpl_dao_tx_loop_poll(&loop, 29000U + 904000U + 900000U),
        "second refresh due");
  lichen_rpl_dao_tx_loop_on_send_result(&loop, 29000U + 904000U + 900100U,
                                        true);
  CHECK(!lichen_rpl_dao_tx_loop_poll(&loop, 29000U + 904000U + 1800099U),
        "rescheduled refresh not due one tick early");
  CHECK(lichen_rpl_dao_tx_loop_poll(&loop, 29000U + 904000U + 900100U + 900000U),
        "rescheduled refresh due 900 s after success");

  /* Exhaustion: three failures in RETRYING -> IDLE, poll stays false. */
  struct lichen_rpl_dao_tx_loop exhausted;
  struct scripted_rng rng2 = {.words = (const uint32_t[]){0U},
                              .count = 1U,
                              .next = 0U,
                              .result = 0};
  CHECK(lichen_rpl_dao_tx_loop_init(&exhausted, 0U, scripted_random, &rng2,
                                    &delay) == 0,
        "exhaustion loop init");
  CHECK(lichen_rpl_dao_tx_loop_poll(&exhausted, 0U), "initial due");
  lichen_rpl_dao_tx_loop_on_send_result(&exhausted, 0U, false);
  (void)lichen_rpl_dao_tx_loop_poll(&exhausted, 4000U);
  lichen_rpl_dao_tx_loop_on_send_result(&exhausted, 4000U, false);
  (void)lichen_rpl_dao_tx_loop_poll(&exhausted, 12000U);
  lichen_rpl_dao_tx_loop_on_send_result(&exhausted, 12000U, false);
  (void)lichen_rpl_dao_tx_loop_poll(&exhausted, 28000U);
  lichen_rpl_dao_tx_loop_on_send_result(&exhausted, 28000U, false);
  CHECK(lichen_rpl_dao_tx_loop_phase(&exhausted) ==
            LICHEN_RPL_DAO_TX_LOOP_IDLE,
        "exhausted retries -> IDLE");
  CHECK(!lichen_rpl_dao_tx_loop_poll(&exhausted, UINT32_MAX),
        "IDLE loop never polls due");

  /* NULL guards. */
  CHECK(!lichen_rpl_dao_tx_loop_poll(NULL, 0U), "NULL poll rejected");
  lichen_rpl_dao_tx_loop_on_send_result(NULL, 0U, true);
  CHECK(lichen_rpl_dao_tx_loop_phase(NULL) ==
            LICHEN_RPL_DAO_TX_LOOP_IDLE,
        "NULL phase query -> IDLE");

  tests_run++;
  return true;
/* ── Composed orchestrator (spec 09 14.2) ────────────────────────────────── */
static uint32_t orch_rng_next;

static int test_rng(void *user, uint32_t *value) {
  (void)user;
  *value = orch_rng_next;
  return 0;
}



static int test_tx_on_join_schedules_initial_window(void) {
  struct lichen_rpl_dao_tx_timing t;
  lichen_rpl_dao_tx_timing_init(&t);
  orch_rng_next = 1000U;
  CHECK(lichen_rpl_dao_tx_timing_on_join(&t, 1000, test_rng, NULL) == 0,
            "on_join ok");
  CHECK(t.phase == LICHEN_RPL_DAO_TX_INITIAL_PENDING, "initial pending");
  CHECK(!lichen_rpl_dao_tx_timing_is_due(&t, 1999), "not due early");
  CHECK(lichen_rpl_dao_tx_timing_is_due(&t, 2000), "due at delay");
  return 1;
}

static int test_tx_on_send_advances_through_backoff_then_exhausted(void) {
  struct lichen_rpl_dao_tx_timing t;
  lichen_rpl_dao_tx_timing_init(&t);
  orch_rng_next = 0U;
  CHECK(lichen_rpl_dao_tx_timing_on_join(&t, 0, test_rng, NULL) == 0, "join");
  CHECK(lichen_rpl_dao_initial_timer_take_if_due(&t.initial, 2000),
            "initial consumed");
  uint32_t now = 2000;
  lichen_rpl_dao_tx_timing_on_send(&t, now);
  CHECK(t.phase == LICHEN_RPL_DAO_TX_RETRY_PENDING, "retry pending");
  /* retry 0 was armed 4 s out at on_send(2000): due at 6000. */
  now = 6000;
  CHECK(lichen_rpl_dao_retry_timer_is_due(&t.retry, now), "retry1 due");
  lichen_rpl_dao_tx_timing_on_send(&t, now);
  /* retry1 consumed; next slot 8 s from now = 14000. */
  now = 14000;
  CHECK(lichen_rpl_dao_retry_timer_is_due(&t.retry, now), "retry2 due");
  lichen_rpl_dao_tx_timing_on_send(&t, now);
  /* retry2 consumed; next = 16 s from 14000 = 30000. */
  now = 30000;
  CHECK(lichen_rpl_dao_retry_timer_is_due(&t.retry, now), "retry3 due");
  lichen_rpl_dao_tx_timing_on_send(&t, now);
  CHECK(t.phase == LICHEN_RPL_DAO_TX_EXHAUSTED, "exhausted after 3");
  return 1;
}

static int test_tx_on_ack_starts_refresh_and_resets_retries(void) {
  struct lichen_rpl_dao_tx_timing t;
  lichen_rpl_dao_tx_timing_init(&t);
  orch_rng_next = 0U;
  CHECK(lichen_rpl_dao_tx_timing_on_join(&t, 0, test_rng, NULL) == 0, "join");
  CHECK(lichen_rpl_dao_initial_timer_take_if_due(&t.initial, 2000),
            "initial consumed");
  lichen_rpl_dao_tx_timing_on_send(&t, 2000);
  CHECK(lichen_rpl_dao_tx_timing_on_ack(&t, 3000) == 0, "ack ok");
  CHECK(t.phase == LICHEN_RPL_DAO_TX_REFRESH_PENDING, "refresh pending");
  CHECK(!lichen_rpl_dao_refresh_timer_is_due(&t.refresh, 902999),
            "not due early");
  CHECK(lichen_rpl_dao_refresh_timer_is_due(&t.refresh, 903000),
            "refresh due at 900s");
  return 1;
}

static int test_tx_on_leave_resets(void) {
  struct lichen_rpl_dao_tx_timing t;
  lichen_rpl_dao_tx_timing_init(&t);
  orch_rng_next = 0U;
  CHECK(lichen_rpl_dao_tx_timing_on_join(&t, 0, test_rng, NULL) == 0, "join");
  lichen_rpl_dao_tx_timing_on_leave(&t);
  CHECK(t.phase == LICHEN_RPL_DAO_TX_IDLE, "idle after leave");
  CHECK(!lichen_rpl_dao_tx_timing_is_due(&t, 999999), "nothing due");
  return 1;
}
/* ── Composed orchestrator (spec 09 14.2) ────────────────────────────────── */





static int test_tx_duplicate_join_rejected_from_any_phase(void) {
  struct lichen_rpl_dao_tx_timing t;
  lichen_rpl_dao_tx_timing_init(&t);
  orch_rng_next = 0U;

  CHECK(lichen_rpl_dao_tx_timing_on_join(&t, 0, test_rng, NULL) == 0,
        "first join ok");

  uint32_t now = 2000;
  (void)lichen_rpl_dao_initial_timer_take_if_due(&t.initial, now);
  lichen_rpl_dao_tx_timing_on_send(&t, now);
  CHECK(t.phase == LICHEN_RPL_DAO_TX_RETRY_PENDING, "retry pending");
  CHECK(lichen_rpl_dao_tx_timing_on_join(&t, now, test_rng, NULL) == -EALREADY,
        "dup join in RETRY_PENDING");
  CHECK(t.phase == LICHEN_RPL_DAO_TX_RETRY_PENDING, "phase unchanged (retry)");

  now = 6000;
  lichen_rpl_dao_tx_timing_on_send(&t, now);
  now = 14000;
  lichen_rpl_dao_tx_timing_on_send(&t, now);
  now = 30000;
  lichen_rpl_dao_tx_timing_on_send(&t, now);
  now = 60000;
  lichen_rpl_dao_tx_timing_on_send(&t, now);
  CHECK(t.phase == LICHEN_RPL_DAO_TX_EXHAUSTED, "exhausted");
  CHECK(lichen_rpl_dao_tx_timing_on_join(&t, now, test_rng, NULL) == -EALREADY,
        "dup join in EXHAUSTED");
  CHECK(t.phase == LICHEN_RPL_DAO_TX_EXHAUSTED, "phase unchanged (exhausted)");
  return 1;
}

static bool run_all_tests(void) {
  if (!test_tx_loop_initial_retry_refresh()) {
    return false;
  }
  return test_exact_mapping_and_rejection_boundary() &&
         test_injected_rng_and_fail_closed_bounds() &&
         test_one_shot_deadlines_and_wrap() &&
         test_retry_profile_and_exhaustion() &&
         test_retry_wrap_and_reset_rearm() &&
         test_refresh_profile_and_periodic_rearm() &&
         test_refresh_wrap_boundary() &&
         test_tx_on_join_schedules_initial_window() &&
         test_tx_on_send_advances_through_backoff_then_exhausted() &&
         test_tx_on_ack_starts_refresh_and_resets_retries() &&
         test_tx_on_leave_resets() &&
         test_tx_duplicate_join_rejected_from_any_phase();
}

#ifdef CONFIG_ZTEST
ZTEST(rpl_dao_timing, test_profile) {
  zassert_true(run_all_tests(), "DAO timing profile failed");
}

ZTEST_SUITE(rpl_dao_timing, NULL, NULL, NULL, NULL, NULL);
#else
int main(void) {
  if (!run_all_tests()) {
    return 1;
  }
  puts("rpl_dao_timing: all tests passed");
  return 0;
}
#endif

#undef ACCEPTANCE_LIMIT