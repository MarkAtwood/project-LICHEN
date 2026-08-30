# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# slot_claim_settings.c host test (same pattern as tests/link_epoch_host):
# real subsystem source + faked settings backend. Round-trip load/store,
# monotonic high-water, reboot (RAM-cache-rebuild) persistence, cache
# overflow, corrupt-entry skip, and persist-first failure propagation.

cmake_minimum_required(VERSION 3.20)
project(slot_claim_settings_host_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(slot_claim_settings_host_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/slot_claim_settings.c
)
target_include_directories(slot_claim_settings_host_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/stub
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/include
)
target_compile_definitions(slot_claim_settings_host_test PRIVATE
  __ZEPHYR__=1
  CONFIG_LICHEN_SLOT_CLAIM_REPLAY_TEST_HOOKS=1
  CONFIG_LICHEN_COAP_SLOT_COORD=1
  CONFIG_LICHEN_COAP_SLOT_COORD_LOG_LEVEL=0
)

lichen_test_target(slot_claim_settings_host_test)

include(CTest)
add_test(NAME slot_claim_settings_host COMMAND slot_claim_settings_host_test)
