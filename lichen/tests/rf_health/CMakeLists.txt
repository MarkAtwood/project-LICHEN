# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(rf_health_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(rf_health_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/rf_health.c
)
target_include_directories(rf_health_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

# Apply sanitizers and hardening (test_common.cmake probes the compiler and
# picks -std=c23 or -std=c2x as supported — no per-target std surgery here).
lichen_test_target(rf_health_test)

include(CTest)
add_test(NAME rf_health
	 COMMAND rf_health_test
		 ${CMAKE_CURRENT_LIST_DIR}/../../../test/vectors/ccp-interference.json
		 ${CMAKE_CURRENT_LIST_DIR}/../../../test/vectors/ccp_ema_update_integer.json)
