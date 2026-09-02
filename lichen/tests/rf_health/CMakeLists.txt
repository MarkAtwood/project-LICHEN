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

# Apply sanitizers and hardening
lichen_test_target(rf_health_test)

# ponytail: shared test_common.cmake targets Apple clang (-std=c23); gcc 13
# (this Linux builder) only accepts c2x — later flag wins for this target.
# Upgrade path: make test_common.cmake probe the compiler.
get_target_property(RF_HEALTH_OPTS rf_health_test COMPILE_OPTIONS)
list(REMOVE_ITEM RF_HEALTH_OPTS -std=c23)
list(APPEND RF_HEALTH_OPTS -std=c2x)
set_target_properties(rf_health_test PROPERTIES COMPILE_OPTIONS "${RF_HEALTH_OPTS}")

include(CTest)
add_test(NAME rf_health
	 COMMAND rf_health_test
		 ${CMAKE_CURRENT_LIST_DIR}/../../../test/vectors/ccp-interference.json)
