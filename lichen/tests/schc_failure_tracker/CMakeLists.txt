# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(schc_failure_tracker_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(schc_failure_tracker_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/schc_failure_tracker.c
)
target_include_directories(schc_failure_tracker_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/include
)

# Apply sanitizers and hardening
lichen_test_target(schc_failure_tracker_test)

include(CTest)
add_test(NAME schc_failure_tracker COMMAND schc_failure_tracker_test)
