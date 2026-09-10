# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(schc_failure_tracker C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

# The consecutive-failure tracker test lives in src/main.c and targets the
# current 2-arg tracker API (see the merge note in schc_failure_tracker.h).
add_executable(schc_failure_tracker
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/schc_failure_tracker.c
)
target_include_directories(schc_failure_tracker PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/include
)

lichen_test_target(schc_failure_tracker)

enable_testing()
add_test(NAME schc_failure_tracker COMMAND schc_failure_tracker)
