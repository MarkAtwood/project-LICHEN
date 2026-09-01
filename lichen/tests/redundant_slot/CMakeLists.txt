# SPDX-License-Identifier: GPL-3.0-or-later

# Two-slot redundant-record persistence tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(redundant_slot_test C)

# Common test config (sanitizers + hardening)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

# Include paths
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/include
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Build test executable
add_executable(redundant_slot_test
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/redundant_slot.c
)

# Apply sanitizers and hardening
lichen_test_target(redundant_slot_test)

include(CTest)
add_test(NAME redundant_slot COMMAND redundant_slot_test)
