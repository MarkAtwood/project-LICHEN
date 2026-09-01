# SPDX-License-Identifier: GPL-3.0-or-later

# CCP slot_map validation tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(ccp_slot_map_test C)

# Common test config (sanitizers + hardening)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

# Include paths
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Build test executable
add_executable(ccp_slot_map_test
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/tdma.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/hash32.c
)

target_compile_definitions(ccp_slot_map_test PRIVATE
  CONFIG_LICHEN_TDMA=1
  CONFIG_LICHEN_ROUTING_GRADIENT_MAX_ENTRIES=16
  CONFIG_LICHEN_DEFAULT_SF=10
)

# Apply sanitizers and hardening
lichen_test_target(ccp_slot_map_test)

include(CTest)
add_test(NAME ccp_slot_map COMMAND ccp_slot_map_test)
