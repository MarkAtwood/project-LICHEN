# SPDX-License-Identifier: GPL-3.0-or-later

# TDMA beacon wire codec tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(tdma_beacon_test C)

# Common test config (sanitizers + hardening)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

# Include paths
include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_SOURCE_DIR}
)

# Build test executable
add_executable(tdma_beacon_test
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/beacon.c
)

# Apply sanitizers and hardening
lichen_test_target(tdma_beacon_test)

include(CTest)
add_test(NAME tdma_beacon COMMAND tdma_beacon_test)
