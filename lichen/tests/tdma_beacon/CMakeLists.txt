# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# TDMA beacon wire codec tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(tdma_beacon_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(tdma_beacon_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/beacon.c
)
target_include_directories(tdma_beacon_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
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
add_test(NAME tdma_beacon
         COMMAND tdma_beacon_test ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/ccp_beacon_format.json
         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
add_test(NAME tdma_beacon COMMAND tdma_beacon_test)
