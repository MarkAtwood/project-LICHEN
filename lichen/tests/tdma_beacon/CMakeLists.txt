# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

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
)

# Apply sanitizers and hardening
lichen_test_target(tdma_beacon_test)

include(CTest)
add_test(NAME tdma_beacon
         COMMAND tdma_beacon_test ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/ccp_beacon_format.json
         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
