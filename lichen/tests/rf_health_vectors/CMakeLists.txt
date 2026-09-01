# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(rf_health_vectors_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(rf_health_vectors_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/rf_health.c
)
target_include_directories(rf_health_vectors_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

# Apply sanitizers and hardening
lichen_test_target(rf_health_vectors_test)

include(CTest)
add_test(NAME rf_health_vectors
         COMMAND rf_health_vectors_test ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/ccp16.json
         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
