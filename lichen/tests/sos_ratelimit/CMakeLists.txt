# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(sos_ratelimit_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(sos_ratelimit_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/sos_ratelimit.c
)
target_include_directories(sos_ratelimit_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

# Apply sanitizers and hardening
lichen_test_target(sos_ratelimit_test)

include(CTest)
add_test(NAME sos_ratelimit
         COMMAND sos_ratelimit_test ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/sos_rate_limiting.json
         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
