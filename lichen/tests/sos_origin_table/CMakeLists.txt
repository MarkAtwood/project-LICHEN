# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(sos_origin_table_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

# The header itself is self-contained (ratelimit-state init is memset(0)
# inline), but the test exercises the per-origin RATE LIMIT behavior, so
# it links the real sos_ratelimit.c. Host builds always have it.
add_executable(sos_origin_table_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/sos_ratelimit.c
)
target_include_directories(sos_origin_table_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

lichen_test_target(sos_origin_table_test)

include(CTest)
add_test(NAME sos_origin_table COMMAND sos_origin_table_test)
