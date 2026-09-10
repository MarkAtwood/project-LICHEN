# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(l2_payload_test C)

include(../cmake/test_common.cmake)

add_executable(l2_payload_test main.c)
target_include_directories(l2_payload_test PRIVATE
  ../../subsys/lichen/link/include
)
lichen_test_target(l2_payload_test)

enable_testing()
add_test(NAME l2_payload_test COMMAND l2_payload_test)
