# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# DIO Time Option codec — standalone host test (bd project-LICHEN-worker6-ndk7).
# Pins the cross-implementation vector test/vectors/packets-timing.json
# "dio_time_option" (Type 0x15) and RFC 6550 Pad1 handling.

cmake_minimum_required(VERSION 3.20)
project(rpl_dio_time_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(rpl_dio_time_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/messages.c
)

target_include_directories(rpl_dio_time_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
  ${CMAKE_CURRENT_SOURCE_DIR}/stub
)
lichen_test_target(rpl_dio_time_test)
target_compile_options(rpl_dio_time_test PRIVATE
  -Wno-nullability-completeness
)

include(CTest)
add_test(NAME rpl_dio_time COMMAND rpl_dio_time_test)
