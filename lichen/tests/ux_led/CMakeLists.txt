# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(ux_led_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(ux_led_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/ux/ux_led_core.c
)
target_include_directories(ux_led_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/ux/include
)

lichen_test_target(ux_led_test)

include(CTest)
add_test(NAME ux_led COMMAND ux_led_test)
