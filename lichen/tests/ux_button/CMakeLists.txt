# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(ux_button_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(ux_button_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/ux/ux_button_core.c
)
target_include_directories(ux_button_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/ux/include
)

lichen_test_target(ux_button_test)

include(CTest)
add_test(NAME ux_button COMMAND ux_button_test)
