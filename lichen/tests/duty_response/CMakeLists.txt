# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(duty_response_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(duty_response_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/duty_response.c
)

target_include_directories(duty_response_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/include
)

lichen_test_target(duty_response_test)

include(CTest)
add_test(NAME duty_response COMMAND duty_response_test)
