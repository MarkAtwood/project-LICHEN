# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(coap_backoff_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(coap_backoff_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/backoff.c
)

target_include_directories(coap_backoff_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/coap/include
)

lichen_test_target(coap_backoff_test)

include(CTest)
add_test(NAME coap_backoff COMMAND coap_backoff_test)
