# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(sf_assignment_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(sf_assignment_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/sf_assignment.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/hash32.c
)

target_include_directories(sf_assignment_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

lichen_test_target(sf_assignment_test)
target_link_libraries(sf_assignment_test PRIVATE pthread)

include(CTest)
add_test(NAME sf_assignment COMMAND sf_assignment_test)
