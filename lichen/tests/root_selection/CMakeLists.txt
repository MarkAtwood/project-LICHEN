# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(root_selection_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

set(LINK_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link)

add_executable(root_selection_test
  main.c
  ${LINK_SRC}/root_selection.c
)

target_include_directories(root_selection_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

lichen_test_target(root_selection_test)

include(CTest)
add_test(NAME root_selection COMMAND root_selection_test)
