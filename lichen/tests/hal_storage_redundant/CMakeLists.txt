# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(hal_storage_redundant_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(hal_storage_redundant_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/hal_storage_redundant.c
)

target_include_directories(hal_storage_redundant_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/include
)

lichen_test_target(hal_storage_redundant_test)
target_link_libraries(hal_storage_redundant_test PRIVATE pthread)

include(CTest)
add_test(NAME hal_storage_redundant COMMAND hal_storage_redundant_test)
