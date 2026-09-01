# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(tdma_root_select_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(tdma_root_select_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/tdma_root_select.c
)
target_include_directories(tdma_root_select_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)
target_link_libraries(tdma_root_select_test PRIVATE m)

# Apply sanitizers and hardening
lichen_test_target(tdma_root_select_test)

include(CTest)
add_test(NAME tdma_root_select COMMAND tdma_root_select_test)
