# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(rpl_sf_assignment_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(rpl_sf_assignment_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/rpl_sf_assignment.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/hash32.c
)
target_include_directories(rpl_sf_assignment_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)

# Apply sanitizers and hardening
lichen_test_target(rpl_sf_assignment_test)

include(CTest)
add_test(NAME rpl_sf_assignment
         COMMAND rpl_sf_assignment_test ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/sf_assignment.json
         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
