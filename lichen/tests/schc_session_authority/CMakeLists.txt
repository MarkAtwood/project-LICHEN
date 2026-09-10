# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# SCHC session authority lifecycle unit tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(schc_session_authority_test C)

include(../cmake/test_common.cmake)

add_executable(schc_session_authority_test
  main.c
  ../../subsys/lichen/schc/schc_session.c
  ../../subsys/lichen/schc/schc_session_table.c
  ../../subsys/lichen/schc/schc_session_authority.c
)
target_include_directories(schc_session_authority_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)
lichen_test_target(schc_session_authority_test)
