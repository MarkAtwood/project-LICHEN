# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# SCHC session table (bounded state) unit tests - standalone build

cmake_minimum_required(VERSION 3.20)
project(schc_session_table_test C)

enable_testing()

include(../cmake/test_common.cmake)

add_executable(schc_session_table_test
  main.c
  ../../subsys/lichen/schc/schc_session.c
  ../../subsys/lichen/schc/schc_session_table.c
)
target_include_directories(schc_session_table_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)
lichen_test_target(schc_session_table_test)

add_test(NAME schc_session_table COMMAND schc_session_table_test)
