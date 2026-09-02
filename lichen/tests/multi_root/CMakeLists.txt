# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(multi_root)
else()
  project(multi_root C)
endif()

set(MULTI_ROOT_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/rpl/multi_root.c)
set(RPL_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/rpl/include)

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE src/main.c)
else()
  add_executable(multi_root src/main.c ${MULTI_ROOT_SOURCE})
  target_include_directories(multi_root PRIVATE ${RPL_INCLUDE})
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(multi_root)
  enable_testing()
  add_test(NAME multi_root COMMAND multi_root)
endif()
