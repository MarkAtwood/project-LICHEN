# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(redundant_slot)
else()
  project(redundant_slot C)
endif()

set(REDUNDANT_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/hal/redundant_slot.c)
set(HAL_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/hal/include)

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE src/main.c)
else()
  add_executable(redundant_slot src/main.c ${REDUNDANT_SOURCE})
  target_include_directories(redundant_slot PRIVATE ${HAL_INCLUDE})
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(redundant_slot)
  enable_testing()
  add_test(NAME redundant_slot COMMAND redundant_slot)
endif()
