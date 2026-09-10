# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(schc_failure_tracker)
endif()

set(TRACKER_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/schc/schc_failure_tracker.c)
set(SCHC_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/schc/include)

if(DEFINED ENV{ZEPHYR_BASE})
  # src/main.c targets the current 2-arg tracker API (see the merge note in
  # schc_failure_tracker.h); the tracker itself comes from the
  # CONFIG_LICHEN_SCHC-gated schc library.
  target_sources(app PRIVATE src/main.c)
else()
  project(schc_failure_tracker C)
  add_executable(schc_failure_tracker src/main.c ${TRACKER_SOURCE})
  target_include_directories(schc_failure_tracker PRIVATE ${SCHC_INCLUDE})
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(schc_failure_tracker)
  enable_testing()
  add_test(NAME schc_failure_tracker COMMAND schc_failure_tracker)
endif()
