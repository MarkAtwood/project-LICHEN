# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(schc_failure_tracker_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(schc_failure_tracker_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/schc_failure_tracker.c
)
target_include_directories(schc_failure_tracker_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc/include
)

# Apply sanitizers and hardening
lichen_test_target(schc_failure_tracker_test)

include(CTest)
add_test(NAME schc_failure_tracker COMMAND schc_failure_tracker_test)
cmake_minimum_required(VERSION 3.20.0)

if(DEFINED ENV{ZEPHYR_BASE})
  find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
  project(schc_failure_tracker)
else()
  project(schc_failure_tracker C)
endif()

set(TRACKER_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/schc/schc_failure_tracker.c)
set(SCHC_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/schc/include)

if(DEFINED ENV{ZEPHYR_BASE})
  target_sources(app PRIVATE src/main.c)
else()
  add_executable(schc_failure_tracker src/main.c ${TRACKER_SOURCE})
  target_include_directories(schc_failure_tracker PRIVATE ${SCHC_INCLUDE})
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
  lichen_test_target(schc_failure_tracker)
  enable_testing()
  add_test(NAME schc_failure_tracker COMMAND schc_failure_tracker)
endif()
