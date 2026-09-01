# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(desync_fsm_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(desync_fsm_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/tdma.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/drift_bound.c
)
target_include_directories(desync_fsm_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
)
target_compile_definitions(desync_fsm_test PRIVATE
  CONFIG_LICHEN_TDMA=1
  CONFIG_LICHEN_CCP_TIME_SYNC=1
)

# Apply sanitizers and hardening
lichen_test_target(desync_fsm_test)
target_link_libraries(desync_fsm_test PRIVATE pthread m)

include(CTest)
add_test(NAME desync_fsm
         COMMAND desync_fsm_test ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/ccp16-desync.json
         WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
# Golden vectors are committed in-repo; a missing file is a real failure,
# not a skip — no SKIP_RETURN_CODE property.
set_tests_properties(desync_fsm PROPERTIES ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1")
