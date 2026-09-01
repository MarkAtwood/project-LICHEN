# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(rpl_dao_tx_persist_test C)

# Common test config (sanitizers + hardening + CONFIG_* defaults)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

add_executable(rpl_dao_tx_persist_test
  main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/rpl_dao_tx_persist.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/hal_storage_redundant.c
)
target_include_directories(rpl_dao_tx_persist_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/include
)

# Apply sanitizers and hardening
lichen_test_target(rpl_dao_tx_persist_test)

include(CTest)
add_test(NAME rpl_dao_tx_persist COMMAND rpl_dao_tx_persist_test)
