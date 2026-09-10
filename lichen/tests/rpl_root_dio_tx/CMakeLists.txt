# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# Gateway RPL root DIO TX regression test (R-RPL-007: MOP=1 non-storing) —
# standalone host build of apps/gateway/src/rpl_root.c against Zephyr
# net_pkt/net_if stubs that capture the emitted packet bytes.

cmake_minimum_required(VERSION 3.20)
project(rpl_root_dio_tx_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

set(RPL_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl)
set(LINK_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link)

add_executable(rpl_root_dio_tx_test
  src/main.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src/rpl_root.c
  ${RPL_SRC_DIR}/messages.c
  ${RPL_SRC_DIR}/dodag.c
  ${RPL_SRC_DIR}/trickle.c
  ${RPL_SRC_DIR}/rpl_sf_assignment.c
  ${RPL_SRC_DIR}/rpl_dao_build.c
  ${RPL_SRC_DIR}/rpl_dao_process.c
  ${RPL_SRC_DIR}/rpl_dao_tx_persist.c
  ${RPL_SRC_DIR}/rpl_prefix.c
  ${RPL_SRC_DIR}/rpl_routing_table.c
  ${LINK_SRC_DIR}/hash32.c
  ${LINK_SRC_DIR}/identity_addr.c
  ${LINK_SRC_DIR}/schnorr48.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto/monocypher.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto/monocypher-ed25519.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/hal_storage_redundant.c
)

target_include_directories(rpl_root_dio_tx_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../../apps/gateway/src
  ${RPL_SRC_DIR}/include
  ${LINK_SRC_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  ${CMAKE_CURRENT_SOURCE_DIR}/stub
  ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_compile_definitions(rpl_root_dio_tx_test PRIVATE
  LICHEN_RPL_TEST=1
  CONFIG_LICHEN_RPL_TRICKLE_IMIN_MS=4000
  CONFIG_LICHEN_RPL_TRICKLE_IMAX_DOUBLINGS=8
  CONFIG_LICHEN_RPL_TRICKLE_K=10
)

lichen_test_target(rpl_root_dio_tx_test)

include(CTest)
add_test(NAME rpl_root_dio_tx COMMAND rpl_root_dio_tx_test)
