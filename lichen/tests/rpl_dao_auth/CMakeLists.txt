# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# DAO origin authorization at the RPL root (spec/05-routing.md 8.7) —
# standalone host test mirroring the contract pinned by
# rust/lichen-rpl/tests/dao_prefix_authorization.rs.

cmake_minimum_required(VERSION 3.20)
project(rpl_dao_auth_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

set(RPL_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl)
set(LINK_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link)
set(CRYPTO_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto)
# Host stubs (zephyr/kernel.h) so real headers parse outside Zephyr.
set(HOST_STUB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

add_executable(rpl_dao_auth_test
  src/main.c
  ${RPL_SRC_DIR}/rpl_dao_process.c
  ${RPL_SRC_DIR}/rpl_dao_build.c
  ${RPL_SRC_DIR}/rpl_dao_tx_persist.c
  ${RPL_SRC_DIR}/rpl_routing_table.c
  ${RPL_SRC_DIR}/rpl_prefix.c
  ${RPL_SRC_DIR}/messages.c
  ${RPL_SRC_DIR}/rpl_sf_assignment.c
  ${LINK_SRC}/schnorr48.c
  ${LINK_SRC}/frame.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/hash32.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/hal_storage_redundant.c
  ${CRYPTO_SRC}/monocypher.c
  ${CRYPTO_SRC}/monocypher-ed25519.c
)

target_include_directories(rpl_dao_auth_test PRIVATE
  ${RPL_SRC_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/hal/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
  ${LINK_SRC}
  ${CRYPTO_SRC}
  ${HOST_STUB_INCLUDE_DIR}
)

# Frame constants schnorr48.c expects (same as tests/coap_slot_claim).
target_compile_definitions(rpl_dao_auth_test PRIVATE
  LICHEN_MAX_FRAME_LEN=254
  LICHEN_MAX_FRAME_BODY_LEN=250
  CONFIG_LICHEN_CRYPTO_MONOCYPHER=1
)
# Match lichen/tests/rpl_routing/prj.conf so capacity semantics agree.
target_compile_definitions(rpl_dao_auth_test PRIVATE
  LICHEN_RPL_TEST=1
  CONFIG_LICHEN_RPL_MAX_ROUTES=7
  CONFIG_LICHEN_RPL_MAX_PARENTS=4
  CONFIG_LICHEN_RPL_MAX_ACTIVE_DAO_CANDIDATES=8
)
lichen_test_target(rpl_dao_auth_test)
# rpl_routing.h includes rpl_messages.h, which lacks _Nonnull on two pointers.
# Apple Clang -Wnullability-completeness is fatal under this target's -Werror,
# and messages.c relies on implicit int conversions.
target_compile_options(rpl_dao_auth_test PRIVATE
  -Wno-nullability-completeness
  -Wno-implicit-int-conversion
)

include(CTest)
add_test(NAME rpl_dao_auth COMMAND rpl_dao_auth_test)
