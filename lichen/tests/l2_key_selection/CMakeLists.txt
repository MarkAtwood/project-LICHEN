# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# SIID-indexed signer key-selection fail-closed tests (spec/02-physical-link.md
# 4.2, project-LICHEN-worker6-nxew option b) - standalone host build.

cmake_minimum_required(VERSION 3.20)
project(l2_key_selection_test C)

find_package(Threads REQUIRED)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

set(LICHEN_LINK_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/link)
set(LICHEN_CRYPTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/crypto)
set(LICHEN_SCHC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/schc)
set(SCHC_CORE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/schc)

add_executable(l2_key_selection_test
  main.c
  ${LICHEN_LINK_DIR}/frame.c
  ${LICHEN_LINK_DIR}/lichen_link_rx.c
  ${LICHEN_LINK_DIR}/lichen_link_tx.c
  ${LICHEN_LINK_DIR}/replay.c
  ${LICHEN_LINK_DIR}/schnorr48.c
  ${LICHEN_LINK_DIR}/link_ctx.c
  ${LICHEN_LINK_DIR}/link_cca.c
  ${LICHEN_LINK_DIR}/csma.c
  ${LICHEN_LINK_DIR}/hash32.c
  ${LICHEN_CRYPTO_DIR}/monocypher.c
  ${LICHEN_CRYPTO_DIR}/monocypher-ed25519.c
  ${SCHC_CORE_DIR}/bitstream.c
  ${SCHC_CORE_DIR}/schc.c
  ${LICHEN_SCHC_DIR}/schc.c
  ${LICHEN_SCHC_DIR}/schc_checksum.c
  ${LICHEN_SCHC_DIR}/schc_compress.c
  ${LICHEN_SCHC_DIR}/schc_decompress.c
  ${LICHEN_SCHC_DIR}/schc_helpers.c
)
target_include_directories(l2_key_selection_test PRIVATE
  ${LICHEN_LINK_DIR}/include
  ${LICHEN_SCHC_DIR}/include
  ${LICHEN_SCHC_DIR}
  ${SCHC_CORE_DIR}/include
  ${LICHEN_CRYPTO_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)
# CONFIG_LICHEN_CRYPTO_MONOCYPHER selects the real schnorr48 implementation
# (same gate as tests/schnorr48 and tests/fuzz); LICHEN_MAX_FRAME* are the
# wire-format constants frame.c expects (spec/02 4.1).
target_compile_definitions(l2_key_selection_test PRIVATE
  CONFIG_LICHEN_CRYPTO_MONOCYPHER=1
  LICHEN_MAX_FRAME_LEN=255
  LICHEN_MAX_FRAME_BODY_LEN=254
)
if(APPLE)
  target_compile_definitions(l2_key_selection_test PRIVATE explicit_bzero=bzero)
  target_compile_options(l2_key_selection_test PRIVATE -include strings.h)
endif()
target_link_libraries(l2_key_selection_test PRIVATE Threads::Threads)

lichen_test_target(l2_key_selection_test)

include(CTest)
add_test(NAME l2_key_selection COMMAND l2_key_selection_test)
