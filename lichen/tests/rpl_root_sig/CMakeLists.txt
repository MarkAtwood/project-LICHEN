# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# Root DIO Signature option wire format (spec/06-security.md 8.10.1) —
# standalone host test mirroring the contract pinned by
# rust/lichen-rpl/src/message.rs (OPT_ROOT_DIO_SIGNATURE 0x17).

cmake_minimum_required(VERSION 3.20)
project(rpl_root_sig_test C)

include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)

set(RPL_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../subsys/lichen/rpl)
set(HOST_STUB_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../include)

set(CRYPTO_SRC ${RPL_SRC_DIR}/../crypto)
set(LINK_SRC ${RPL_SRC_DIR}/../link)

add_executable(rpl_root_sig_test
  src/main.c
  ${RPL_SRC_DIR}/messages.c
  ${RPL_SRC_DIR}/root_dio_sig.c
  ${RPL_SRC_DIR}/root_dio_replay.c
  ${LINK_SRC}/identity_addr.c
  ${CRYPTO_SRC}/monocypher.c
  ${CRYPTO_SRC}/monocypher-ed25519.c
)
target_compile_definitions(rpl_root_sig_test PRIVATE LICHEN_RPL_TEST=1)
# NOTE: deliberately does not call lichen_test_target() — this host's gcc 13
# rejects its -std=c23 flag. The test builds with the default dialect and
# keeps LICHEN_RPL_TEST=1 (required by the host byteorder stub).

target_include_directories(rpl_root_sig_test PRIVATE
  ${RPL_SRC_DIR}/include
  ${RPL_SRC_DIR}
  ${LINK_SRC}/include
  ${CRYPTO_SRC}
  ${HOST_STUB_INCLUDE_DIR}
  ${HOST_STUB_INCLUDE_DIR}/..
)
