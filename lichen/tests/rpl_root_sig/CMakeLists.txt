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
  ${RPL_SRC_DIR}/dodag.c
  ${RPL_SRC_DIR}/trickle.c
  ${RPL_SRC_DIR}/rpl_sf_assignment.c
  ${LINK_SRC}/hash32.c
  ${RPL_SRC_DIR}/root_dio_sig.c
  ${RPL_SRC_DIR}/root_dio_replay.c
  ${LINK_SRC}/identity_addr.c
  ${CRYPTO_SRC}/monocypher.c
  ${CRYPTO_SRC}/monocypher-ed25519.c
  ${LINK_SRC}/schnorr48.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../coap_slot_claim/stub/tinycrypt/sha256.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../coap_slot_claim/stub/tinycrypt/utils.c
)
target_compile_definitions(rpl_root_sig_test PRIVATE
  LICHEN_RPL_TEST=1
  CONFIG_LICHEN_CRYPTO_MONOCYPHER=1
  CONFIG_LICHEN_LINK_SCHNORR=1
  CONFIG_LICHEN_RPL_ROOT_SIG=1
  CONFIG_LICHEN_LINK_MAX_NEIGHBORS=16
)
# LICHEN_RPL_TEST=1 (required by the host byteorder stub) stays a suite-local
# define; sanitizers, hardening, and the compiler-probed -std flag come from
# the shared config.
lichen_test_target(rpl_root_sig_test)

# Vendored upstream tinycrypt stubs (unmodified, shared with coap_slot_claim):
# same policy as that suite — silence -Wconversion inside vendored sources
# only; no local patches to third-party crypto code for host-only lints.
set_source_files_properties(
  ${CMAKE_CURRENT_SOURCE_DIR}/../coap_slot_claim/stub/tinycrypt/sha256.c
  PROPERTIES
  COMPILE_OPTIONS "-Wno-conversion;-Wno-shorten-64-to-32"
)
set_source_files_properties(
  ${CMAKE_CURRENT_SOURCE_DIR}/../coap_slot_claim/stub/tinycrypt/utils.c
  PROPERTIES
  COMPILE_OPTIONS "-Wno-conversion"
)

target_include_directories(rpl_root_sig_test PRIVATE
  ${RPL_SRC_DIR}/include
  ${RPL_SRC_DIR}
  ${LINK_SRC}/include
  ${CRYPTO_SRC}
  ${HOST_STUB_INCLUDE_DIR}
  ${HOST_STUB_INCLUDE_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/../coap_slot_claim/stub
  ${CMAKE_CURRENT_SOURCE_DIR}/../../include
)

include(CTest)
add_test(NAME rpl_root_sig COMMAND rpl_root_sig_test)
