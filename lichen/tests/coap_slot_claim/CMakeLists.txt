# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# GCP-6.5 slot-claim COSE_Sign1 encode/decode/verify — standalone host test
# (same pattern as tests/rpl_dodag: real subsystem sources + stub headers).
# The Zephyr-side firmware build (resource handlers, key store, wall clock)
# is validated by the Twister/AWS CI builds, not here: the fake key store
# and seq hooks below intentionally replace those subsystems on host.

cmake_minimum_required(VERSION 3.20)
project(coap_slot_claim_test C)

set(SLOT_COORD_SRC ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/coap/coap_slot_coord.c)
set(LINK_SRC ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/link)
set(CRYPTO_SRC ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/crypto)

add_executable(coap_slot_claim_test
  src/main.c
  ${SLOT_COORD_SRC}
  ${LINK_SRC}/schnorr48.c
  ${LINK_SRC}/frame.c
  ${CRYPTO_SRC}/monocypher.c
  ${CRYPTO_SRC}/monocypher-ed25519.c
  stub/tinycrypt/sha256.c
  stub/tinycrypt/utils.c
)

target_include_directories(coap_slot_claim_test PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/coap/include
  ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/oscore/include
  ${CMAKE_CURRENT_LIST_DIR}/../../subsys/lichen/link/include
  ${CMAKE_CURRENT_LIST_DIR}/../../include
  ${CRYPTO_SRC}
  ${CMAKE_CURRENT_LIST_DIR}/stub
)

# CONFIG_LICHEN_LINK_SCHNORR / CONFIG_TINYCRYPT_SHA256 enable the real
# verify path (fail-closed #error otherwise); CONFIG_LICHEN_CRYPTO_
# MONOCYPHER enables the real schnorr48/monocypher implementation and
# LICHEN_MAX_FRAME* provide the frame constants schnorr48.c expects.
# LICHEN_SLOT_CLAIM_TEST arms the host stub headers and omits the weak
# claim_seq hook defaults so the test's strong definitions are used.
target_compile_definitions(coap_slot_claim_test PRIVATE
  LICHEN_SLOT_CLAIM_TEST=1
  CONFIG_LICHEN_LINK_SCHNORR=1
  CONFIG_TINYCRYPT_SHA256=1
  CONFIG_LICHEN_CRYPTO_MONOCYPHER=1
  CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX=256
  CONFIG_LICHEN_SLOT_CLAIM_MAX_DURATION_SUPERFRAMES=5
  LICHEN_MAX_FRAME_LEN=254
  LICHEN_MAX_FRAME_BODY_LEN=250
)

include(${CMAKE_CURRENT_LIST_DIR}/../cmake/test_common.cmake)
lichen_test_target(coap_slot_claim_test)
# coap_oscore.h has pointers without explicit nullability annotations
# (same situation as rpl_messages.h in the rpl_dodag host test).
target_compile_options(coap_slot_claim_test PRIVATE
  -Wno-nullability-completeness
)
# Vendored upstream tinycrypt (unmodified): keep its upstream form and
# silence -Wconversion noise inside it only.
set_source_files_properties(stub/tinycrypt/sha256.c PROPERTIES
  COMPILE_OPTIONS "-Wno-conversion;-Wno-shorten-64-to-32"
)
set_source_files_properties(stub/tinycrypt/utils.c PROPERTIES
  COMPILE_OPTIONS "-Wno-conversion"
)

enable_testing()
add_test(NAME coap_slot_claim COMMAND coap_slot_claim_test)
