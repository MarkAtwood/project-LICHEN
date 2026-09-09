# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(capability_announce_test C)
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/test_common.cmake)
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
set(CAPABILITY_ANNOUNCE_VECTORS_HEADER ${CMAKE_CURRENT_BINARY_DIR}/capability_announce_vectors.h)
add_custom_command(
  OUTPUT ${CAPABILITY_ANNOUNCE_VECTORS_HEADER}
  COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${CAPABILITY_ANNOUNCE_VECTORS_HEADER}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/gen_vectors.py
          ${CMAKE_CURRENT_SOURCE_DIR}/../../../test/vectors/capability_announcements.json
  COMMENT "Generating capability_announce_vectors.h"
  VERBATIM)
add_executable(capability_announce_test
  src/main.c
  ${CAPABILITY_ANNOUNCE_VECTORS_HEADER}
  ../../subsys/lichen/gateway/capability_announce.c
  ../../subsys/lichen/link/schnorr48.c
  ../../subsys/lichen/crypto/monocypher.c
  ../../subsys/lichen/crypto/monocypher-ed25519.c
)
target_include_directories(capability_announce_test PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}
  ../../subsys/lichen/gateway/include
  ../../subsys/lichen/link/include
  ../../subsys/lichen/crypto
  ../../include
)
target_compile_definitions(capability_announce_test PRIVATE CONFIG_LICHEN_CRYPTO_MONOCYPHER=1)
# Small table so the host test exercises LRU eviction, the egress-reserved
# tail, and the eviction seq-floor ledger without allocating 256 slots.
target_compile_definitions(capability_announce_test PRIVATE CONFIG_LICHEN_CAPABILITY_TABLE_CAPACITY=8)
target_link_libraries(capability_announce_test PRIVATE OpenSSL::Crypto)
lichen_test_target(capability_announce_test)
include(CTest)
add_test(NAME capability_announce COMMAND capability_announce_test)
