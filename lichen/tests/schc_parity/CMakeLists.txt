# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
project(schc_parity_test C)

include(../cmake/test_common.cmake)

# The parity vectors are the committed source header schc_parity_vectors.h
# (sole source of truth — no build-dir generation).  After editing
# test/vectors/schc_compression.json, regenerate it (from the repository
# root) with:
#   python3 lichen/tests/schc_parity/gen_vectors.py \
#     test/vectors/schc_compression.json \
#     lichen/tests/schc_parity/schc_parity_vectors.h

add_executable(schc_parity_test
  main.c
  ../../subsys/schc/bitstream.c
  ../../subsys/schc/schc.c
  ../../subsys/lichen/schc/schc.c
  ../../subsys/lichen/schc/schc_checksum.c
  ../../subsys/lichen/schc/schc_compress.c
  ../../subsys/lichen/schc/schc_decompress.c
  ../../subsys/lichen/schc/schc_helpers.c
)
target_include_directories(schc_parity_test PRIVATE
  ../../subsys/schc/include
  ../../subsys/lichen/schc/include
  ../../subsys/lichen/schc
)
lichen_test_target(schc_parity_test)
target_compile_options(schc_parity_test PRIVATE -Wno-implicit-int-conversion)

enable_testing()
add_test(NAME schc_parity_test COMMAND schc_parity_test)
