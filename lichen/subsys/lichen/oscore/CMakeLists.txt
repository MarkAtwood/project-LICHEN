# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN OSCORE subsystem

zephyr_library()

zephyr_library_sources(
  oscore.c
  aes_ccm.c
  hkdf.c
  coap_oscore.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
