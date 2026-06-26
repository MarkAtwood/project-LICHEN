# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN link layer

zephyr_library()

zephyr_library_sources(
  frame.c
  replay.c
)

zephyr_library_sources_ifdef(CONFIG_LICHEN_LINK_SCHNORR
  schnorr48.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
