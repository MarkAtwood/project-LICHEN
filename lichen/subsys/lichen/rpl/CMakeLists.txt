# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN RPL routing

zephyr_library()

zephyr_library_sources(
  trickle.c
  messages.c
  dodag.c
  routing.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
