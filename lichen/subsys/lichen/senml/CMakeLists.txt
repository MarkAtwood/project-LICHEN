# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN SenML subsystem

zephyr_library()

zephyr_library_sources(
  senml.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
