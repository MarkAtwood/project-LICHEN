# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

# LICHEN HMI subsystem (spec 19 device UX design language)

zephyr_library()

zephyr_library_sources(
  hmi_led.c
)

zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
