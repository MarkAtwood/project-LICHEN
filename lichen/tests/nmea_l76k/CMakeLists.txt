# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(nmea_l76k LANGUAGES C)

target_include_directories(app PRIVATE ${ZEPHYR_BASE}/drivers/gnss)
target_sources(app PRIVATE src/main.c)
