# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(coap_oscore_fallback)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})

# Per-service CoAP resource sections (mirrors zephyr/tests/net/lib/coap_server).
zephyr_linker_sources(DATA_SECTIONS sections-ram.ld)
