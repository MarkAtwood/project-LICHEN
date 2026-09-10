# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(coap_oscore_fallback)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})
target_sources(app PRIVATE ../../subsys/lichen/coap/coap_server.c)
target_include_directories(app PRIVATE
  ../../subsys/lichen/senml/include
  ../../subsys/lichen/gateway/include
)

# Per-service CoAP resource sections (mirrors zephyr/tests/net/lib/coap_server).
zephyr_linker_sources(DATA_SECTIONS sections-ram.ld)

# Inbox handler regression captures only that resource's sends. Other suite
# resources still use the real CoAP service/socket implementation.
zephyr_ld_options(
  -Wl,--wrap=coap_service_start
  -Wl,--wrap=coap_resource_send
)
