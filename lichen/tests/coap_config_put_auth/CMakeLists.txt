# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(coap_config_put_auth)

target_include_directories(app PRIVATE
  ../../include
  ../../subsys
  ../../subsys/lichen/coap/include
  ../../subsys/lichen/oscore/include
  ../../subsys/lichen/senml/include
  ../../subsys/lichen/link/include
  ../../subsys/lichen/transport/include
  ../../subsys/lichen/gateway/include
)

target_compile_definitions(app PRIVATE
  CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX=320
  CONFIG_LICHEN_COAP_SERVER_LOG_LEVEL=4
)

# coap_server.c provides the real lichen_coap_respond and calls it from
# within its own translation unit, so --wrap cannot intercept it there;
# capture responses one level down at coap_resource_send (different TU,
# same approach as lichen/tests/coap_msg_sent). The OSCORE helper
# (coap_oscore.c) is intentionally NOT linked so its entry points can be
# mocked directly in main.c.
zephyr_ld_options(-Wl,--wrap=coap_resource_send)
zephyr_ld_options(-Wl,--wrap=coap_oscore_authorize_mutating)

target_sources(app PRIVATE
  src/main.c
  ../../subsys/lichen/coap/coap_server.c
  ../../subsys/lichen/coap/coap_respond.c
)

# Per-service CoAP resource section (mirrors lichen/tests/coap_config).
zephyr_linker_sources(DATA_SECTIONS sections-ram.ld)
