# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(sos_post_origin)

target_include_directories(app PRIVATE
  ../../include
  ../../subsys
  ../../subsys/lichen/coap/include
  ../../subsys/lichen/oscore/include
  ../../subsys/lichen/senml/include
  ../../subsys/lichen/link/include
  ../../subsys/lichen/transport/include
  ../../subsys/lichen/gateway/include
  ../../subsys/lichen/crypto
)

# Real crypto path in sos_origin.c / schnorr48.c (their #else branches are
# fail-closed stubs for builds without Monocypher).
target_compile_definitions(app PRIVATE
  CONFIG_LICHEN_CRYPTO_MONOCYPHER=1
  CONFIG_LICHEN_OSCORE_PLAINTEXT_MAX=320
  CONFIG_LICHEN_COAP_SERVER_LOG_LEVEL=4
)

# coap_respond.c provides the real lichen_coap_respond; coap_server.c
# calls it from within its own translation unit, so --wrap cannot
# intercept it there; capture responses one level down at
# coap_resource_send (different TU, same approach as
# lichen/tests/coap_msg_sent). The OSCORE helper (coap_oscore.c) is
# intentionally NOT linked so its entry points can be mocked in main.c.
zephyr_ld_options(-Wl,--wrap=coap_resource_send)

target_sources(app PRIVATE
  src/main.c
  ../../subsys/lichen/coap/coap_server.c
  ../../subsys/lichen/coap/coap_respond.c
  ../../subsys/lichen/coap/sos_alert.c
  ../../subsys/lichen/link/sos_origin.c
  ../../subsys/lichen/link/sos_ratelimit.c
  ../../subsys/lichen/link/schnorr48.c
  ../../subsys/lichen/link/identity_addr.c
  ../../subsys/lichen/crypto/monocypher.c
  ../../subsys/lichen/crypto/monocypher-ed25519.c
)

# Vendored Monocypher sources are upstream style; do not hold them to the
# project's -Wconversion discipline.
foreach(src
  ../../subsys/lichen/crypto/monocypher.c
  ../../subsys/lichen/crypto/monocypher-ed25519.c
)
  set_source_files_properties(${src} PROPERTIES COMPILE_OPTIONS "-Wno-conversion")
endforeach()

# Per-service CoAP resource section (mirrors lichen/tests/coap_config).
zephyr_linker_sources(DATA_SECTIONS sections-ram.ld)
