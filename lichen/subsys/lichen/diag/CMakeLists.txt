# SPDX-License-Identifier: GPL-3.0-or-later

# Hardware diagnostics event ring - Zephyr build

zephyr_library_sources(lichen_diag.c)
# Public its include/ tree like every other subsystem (link, schc, coap...)
# so <lichen/diag.h> resolves when LICHEN_DIAG pulls this module in.
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
