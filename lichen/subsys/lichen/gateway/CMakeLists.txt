# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()
zephyr_library_sources(tunnel_auth.c)
zephyr_include_directories(include)
# tunnel_auth.c calls lichen_sha256() (l2 lichen_util.h)
zephyr_include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../l2)
