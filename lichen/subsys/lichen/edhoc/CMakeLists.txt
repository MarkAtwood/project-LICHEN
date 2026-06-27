# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_include_directories(include)

zephyr_library_sources_ifdef(CONFIG_LICHEN_EDHOC edhoc.c)
