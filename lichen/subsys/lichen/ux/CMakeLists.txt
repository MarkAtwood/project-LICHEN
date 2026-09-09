# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()

# Pure timing engine (spec 19 §10 table) is always compiled; the Zephyr
# GPIO backend drives led0 when the feature is enabled.
zephyr_library_sources(ux_led_core.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_UX_LED ux_led_zephyr.c)

zephyr_include_directories(include)
