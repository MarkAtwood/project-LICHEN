# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

zephyr_library()

# Pure engines (spec 19 §10 LED table, §4/§8/§9 button grammar) are always
# compiled; the Zephyr GPIO backends drive hardware when enabled.
zephyr_library_sources(ux_led_core.c ux_button_core.c ux_strings.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_UX_LED ux_led_zephyr.c)
zephyr_library_sources_ifdef(CONFIG_LICHEN_UX_BUTTON ux_button_zephyr.c)

zephyr_include_directories(include)
