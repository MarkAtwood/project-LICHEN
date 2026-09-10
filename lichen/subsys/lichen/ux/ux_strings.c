/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file ux_strings.c
 * @brief Spec 19 §13 v0.1 English string table.
 */

#include <lichen/ux_strings.h>

#include <stddef.h>

static const char *const strings[LICHEN_UX_STRING_COUNT] = {
	[LICHEN_UX_STRING_BOOT] = "Boot",
	[LICHEN_UX_STRING_STATUS] = "Status",
	[LICHEN_UX_STRING_POSITION] = "Position",
	[LICHEN_UX_STRING_LAST_MESSAGE] = "Last message",
	[LICHEN_UX_STRING_SCREENSAVER] = "Screensaver",
	[LICHEN_UX_STRING_BATTERY] = "Battery",
	[LICHEN_UX_STRING_GPS] = "GPS",
	[LICHEN_UX_STRING_MESSAGE_WAITING] = "Message waiting",
};

const char *lichen_ux_string(enum lichen_ux_string_id id)
{
	return id >= 0 && id < LICHEN_UX_STRING_COUNT ? strings[id] : NULL;
}
