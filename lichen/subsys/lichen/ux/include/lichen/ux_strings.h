/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

#ifndef LICHEN_UX_STRINGS_H_
#define LICHEN_UX_STRINGS_H_

/**
 * @file ux_strings.h
 * @brief Spec 19 §13 English string table and localization seam.
 */

#ifdef __cplusplus
extern "C" {
#endif

enum lichen_ux_string_id {
	LICHEN_UX_STRING_BOOT = 0,
	LICHEN_UX_STRING_STATUS,
	LICHEN_UX_STRING_POSITION,
	LICHEN_UX_STRING_LAST_MESSAGE,
	LICHEN_UX_STRING_SCREENSAVER,
	LICHEN_UX_STRING_BATTERY,
	LICHEN_UX_STRING_GPS,
	LICHEN_UX_STRING_MESSAGE_WAITING,
	LICHEN_UX_STRING_COUNT,
};

/** Return the v0.1 English text for @p id, or NULL for an invalid ID. */
const char *lichen_ux_string(enum lichen_ux_string_id id);

#ifdef __cplusplus
}
#endif

#endif /* LICHEN_UX_STRINGS_H_ */
