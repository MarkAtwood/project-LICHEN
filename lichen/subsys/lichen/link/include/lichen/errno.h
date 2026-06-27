/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/errno.h
 * @brief Portable error code definitions for LICHEN
 *
 * Provides standard POSIX error codes for non-Zephyr builds. On Zephyr,
 * defers to <errno.h> for compatibility with the kernel.
 *
 * Error codes are divided into two categories:
 *
 * **Standard POSIX codes** (values from Linux errno.h):
 *   - EINVAL (22): Invalid argument
 *   - ENOMEM (12): Out of memory / buffer too small
 *   - EMSGSIZE (90): Message too long
 *   - EALREADY (114): Operation already in progress / duplicate
 *   - EOVERFLOW (75): Value too large (nonce space exhausted)
 *
 * **LICHEN-specific codes** (project-defined, not in POSIX):
 *   - EAUTH (80): Authentication/signature verification failed
 *     Note: 80 is chosen to avoid collision with standard codes (highest
 *     standard code is ~130). Some BSDs define EAUTH at 80, which is
 *     why we use the same value for portability with BSD systems.
 */

#ifndef LICHEN_ERRNO_H_
#define LICHEN_ERRNO_H_

#ifdef __ZEPHYR__
/*
 * Zephyr provides its own errno.h with standard codes.
 * We only need to define LICHEN-specific codes here.
 */
#include <errno.h>
#else
/*
 * Non-Zephyr builds: define standard POSIX error codes.
 * Values match Linux errno.h for consistency.
 */

/** Invalid argument */
#ifndef EINVAL
#define EINVAL 22
#endif

/** Out of memory / buffer too small */
#ifndef ENOMEM
#define ENOMEM 12
#endif

/** Message too long (frame exceeds maximum size) */
#ifndef EMSGSIZE
#define EMSGSIZE 90
#endif

/** Operation already in progress (replay detected) */
#ifndef EALREADY
#define EALREADY 114
#endif

/** Value too large (nonce space exhausted) */
#ifndef EOVERFLOW
#define EOVERFLOW 75
#endif

#endif /* __ZEPHYR__ */

/*
 * LICHEN-specific error codes.
 * Defined unconditionally since they are not in POSIX.
 */

/**
 * Authentication failed.
 *
 * Returned when:
 * - Schnorr-48 signature verification fails
 * - MIC verification fails
 * - No peer public key available for signature verification
 *
 * Note: Value 80 matches BSD EAUTH where defined.
 */
#ifndef EAUTH
#define EAUTH 80
#endif

#endif /* LICHEN_ERRNO_H_ */
