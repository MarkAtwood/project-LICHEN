/* SPDX-License-Identifier: GPL-3.0-or-later */
/* SPDX-FileCopyrightText: The contributors to the LICHEN project */

/**
 * @file lichen/rpl.h
 * @brief LICHEN RPL routing - unified header
 *
 * RPL (RFC 6550) implementation for LICHEN mesh networking.
 * Implements:
 * - Trickle timer (RFC 6206) for DIO scheduling
 * - DODAG state machine with MRHOF parent selection
 * - DIO/DAO message codecs
 * - Non-storing mode routing table and DAO manager
 *
 * This is a caller-driven design with no internal threading.
 * The caller is responsible for:
 * - Driving the Trickle timer and sending DIOs
 * - Processing received DIOs/DAOs
 * - Managing timers and I/O
 */

#ifndef LICHEN_RPL_H_
#define LICHEN_RPL_H_

#include <lichen/rpl_trickle.h>
#include <lichen/rpl_messages.h>
#include <lichen/rpl_dodag.h>
#include <lichen/rpl_routing.h>

#endif /* LICHEN_RPL_H_ */
