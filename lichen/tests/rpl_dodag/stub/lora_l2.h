/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Host stub: the L2 assigned-SF push is recorded, not forwarded. */
#ifndef LORA_L2_STUB_H_
#define LORA_L2_STUB_H_
#include <stdint.h>
void lora_l2_assign_sf(uint8_t sf);
#endif
