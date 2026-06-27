#!/usr/bin/env bash
# Initial flash of MCUboot + LICHEN puck firmware to the Seeed T1000-E.
#
# The T1000-E uses the Adafruit nRF52 UF2 bootloader v0.9.1 (Seeed build)
# with APP_START_ADDR=0x1000 and no SoftDevice. Flash layout:
#
#   0x0000–0x0FFF   Nordic MBR (4 KB)
#   0x1000–0xCFFF   MCUboot boot_partition (48 KB)
#   0xD000–0x65FFF  slot0_partition — active app (356 KB)
#   0x66000–0xBEFFF slot1_partition — SMP OTA staging (356 KB)
#   0xBF000–0xC2FFF storage_partition (16 KB)
#
# This script runs a serial DFU with a combined MCUboot+slot0 binary.
# UF2 drag-and-drop cannot be used for initial flash: after the first
# serial DFU sets 0xFF000 image_size to 16 KB, the bootloader silently
# rejects UF2 writes above that boundary.
#
# After first flash, use SMP OTA for app updates (no reset required):
#   python3 smp-flash.py rfc2217://localhost:4005 \
#       build_t1000e_puck/zephyr/zephyr.slot0.signed.bin
#
# Usage:
#   ./flash-t1000e.sh              # build if needed, then flash
#   ./flash-t1000e.sh --rebuild    # force rebuild before flash
#   Put T1000-E in UF2 bootloader mode (double-tap reset) before running.

set -euo pipefail
cd "$(dirname "$0")"

APP_BUILD="build_t1000e_puck"
MCUBOOT_BUILD="build_mcuboot_t1000e"
COMBINED_BIN="/tmp/t1000e_combined.bin"
COMBINED_DFU="/tmp/t1000e_combined_dfu.zip"
PORT="${T1000E_PORT:-/dev/ttyACM0}"

export PYTHONPATH="/home/frosty/.local/lib/python3.10/site-packages:${PYTHONPATH:-}"
export ZEPHYR_SDK_INSTALL_DIR=/home/frosty/.local/share/safe-agent/b9243483d7697056/zephyr-sdk-0.16.8

# -----------------------------------------------------------------------
# 1. Build (delegate to build-t1000e.sh)
# -----------------------------------------------------------------------
BUILD_ARGS=()
if [[ "${1:-}" == "--rebuild" ]]; then
    BUILD_ARGS=(--mcuboot)
fi
./build-t1000e.sh "${BUILD_ARGS[@]}"

# -----------------------------------------------------------------------
# 2. Combine MCUboot + signed slot0 into a single DFU binary
#
# MCUboot is compiled for boot_partition@0x1000, so its Reset vector is
# within 0x1000–0xCFFF. The bootloader validates the binary via CRC stored
# at 0xFF000, then jumps to 0x1000. MCUboot boots slot0 from 0xD000.
# -----------------------------------------------------------------------
echo "==> Building combined DFU binary..."
python3 - <<'PYEOF'
import struct

MCUBOOT_ADDR = 0x1000   # boot_partition base = APP_START_ADDR
SLOT0_ADDR   = 0xD000   # slot0_partition base

mcuboot = open("build_mcuboot_t1000e/zephyr/zephyr.bin", "rb").read()
slot0   = open("build_t1000e_puck/zephyr/zephyr.slot0.signed.bin", "rb").read()

reset = struct.unpack_from("<I", mcuboot, 4)[0]
assert MCUBOOT_ADDR <= reset < SLOT0_ADDR, \
    f"MCUboot Reset=0x{reset:08X} not in boot_partition — stale build?"

pad = b"\xff" * (SLOT0_ADDR - MCUBOOT_ADDR - len(mcuboot))
combined = mcuboot + pad + slot0

with open("/tmp/t1000e_combined.bin", "wb") as f:
    f.write(combined)
print(f"  mcuboot@0x{MCUBOOT_ADDR:05X} ({len(mcuboot)}B)  "
      f"slot0@0x{SLOT0_ADDR:05X} ({len(slot0)}B)  "
      f"total={len(combined)}B")
PYEOF

# -----------------------------------------------------------------------
# 3. Package and flash via serial DFU
# -----------------------------------------------------------------------
echo "==> Packaging DFU..."
adafruit-nrfutil dfu genpkg \
    --dev-type 0x0052 \
    --application "$COMBINED_BIN" \
    --application-version 2 \
    "$COMBINED_DFU"

echo ""
echo "==> Flashing via serial DFU on $PORT..."
echo "    (device must be in UF2 bootloader mode — double-tap reset)"
adafruit-nrfutil --verbose dfu serial \
    --package "$COMBINED_DFU" \
    -p "$PORT" \
    -b 115200 \
    --singlebank

echo ""
echo "Done. Expected boot sequence:"
echo "  PRE_KERNEL_1: 3 blinks on P0.24 (LED)"
echo "  APPLICATION:  1 beep (USB init) + 2 beeps (LoRa/GNSS OK)"
echo "  USB CDC:      'LICHEN Node' / 'LICHEN Project' on ttyACM0 + ttyACM1"
