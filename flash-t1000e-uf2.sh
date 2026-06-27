#!/usr/bin/env bash
# Flash MCUboot + LICHEN puck firmware to T1000-E via serial DFU.
#
# The T1000-E (Adafruit nRF52 UF2 bootloader v0.9.1, Seeed build) has
# APP_START_ADDR = 0x1000. Flash layout (no SoftDevice; Zephyr BLE stack):
#
#   0x0000–0x0FFF  Nordic MBR (4 KB)
#   0x1000–0xCFFF  MCUboot boot_partition (48 KB)
#   0xD000–0x65FFF slot0_partition (356 KB)
#   0x66000–0xBEFFF slot1_partition (356 KB) — SMP OTA target
#   0xBF000–0xC2FFF storage_partition (16 KB)
#
# UF2 drag-and-drop silently rejects writes above the 0xFF000 image_size
# boundary after the first serial DFU. Serial DFU is the only reliable path.
#
# After first flash, use SMP OTA for app updates:
#   python3 smp-flash.py rfc2217://localhost:4005 build_t1000e_puck/zephyr/zephyr.slot0.signed.bin
#
# Usage:
#   ./flash-t1000e-uf2.sh [--build]   # --build forces MCUboot rebuild
#   Put T1000-E in UF2 bootloader mode (double-tap reset) before running.

set -euo pipefail
cd "$(dirname "$0")"

APP_BUILD="build_t1000e_puck"
MCUBOOT_BUILD="build_mcuboot_t1000e"
IMGTOOL="bootloader/mcuboot/scripts/imgtool.py"
HEADER_SIZE="0x200"
SLOT_SIZE="0x59000"    # slot0_partition size from t1000_e DTS (356 KB)
SLOT0_ADDR="0xD000"    # slot0_partition base (boot_partition@1000 + 0xC000)
COMBINED_BIN="/tmp/t1000e_combined.bin"
COMBINED_DFU="/tmp/t1000e_combined_dfu.zip"
PORT="${T1000E_PORT:-/dev/ttyACM0}"

export PYTHONPATH="/home/frosty/.local/lib/python3.10/site-packages:${PYTHONPATH:-}"
export ZEPHYR_SDK_INSTALL_DIR=/home/frosty/.local/share/safe-agent/b9243483d7697056/zephyr-sdk-0.16.8

# -----------------------------------------------------------------------
# 1. Build MCUboot (once; skip unless --build)
# -----------------------------------------------------------------------
if [[ "${1:-}" == "--build" || ! -f "$MCUBOOT_BUILD/zephyr/zephyr.bin" ]]; then
    echo "==> Building MCUboot for t1000_e/nrf52840..."
    west build -d "$MCUBOOT_BUILD" -b "t1000_e/nrf52840" \
        bootloader/mcuboot/boot/zephyr -- \
        -DCONFIG_BOOT_SIGNATURE_TYPE_NONE=y \
        -DCONFIG_BOOT_SWAP_USING_MOVE=y \
        -DCONFIG_BOOT_MAX_IMG_SECTORS=256 \
        -DCONFIG_USB_DEVICE_STACK=n \
        -DCONFIG_USB_CDC_ACM=n \
        -DCONFIG_UART_CONSOLE=n \
        -DCONFIG_CONSOLE=n \
        -DCONFIG_LOG=n \
        -DCONFIG_BOOT_WATCHDOG_FEED=n
fi

# -----------------------------------------------------------------------
# 2. Sign LICHEN puck firmware
# -----------------------------------------------------------------------
if [[ ! -f "$APP_BUILD/zephyr/zephyr.bin" ]]; then
    echo "ERROR: $APP_BUILD not built — run: west build -d $APP_BUILD" >&2
    exit 1
fi

echo "==> Signing firmware..."
TMP_CONTENT=$(mktemp /tmp/lichen_content_XXXXXX.bin)
dd if="$APP_BUILD/zephyr/zephyr.bin" bs=512 skip=1 of="$TMP_CONTENT" 2>/dev/null
python3 "$IMGTOOL" sign \
    --header-size "$HEADER_SIZE" \
    --align 4 \
    --version 0.1.0+0 \
    --slot-size "$SLOT_SIZE" \
    --pad-header \
    "$TMP_CONTENT" \
    "$APP_BUILD/zephyr/zephyr.slot0.signed.bin"
rm -f "$TMP_CONTENT"

# -----------------------------------------------------------------------
# 3. Build combined binary: MCUboot at 0x1000 + slot0 at 0xD000
#
# MCUboot is compiled for boot_partition@1000 (APP_START_ADDR), so its
# Reset vector lands within 0x1000-0xCFFF. No stub needed.
# -----------------------------------------------------------------------
echo "==> Building combined DFU binary..."
python3 - <<'PYEOF'
import struct, sys

MCUBOOT_ADDR = 0x1000   # APP_START_ADDR = boot_partition base
SLOT0_ADDR   = 0xD000   # slot0_partition base

mcuboot = open("build_mcuboot_t1000e/zephyr/zephyr.bin", "rb").read()
slot0   = open("build_t1000e_puck/zephyr/zephyr.slot0.signed.bin", "rb").read()

reset = struct.unpack_from("<I", mcuboot, 4)[0]
assert MCUBOOT_ADDR <= reset < SLOT0_ADDR, \
    f"MCUboot Reset=0x{reset:08X} not in boot_partition — wrong build?"

pad = b"\xff" * (SLOT0_ADDR - MCUBOOT_ADDR - len(mcuboot))
combined = mcuboot + pad + slot0

with open("/tmp/t1000e_combined.bin", "wb") as f:
    f.write(combined)
print(f"  mcuboot@0x{MCUBOOT_ADDR:05X} ({len(mcuboot)}B)  slot0@0x{SLOT0_ADDR:05X} ({len(slot0)}B)  total={len(combined)}B")
PYEOF

# -----------------------------------------------------------------------
# 4. Package and flash via serial DFU
# -----------------------------------------------------------------------
echo "==> Creating DFU package..."
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
echo "  PRE_KERNEL_1: 3 slow blinks (~1s each) on P0.24"
echo "  APPLICATION:  1 beep (USB init) + 2 beeps (LoRa/GNSS OK)"
echo "  USB CDC: 'LICHEN Node' / 'LICHEN Project' on /dev/ttyACM0 + ttyACM1"
