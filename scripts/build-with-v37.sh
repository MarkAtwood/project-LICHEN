#!/usr/bin/env bash
# Build a LICHEN CMake test/app against the local Zephyr v3.7.0 reference
# clone (~/GIT/zephyr-v3.7.0) instead of the v4.1.0 workspace (bead oyhg).
#
# Usage: build-with-v37.sh <source-dir> <build-dir> [-- extra cmake args...]
#
# Verified working recipe (ping_l2 configure clean, 0 undefined Kconfig
# symbols):
#   ZEPHYR_BASE   = ~/GIT/zephyr-v3.7.0   (plain v3.7.0 clone, no west needed)
#   ZEPHYR_MODULES = $LICHEN_ROOT/lichen        (LICHEN module)
#                  + ~/Developer/lichen-workspace/modules/lib/zcbor
#                  + ~/Developer/lichen-workspace/modules/crypto/tinycrypt
#   Zephyr-sdk_DIR = ~/Developer/zephyr-sdk/zephyr-sdk-0.16.8/cmake
#     (the SDK's own Zephyr-sdkConfig.cmake is NOT in the CMake package
#      registry on this host; pass -DZephyr-sdk_DIR explicitly)
#   Python        = ~/Developer/lichen-venv/bin/python3
#
# Known residual build breaks at v3.7.0 (documented, bead oyhg close):
#   - lichen/coap/coap_client.c uses `lock`; v3.7.0 names it `send_mutex`
#     (v4.1.0 API drift — needs a compat macro like LORA_RECV_ASYNC)
#   - lichen/coap/sos_alert.c needs <math.h> (NAN/INFINITY/ldexp)
set -euo pipefail
SRC="$1"; shift
BLD="$1"; shift
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
V37="$HOME/GIT/zephyr-v3.7.0"
SDK="$HOME/Developer/zephyr-sdk/zephyr-sdk-0.16.8"
WS_MODULES="$HOME/Developer/lichen-workspace/modules"
PY="$HOME/Developer/lichen-venv/bin/python3"

export ZEPHYR_BASE="$V37"
export ZEPHYR_SDK_INSTALL_DIR="$SDK"

EXTRA_MODULES=("$ROOT/lichen" "$HOME/Developer/lichen-workspace/modules/lib/zcbor" "$HOME/Developer/lichen-workspace/modules/crypto/tinycrypt")
MODULE_ARG=$(IFS=';'; echo "${EXTRA_MODULES[*]}")

EXTRA=()
if [ $# -gt 0 ]; then
  [ "$1" = "--" ] && shift
  EXTRA=("$@")
fi

cmake -S "$SRC" -B "$BLD" \
  -G Ninja \
  -DBOARD=native_sim/native/64 \
  -DZEPHYR_MODULES="$MODULE_ARG" \
  -DZephyr-sdk_DIR="$SDK/cmake" \
  -DPython3_EXECUTABLE="$PY" \
  "${EXTRA[@]}"
cmake --build "$BLD" -j"${JOBS:-4}"
