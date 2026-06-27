#!/usr/bin/env python3
"""
Minimal SMP client — image upload + reset over any pyserial-compatible port.

Supports RFC2217 URLs directly (no PTY bridge needed):
  ./smp-flash.py rfc2217://localhost:4005 firmware.signed.bin
  ./smp-flash.py /dev/ttyACM1            firmware.signed.bin
"""

import sys
import os
import struct
import base64
import hashlib
import time
import argparse

# cbor2 may live in the user site
sys.path.insert(0, "/home/frosty/.local/lib/python3.10/site-packages")
import cbor2
import serial

# ── SMP constants ────────────────────────────────────────────────────────────

SMP_SOF       = bytes([0x06, 0x09])
SMP_OP_READ   = 0
SMP_OP_WRITE  = 2

SMP_GRP_OS    = 0
SMP_OS_RESET  = 5

SMP_GRP_IMG   = 1
SMP_IMG_UPLOAD = 1

CHUNK_SIZE    = 256   # payload bytes per SMP frame
BAUD          = 115200
TIMEOUT_S     = 10.0  # per-chunk response timeout

# ── Serial framing (mcumgr UART protocol) ────────────────────────────────────

def _crc16(data: bytes) -> int:
    """CRC-CCITT, poly=0x1021, init=0x0000."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if (crc & 0x8000) else (crc << 1)
        crc &= 0xFFFF
    return crc

def _encode_frame(op: int, group: int, seq: int, cmd_id: int, payload: bytes) -> bytes:
    """Build one mcumgr serial frame: SOF + base64(pkt_len | SMP_hdr | payload | crc) + \n"""
    smp_hdr = struct.pack(">BBHHBB", op, 0, len(payload), group, seq & 0xFF, cmd_id)
    raw = smp_hdr + payload
    crc = _crc16(raw)
    pkt_len = len(raw) + 2  # includes CRC
    inner = struct.pack(">H", pkt_len) + raw + struct.pack(">H", crc)
    return SMP_SOF + base64.b64encode(inner) + b'\n'

def _read_frame(ser: serial.Serial) -> bytes:
    """Block until one complete SMP frame is received; return raw SMP bytes (hdr+payload)."""
    deadline = time.monotonic() + TIMEOUT_S
    buf = bytearray()

    # Read bytes until \n (mcumgr serial frame terminator)
    while time.monotonic() < deadline:
        b = ser.read(1)
        if not b:
            continue
        if b == b'\n':
            break
        buf += b
    else:
        raise TimeoutError("Timeout waiting for SMP response")

    if len(buf) < 2 or bytes(buf[:2]) != SMP_SOF:
        raise ValueError(f"Bad SOF: {buf[:2].hex() if len(buf) >= 2 else 'short'}")

    # Decode base64 portion (after 2-byte SOF)
    try:
        decoded = base64.b64decode(buf[2:])
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

    if len(decoded) < 4:
        raise ValueError(f"Decoded frame too short: {len(decoded)} bytes")

    # First 2 bytes = pkt_len (SMP data + CRC); rest = SMP data + CRC
    pkt_len = struct.unpack(">H", decoded[:2])[0]
    smp_and_crc = decoded[2:]

    if len(smp_and_crc) != pkt_len:
        raise ValueError(f"Length mismatch: got {len(smp_and_crc)}, want {pkt_len}")

    # Verify CRC: crc16(SMP_data || CRC) must be 0 (self-verifying)
    if _crc16(smp_and_crc) != 0:
        raise ValueError(f"CRC verify failed")

    # Return SMP header + payload (strip trailing 2-byte CRC)
    return bytes(smp_and_crc[:-2])

def _parse_response(raw: bytes) -> dict:
    # 8-byte SMP header, then CBOR payload
    if len(raw) < 8:
        raise ValueError(f"Response too short: {len(raw)} bytes")
    payload = raw[8:]
    return cbor2.loads(payload) if payload else {}

# ── High-level operations ────────────────────────────────────────────────────

def upload_image(ser: serial.Serial, image: bytes) -> None:
    total = len(image)
    sha256 = hashlib.sha256(image).digest()
    offset = 0
    seq = 0

    print(f"Uploading {total} bytes...")

    while offset < total:
        chunk = image[offset: offset + CHUNK_SIZE]
        cbor_map = {"off": offset, "data": chunk}
        if offset == 0:
            cbor_map["len"] = total
            cbor_map["sha"] = sha256

        frame = _encode_frame(SMP_OP_WRITE, SMP_GRP_IMG, seq, SMP_IMG_UPLOAD,
                               cbor2.dumps(cbor_map))
        ser.write(frame)

        raw = _read_frame(ser)
        rsp = _parse_response(raw)

        rc = rsp.get("rc", 0)
        if rc != 0:
            raise RuntimeError(f"Upload error at offset {offset}: rc={rc}")

        next_off = rsp.get("off", offset + len(chunk))
        pct = next_off * 100 // total
        print(f"\r  {pct:3d}%  {next_off}/{total} B", end="", flush=True)
        offset = next_off
        seq += 1

    print()

def reset_device(ser: serial.Serial) -> None:
    frame = _encode_frame(SMP_OP_WRITE, SMP_GRP_OS, 0, SMP_OS_RESET,
                           cbor2.dumps({}))
    ser.write(frame)
    try:
        raw = _read_frame(ser)
        rsp = _parse_response(raw)
        rc = rsp.get("rc", 0)
        if rc != 0:
            print(f"Warning: reset rc={rc}", file=sys.stderr)
    except TimeoutError:
        pass  # device rebooted before responding — that's fine

# ── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("port",
        help="Serial port or RFC2217 URL, e.g. rfc2217://localhost:4005")
    parser.add_argument("firmware",
        help="Signed firmware binary (.signed.bin)")
    parser.add_argument("--baud", type=int, default=BAUD)
    parser.add_argument("--no-reset", action="store_true",
        help="Skip reset after upload")
    args = parser.parse_args()

    if not os.path.isfile(args.firmware):
        sys.exit(f"ERROR: firmware not found: {args.firmware}")

    with open(args.firmware, "rb") as f:
        image = f.read()

    print(f"Connecting to {args.port} ...")
    ser = serial.serial_for_url(args.port, baudrate=args.baud, timeout=1)
    ser.reset_input_buffer()

    try:
        upload_image(ser, image)
        if not args.no_reset:
            print("Resetting device...")
            reset_device(ser)
            print("Done.")
    finally:
        ser.close()

if __name__ == "__main__":
    main()
