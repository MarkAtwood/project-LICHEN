<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Implementation Notes

## 16. Implementation Notes

### 16.1. Repository Structure

```
LICHEN/
├── docs/
│   ├── spec/                   # Protocol specification (CC-BY-4.0)
│   └── draft-lichen-*.md       # IETF-style I-Ds
│
├── rust/                       # Rust implementation (Linux, gateway, simulator)
│   ├── Cargo.toml              # Workspace root
│   ├── lichen-core/            # Core protocol logic (no_std)
│   ├── lichen-link/            # Link layer (Ed25519 signatures)
│   ├── lichen-schc/            # SCHC compression
│   ├── lichen-coap/            # CoAP + OSCORE
│   ├── lichen-senml/           # SenML encoding
│   ├── lichen-apps/            # Applications (messaging, SOS)
│   ├── lichen-node/            # Linux node binary
│   ├── lichen-gateway/         # Border router binary
│   └── lichen-sim/             # Network simulator
│
├── zephyr/                     # Zephyr implementation (embedded)
│   ├── west.yml                # West manifest
│   ├── CMakeLists.txt
│   ├── Kconfig                 # LICHEN Kconfig options
│   ├── subsys/
│   │   ├── lichen_link/        # Link layer module
│   │   ├── lichen_schc/        # SCHC module
│   │   ├── lichen_rpl/         # RPL tuning for LoRa
│   │   ├── lichen_apps/        # Applications
│   │   └── lichen_lci/         # Local Client Interface
│   ├── drivers/
│   │   └── lora/               # LoRa-specific adaptations
│   ├── boards/                 # Board-specific overlays
   │   │   ├── heltec_wifi_lora32_v3_esp32s3_procpu.overlay
   │   │   ├── rak4631_nrf52840.overlay
   │   │   ├── tbeam_supreme.overlay (BLOCKED: no canonical board)
   │   │   └── nucleo_wl55jc.overlay

│   └── samples/
│       ├── basic_node/         # Minimal node example
│       ├── sensor_node/        # Sensor + position beacon
│       └── border_router/      # 6LBR example
│
├── riot/                       # RIOT fallback (STM32WL if Zephyr too big)
│   └── ...
│
├── test/
│   ├── vectors/                # Shared test vectors (JSON)
│   ├── interop/                # Cross-implementation tests
│   └── hardware/               # Hardware-in-loop tests
│
├── tools/
│   ├── lichen-craft/           # Packet builder/parser CLI (Rust)
│   ├── wireshark-dissector/    # Wireshark Lua plugin
│   └── lichen-keygen/          # Key generation tool (Rust)
│
└── apps/
    ├── lichen-cli/             # Command-line client (Rust)
    ├── lichen-tui/             # Terminal UI (Rust)
    └── lichen-web/             # Web dashboard (border router)
```

### 16.2. Hardware Targets

#### Recommended First Device

**Muzi Works R1 Neo (`r1_neo_nrf52840`)** -- turnkey nRF52840 + SX1262 in a ready-to-use enclosure. Battery, antenna, USB-C. Comfortable memory (256KB RAM, 1MB flash). Many Meshtastic users already have one. Reflash and go.

This recommendation is scoped to the R1 Neo board target. Original/non-Neo R1
display variants and any LR1121 radio variants are not implied by the MVP and
require separate board files, driver work, and validation evidence before they
can be advertised as supported.

#### Meshtastic-Compatible (Primary)

Reflash existing Meshtastic hardware with LICHEN firmware -- same radios, different stack.

| Family | Examples | MCU | Radio |
|--------|----------|-----|-------|
| ESP32 + SX127x | TTGO T-Beam v1, Heltec LoRa 32 V2 | ESP32 | SX1276/78 |
| ESP32-S3 + SX126x | Heltec LoRa 32 V3, T-Beam Supreme | ESP32-S3 | SX1262 |
| nRF52840 + SX126x | RAK4631, LilyGo T-Echo | nRF52840 | SX1262 |
| RP2040 + SX126x | RAK11310 | RP2040 | SX1262 |
| STM32WL | RAK3172, Seeed Wio-E5 | STM32WL55 | Integrated |

#### Open Hardware Radios (Future)

*Tracking: `bd show python-wdr`*

| Project | Hardware | Notes |
|---------|----------|-------|
| [kv4p HT](https://www.kv4p.com/) | ESP32 + SA818 VHF/UHF | ~$50, Android app, has APRS modem |
| [OpenHT](https://github.com/M17-Project/OpenHT-hw) | AT86RF215 SDR + FPGA | True SDR, M17 project |
| [Module17](https://m17project.org/module17/) | STM32 M17 modem | OSHWA certified, plugs into FM radio |

Integration: Native LICHEN (if LoRa added), gateway to mesh, or LICHEN-over-FM.

#### Open Firmware Radios (Gateway Candidates)

*Tracking: `bd show python-wdr`*

| Radio | Firmware | Notes |
|-------|----------|-------|
| TYT MD-380/UV380 | [OpenRTX](https://openrtx.org/) | DMR handheld, M17 support |
| Radioddity GD-77 | OpenRTX | Popular, well documented |
| QuanSheng UV-K5 | [egzumer](https://github.com/egzumer/uv-k5-firmware-custom) | ~$25, huge community |
| Baofeng DM-1801 | OpenGD77 | Budget option |

Integration: Bridge APRS/packet ↔ LICHEN mesh via border router.

#### Border Router Hardware

*Tracking: `bd show python-dqc`*

Border routers benefit from good antennas and elevated placement -- more direct reach = fewer hops to internet.

| Platform | Config | Cost | Notes |
|----------|--------|------|-------|
| Raspberry Pi 4/5 | + USB puck | ~$80 | Development |
| Pi Zero 2W | + SX1262 HAT | ~$40 | Low power deployment |
| GL.iNet routers | + USB puck | ~$70+ | OpenWRT, easy setup |
| RAK7391 WisGate | CM4 + LoRa + cell | ~$200 | Integrated solution |

Antenna matters more than compute:

| Level | Antenna | Placement | Range |
|-------|---------|-----------|-------|
| Basic | Rubber duck | Indoor | 1-2 km |
| Better | 5dBi fiberglass | Window | 5-10 km |
| Good | 8dBi collinear | Rooftop | 15-25 km |
| Excellent | Yagi/sector | Tower | 30+ km LOS |

**Memory budgets:**

| Platform | RAM | Flash | Constraint Level |
|----------|-----|-------|------------------|
| ESP32/ESP32-S3 | 320KB+ | 4MB+ | Comfortable |
| nRF52840 | 256KB | 1MB | Comfortable |
| RP2040 | 264KB | 2MB | Comfortable |
| STM32WL | 64KB | 256KB | **Constrained - risk** |

### 16.3. Software Architecture

**Tiered Implementation Strategy:**

| Platform | Stack | Tracking | Notes |
|----------|-------|----------|-------|
| Linux/Pi | Rust | `bd show python-ypk` | Gateway, simulator, border router |
| ESP32, nRF52840, RP2040 | Rust (Embassy) | `bd show python-ypk` | Alternative to Zephyr |
| ESP32, nRF52840, RP2040 | Zephyr RTOS | `bd show python-oae` | Uses Zephyr IPv6 stack |
| STM32WL | Zephyr or RIOT | `bd show python-oae` | RIOT fallback if Zephyr too big |

Both Rust and Zephyr are on the roadmap. Whichever gets contributors first wins, or they coexist for different use cases.

**Zephyr Stack Usage:**

| LICHEN Component | Zephyr Subsystem | Notes |
|------------------|------------------|-------|
| IPv6 | `CONFIG_NET_IPV6` | Native |
| Adaptation | Custom SCHC | Replaces 6LoWPAN compression and fragmentation |
| UDP | `CONFIG_NET_UDP` | Native |
| CoAP | `CONFIG_COAP` | Native library |
| OSCORE | Custom or port | May need to implement |
| BLE (LCI) | `CONFIG_BT` | NimBLE or Zephyr BLE |
| LoRa radio | `CONFIG_LORA` | SX126x/SX127x drivers exist |
| Crypto | `CONFIG_MBEDTLS` or TinyCrypt | Ed25519 may need monocypher |

**What we build on top of Zephyr:**
- SCHC compression (custom, ~10KB flash)
- RPL tuning for LoRa timing
- Ed25519 truncated signatures
- LICHEN link layer framing
- Application layer (messaging, SOS, etc.)
- Local Client Interface

### 16.4. STM32WL Memory Budget

```
FLASH (256 KB available):
┌────────────────────────────────────┬────────┐
│ Component                          │ Est.   │
├────────────────────────────────────┼────────┤
│ Zephyr kernel + HAL                │ ~40 KB │
│ IPv6 network stack                 │ ~20 KB │
│ RPL                                │ ~15 KB │
│ CoAP                               │ ~15 KB │
│ OSCORE/DTLS                        │ ~20 KB │
│ SCHC                               │ ~10 KB │
│ Ed25519 (monocypher)               │ ~10 KB │
│ LoRa driver                        │ ~10 KB │
│ BLE (minimal)                      │ ~30 KB │
│ LICHEN application                 │ ~40 KB │
├────────────────────────────────────┼────────┤
│ TOTAL                              │ ~210KB │
│ Margin                             │ ~36 KB │
└────────────────────────────────────┴────────┘

RAM (64 KB available):
┌────────────────────────────────────┬────────┐
│ Component                          │ Est.   │
├────────────────────────────────────┼────────┤
│ Zephyr kernel                      │ ~4 KB  │
│ Network buffers (tuned down)       │ ~6 KB  │
│ IPv6 + neighbor cache              │ ~4 KB  │
│ RPL routing state                  │ ~3 KB  │
│ CoAP contexts                      │ ~3 KB  │
│ SCHC contexts                      │ ~2 KB  │
│ Key store (limited peers)          │ ~3 KB  │
│ Application state                  │ ~8 KB  │
│ Thread stacks (2-3 threads)        │ ~6 KB  │
│ BLE buffers                        │ ~4 KB  │
├────────────────────────────────────┼────────┤
│ TOTAL                              │ ~43 KB │
│ Margin                             │ ~21 KB │
└────────────────────────────────────┴────────┘
```

**Constraints on STM32WL:**
- Aggressive Kconfig tuning required
- Reduced network buffer count
- Limited routing table size
- May disable store-and-forward

**RIOT Fallback:** If Zephyr doesn't fit, use RIOT OS (~10KB RAM for full IPv6/6LoWPAN/RPL).

### 16.5. Dependencies

**Zephyr RTOS Modules:**

| Component | Zephyr Module | Notes |
|-----------|---------------|-------|
| Kernel | `CONFIG_KERNEL` | Threads, scheduling |
| IPv6 | `CONFIG_NET_IPV6` | Native stack |
| UDP | `CONFIG_NET_UDP` | Native |
| CoAP | `CONFIG_COAP` | Zephyr CoAP library |
| LoRa | `CONFIG_LORA` | SX126x, SX127x drivers |
| BLE | `CONFIG_BT` | For Local Client Interface |
| Crypto | `CONFIG_MBEDTLS` | AES, hashing |
| Shell | `CONFIG_SHELL` | Debug/CLI (optional) |

**Rust Crates (GPL-3.0 compatible):**

| Crate | Use | License |
|-------|-----|---------|
| ed25519-dalek | Signatures | BSD-3 |
| aes-gcm | OSCORE encryption | MIT/Apache-2.0 |
| heapless | no_std collections | MIT/Apache-2.0 |
| coap-lite | CoAP parsing | MIT |
| smoltcp | IP stack (Linux node) | 0BSD |

**C Libraries (for Zephyr modules):**

| Library | Use | License |
|---------|-----|---------|
| monocypher | Ed25519, AES | Public domain |
| libschc | SCHC reference | MIT |

**RIOT OS (STM32WL fallback):**

| Component | RIOT Module | Notes |
|-----------|-------------|-------|
| IPv6/6LoWPAN | GNRC | Proven ~10KB RAM |
| RPL | GNRC RPL | Lightweight |
| CoAP | gcoap | Efficient |
| LoRa | sx126x/sx127x | Drivers available |

### 16.6. IETF-Style Documents

| Document | Content |
|----------|---------|
| draft-lichen-link | Link layer, LLSec, Ed25519 |
| draft-lichen-schc | SCHC profile for LICHEN |
| draft-lichen-addr | IPv6 addressing (link-local + 02xx Yggdrasil only) |
| draft-lichen-rpl | RPL configuration, MRHOF |
| draft-lichen-security | TOFU, DANE, OSCORE profile |
| draft-lichen-lci | Local Client Interface |
| draft-lichen-senml | SenML sensor profiles |
| draft-lichen-apps | Application protocols |
| draft-lichen-border | Border router behavior |

### 16.7. DAO Origin Persistence

DAO TX and RX persistence intentionally store different records:

- TX stores the public-key identity, last reserved Origin Sequence, and complete
  last signed DAO bytes in a crash-safe record. On reboot the API exposes those
  exact bytes for retransmission; it does not reconstruct or re-sign them.
- RX stores only the public key, accepted high-water sequence, and digest of the
  complete signed DAO. It does not persist the complete received DAO or route
  table.

For a fresh receive, persist the RX floor before exposing the route or returning
success. Then apply the fully validated route proposal atomically in memory. A
crash between those operations leaves the floor durable and route state absent.
An equal-sequence/equal-digest retransmission does not rewrite persistence; it
may repeat semantic parsing and exact self-Target validation to idempotently
reconstruct the missing route. Implementations MUST snapshot the complete route, replay-floor,
and storage state around rejected DAOs to test that no partial mutation occurs.

### 16.8. Structured Logging Convention

All implementations MUST emit diagnostic log lines in **logfmt** format: space-separated
`key=value` pairs, with string values containing spaces quoted. This applies to all
log output on the packet processing path (link through application layer).

```
ts=1725811200.123 level=debug layer=link pkt_id=47 event=rx_frame sender_iid=a3b2c1d4 rssi=-87 len=42
ts=1725811200.124 level=debug layer=schc pkt_id=47 event=decompress rule_id=3 compressed=42 decompressed=89
ts=1725811200.125 level=debug layer=routing pkt_id=47 event=forward next_hop=fe80::1 reason=preferred_parent
```

Implementations MAY additionally emit JSON Lines (JSONL) to structured sinks (files, CI
backends) for richer nesting, but logfmt is the required baseline that all tooling —
including AI test watchers — can parse without configuration.

#### 16.8.1. Standard Field Names

| Field | Type | Description |
|-------|------|-------------|
| `ts` | float | Unix epoch in seconds with millisecond precision |
| `level` | string | `debug`, `info`, `warn`, `error` |
| `layer` | string | `link`, `schc`, `ipv6`, `routing`, `coap`, `oscore`, `app` |
| `pkt_id` | uint | Monotonic per-node packet correlation ID (assigned at link RX entry) |
| `event` | string | Verb phrase: `rx_frame`, `tx_drain`, `decompress`, `forward`, `drop`, `reject` |
| `sender_iid` | hex | IID of sender (when known) |
| `peer_iid` | hex | IID of peer (when relevant, e.g. CoAP exchange partner) |
| `errno` | int | Numeric error code (on error paths) |
| `reason` | string | Machine-readable cause (on drops/rejects, e.g. `replay`, `queue_full`) |
| `len` | uint | Payload length in bytes |
| `rssi` | int | Received signal strength in dBm (link layer) |

Implementations MUST include `ts`, `level`, `layer`, and `event` on every log line.
`pkt_id` MUST be present on all lines in the packet processing path. Other fields are
included when contextually relevant.

#### 16.8.2. Per-Implementation Notes

- **C/Zephyr:** Emit logfmt fields via existing `LOG_DBG`/`LOG_INF`/`LOG_WRN`/`LOG_ERR`
  macros with format strings. No heap allocation required. Gate verbose pipeline
  logging behind `CONFIG_LICHEN_DIAG_VERBOSE`. For native_sim CI, Zephyr's dictionary
  logging backend (`CONFIG_LOG_BACKEND_DICT`) MAY be post-processed to JSONL.
- **Rust:** Use the `tracing` crate with structured spans (`info_span!`) on the packet
  path. `tracing-subscriber` emits JSONL or logfmt depending on configuration.
  Embedded targets (`lichen-node` on `no_std`) use `defmt` with logfmt conventions
  in format strings.
- **Python:** Use `structlog` with bound loggers carrying `pkt_id` and `layer` context.
  Emit JSONL to files/structured sinks; logfmt to console for human readability.

#### 16.8.3. Correlation ID Assignment

Each node maintains a monotonic `u32` counter (wrapping). A new `pkt_id` is assigned at
the link layer RX entry point for received frames and at the TX queue push for locally
originated packets. The `pkt_id` is local to the node and is NOT transmitted on the wire —
it exists solely for log correlation. Forwarded packets receive a new `pkt_id` at the
forwarding node; the relationship between the inbound and outbound IDs SHOULD be logged
as `event=forward in_pkt_id=<rx> pkt_id=<tx>`.

---

[← Previous: Packets and Timing](09-packets-timing.md) | [Index](README.md) | [Next: Local Client Interface →](11-lci.md)
