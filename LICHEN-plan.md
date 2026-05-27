# Implementation Plan: LICHEN Protocol

**LICHEN** = **L**oRa **I**Pv6 **C**oAP **H**ybrid **E**xtended **N**etwork

**Document:** Implementation Plan
**Spec Reference:** LICHEN-spec.md
**Date:** 2026-05-26
**Status:** Draft
**License:** CC-BY-4.0 (documentation), GPL-3.0 (code)

---

## Executive Summary

This plan describes how to build the LICHEN protocol stack from the specification.

**Key characteristics:**
- **Standards-based:** 100% IETF protocols (IPv6, SCHC, RPL, CoAP, SenML, OSCORE)
- **Hardware:** Runs on existing Meshtastic-compatible devices (reflash)
- **Software:** Zephyr RTOS (embedded) + Rust (Linux/gateway/simulator)
- **Decentralized:** No PSK, no mandatory CA, TOFU baseline trust

**Why not Arduino like Meshtastic?**
- Arduino has no native IPv6, 6LoWPAN, RPL, or CoAP
- Zephyr has all of these built-in
- Consistent RTOS API across all platforms
- Better power management primitives

---

## 1. Repository Structure

```
LICHEN/
├── docs/
│   ├── LICHEN-spec.md           # Protocol specification (CC-BY-4.0)
│   ├── LICHEN-plan.md           # This file
│   └── draft-lichen-*.md        # IETF-style I-Ds
│
├── rust/                        # Rust implementation (Linux, gateway, simulator)
│   ├── Cargo.toml               # Workspace root
│   ├── lichen-core/             # Core protocol logic (no_std)
│   ├── lichen-link/             # Link layer (Ed25519 signatures)
│   ├── lichen-schc/             # SCHC compression
│   ├── lichen-coap/             # CoAP + OSCORE
│   ├── lichen-senml/            # SenML encoding
│   ├── lichen-apps/             # Applications (messaging, SOS)
│   ├── lichen-node/             # Linux node binary
│   ├── lichen-gateway/          # Border router binary
│   └── lichen-sim/              # Network simulator
│
├── zephyr/                      # Zephyr implementation (embedded)
│   ├── west.yml                 # West manifest
│   ├── CMakeLists.txt
│   ├── Kconfig                  # LICHEN Kconfig options
│   ├── subsys/
│   │   ├── lichen_link/         # Link layer module
│   │   ├── lichen_schc/         # SCHC module
│   │   ├── lichen_rpl/          # RPL tuning for LoRa
│   │   ├── lichen_apps/         # Applications
│   │   └── lichen_lci/          # Local Client Interface
│   ├── drivers/
│   │   └── lora/                # LoRa-specific adaptations
│   ├── boards/                  # Board-specific overlays
│   │   ├── heltec_lora32_v3.overlay
│   │   ├── rak4631.overlay
│   │   ├── tbeam_supreme.overlay
│   │   └── nucleo_wl55jc.overlay
│   └── samples/
│       ├── basic_node/          # Minimal node example
│       ├── sensor_node/         # Sensor + position beacon
│       └── border_router/       # 6LBR example
│
├── riot/                        # RIOT fallback (STM32WL if Zephyr too big)
│   ├── Makefile
│   └── ... (only if needed)
│
├── test/
│   ├── vectors/                 # Shared test vectors (JSON)
│   ├── interop/                 # Cross-implementation tests
│   └── hardware/                # Hardware-in-loop tests
│
├── tools/
│   ├── lichen-craft/            # Packet builder/parser CLI (Rust)
│   ├── wireshark-dissector/     # Wireshark Lua plugin
│   └── lichen-keygen/           # Key generation tool (Rust)
│
└── apps/
    ├── lichen-cli/              # Command-line client (Rust)
    ├── lichen-tui/              # Terminal UI (Rust)
    └── lichen-web/              # Web dashboard (border router)
```

---

## 2. Hardware Targets

**Primary target:** All Meshtastic-compatible hardware (reflash, same radios).

| Family | Examples | MCU | Radio |
|--------|----------|-----|-------|
| ESP32 + SX127x | TTGO T-Beam v1, Heltec LoRa 32 V2 | ESP32 | SX1276/78 |
| ESP32-S3 + SX126x | Heltec LoRa 32 V3, T-Beam Supreme | ESP32-S3 | SX1262 |
| nRF52840 + SX126x | RAK4631, LilyGo T-Echo | nRF52840 | SX1262 |
| RP2040 + SX126x | RAK11310 | RP2040 | SX1262 |
| STM32WL | RAK3172, Seeed Wio-E5 | STM32WL55 | Integrated |

**Memory budgets:**

| Platform | RAM | Flash | Constraint Level |
|----------|-----|-------|------------------|
| ESP32/ESP32-S3 | 320KB+ | 4MB+ | Comfortable |
| nRF52840 | 256KB | 1MB | Comfortable |
| RP2040 | 264KB | 2MB | Comfortable |
| STM32WL | 64KB | 256KB | **Constrained - risk** |

---

## 3. Software Architecture

### 3.1 Why Not Arduino?

Meshtastic uses Arduino + PlatformIO. This was reasonable for their goals but wrong for LICHEN:

| Feature | Arduino | Zephyr |
|---------|---------|--------|
| IPv6 | Bolt-on | **Native** |
| 6LoWPAN | No | **Native** |
| RPL | No | **Partial (usable)** |
| CoAP | No | **Native** |
| OSCORE | No | **Available** |
| Threading | Platform-dependent | **Consistent RTOS API** |
| Power management | Hidden | **First-class PM subsystem** |
| BLE | NimBLE (good) | NimBLE or Zephyr BLE |

### 3.2 Tiered Implementation Strategy

```
┌─────────────────────────────────────────────────────────────┐
│                        LICHEN Stack                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────┐    ┌─────────────────────────────┐│
│  │   Rust (no_std)     │    │         Zephyr RTOS         ││
│  │                     │    │                             ││
│  │  • Linux gateway    │    │  • ESP32/ESP32-S3           ││
│  │  • Simulator        │    │  • nRF52840                 ││
│  │  • Test harness     │    │  • RP2040                   ││
│  │  • Border router    │    │  • STM32WL (if fits)        ││
│  │    (Linux/Pi)       │    │                             ││
│  └─────────────────────┘    └─────────────────────────────┘│
│                                                             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │              Fallback: RIOT or Contiki-NG               ││
│  │                    (STM32WL only, if needed)            ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

### 3.3 Zephyr Stack Usage

Leverage existing Zephyr subsystems:

| LICHEN Component | Zephyr Subsystem | Notes |
|------------------|------------------|-------|
| IPv6 | `CONFIG_NET_IPV6` | Native |
| 6LoWPAN | `CONFIG_NET_L2_IEEE802154` | Adapt for LoRa |
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

### 3.4 STM32WL Memory Budget (Critical Path)

```
FLASH (256 KB available):
┌────────────────────────────────────┬────────┐
│ Component                          │ Est.   │
├────────────────────────────────────┼────────┤
│ Zephyr kernel + HAL                │ ~40 KB │
│ IPv6 + 6LoWPAN                     │ ~30 KB │
│ RPL                                │ ~15 KB │
│ CoAP                               │ ~15 KB │
│ OSCORE/DTLS                        │ ~20 KB │
│ SCHC                               │ ~10 KB │
│ Ed25519 (monocypher)               │ ~10 KB │
│ LoRa driver                        │ ~10 KB │
│ BLE (minimal)                      │ ~30 KB │
│ LICHEN application                 │ ~40 KB │
├────────────────────────────────────┼────────┤
│ TOTAL                              │ ~220KB │
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

**Verdict:** Tight but feasible. Requires:
- Aggressive Kconfig tuning
- Reduced network buffer count
- Limited routing table size
- May disable store-and-forward on STM32WL

### 3.5 Fallback Plan: RIOT OS for STM32WL

If Zephyr doesn't fit on STM32WL after tuning:

| Aspect | Zephyr | RIOT OS |
|--------|--------|---------|
| IPv6+6LoWPAN+RPL RAM | ~20-30 KB | **~10 KB** |
| Flash footprint | ~150+ KB | **~80 KB** |
| CoAP | Native | Native (gcoap) |
| LoRa drivers | Good | Good |
| Maturity | High | Medium |
| Vendor support | Strong | Community |

RIOT has proven ~10KB RAM for full IPv6/6LoWPAN/RPL stack. If STM32WL can't run Zephyr, we port that platform only to RIOT while keeping Zephyr for everything else.

**Decision point:** End of Phase 1, after STM32WL prototype.

---

## 4. Phase Plan

### Phase 0: Foundation + STM32WL Validation

**Goal:** Project scaffolding, tooling, CI/CD, and **early STM32WL memory validation**.

| Task | Output |
|------|--------|
| Create Rust workspace with `no_std` crates | `rust/Cargo.toml` |
| Set up Zephyr west workspace | `zephyr/west.yml` |
| **Build minimal Zephyr+IPv6+CoAP on STM32WL** | Memory report |
| **Validate STM32WL fits (<50KB RAM, <220KB flash)** | Go/no-go decision |
| Define shared constants (frequencies, sync word 0x34, ports) | Shared headers |
| Set up GitHub Actions CI | `.github/workflows/` |
| Create test vector framework | `test/vectors/` |
| Write `draft-lichen-link-01.md` | `docs/` |

**Exit Criteria:**
- `cargo build --workspace` succeeds (stubs)
- Zephyr builds for nRF52840, ESP32, STM32WL
- **STM32WL memory validated** (or fallback to RIOT decided)
- CI runs on push

**STM32WL Validation Build:**
```bash
west build -b nucleo_wl55jc samples/net/sockets/coap_client -- \
  -DCONFIG_NET_IPV6=y \
  -DCONFIG_NET_UDP=y \
  -DCONFIG_COAP=y \
  -DCONFIG_SIZE_OPTIMIZATIONS=y
west build -t ram_report
west build -t rom_report
```

If RAM > 50KB or Flash > 220KB: evaluate RIOT OS fallback.

---

### Phase 1: Physical & Link Layer

**Goal:** Transmit and receive authenticated frames over LoRa.

#### 1.1 Radio Abstraction

```rust
pub trait Radio {
    fn configure(&mut self, config: &Config) -> Result<(), Error>;
    fn transmit(&mut self, data: &[u8]) -> Result<(), Error>;
    fn receive(&mut self, buf: &mut [u8], timeout: Duration) -> Result<usize, Error>;
    fn cad(&mut self) -> Result<bool, Error>;
    fn rssi(&self) -> i16;
    fn snr(&self) -> i8;
}
```

Implementations: `sx126x`, `sx127x`, `simulated`

#### 1.2 Link Layer Frame

Per spec section 4:
- Length (1B) + LLSec (1B) + SeqNum (2B) + DstAddr (2-8B) + Payload + Signature (32B)

#### 1.3 Ed25519 Truncated Signatures

32-byte truncated Ed25519 signatures per spec section 8.3.

#### 1.4 Replay Protection

16-bit sequence number with 32-entry sliding window.

**Exit Criteria:**
- Two nodes exchange authenticated frames
- Replay attack blocked
- Test vectors for link layer

---

### Phase 2: SCHC Compression

**Goal:** RFC 8724 SCHC for IPv6/UDP/CoAP compression.

#### 2.1 Compression Rules (per spec Appendix A)

| Rule | Use Case | Compressed Size |
|------|----------|-----------------|
| 0 | Link-local IPv6 + UDP + CoAP | 4-6 bytes |
| 1 | Global IPv6 + UDP + CoAP | 12-14 bytes |
| 2 | ICMPv6 Echo | 3 bytes |
| 3 | RPL DIO | 8 bytes |
| 4 | RPL DAO | 6 bytes |

#### 2.2 Fragmentation

ACK-on-Error mode for packets exceeding L2 MTU.

**Exit Criteria:**
- All rules implemented and tested
- Fragmentation working
- Rust and C produce identical output

---

### Phase 3: IPv6 and 6LoWPAN

**Goal:** Full IPv6 with layered addressing.

#### 3.1 Address Types (per spec section 6.1)

| Type | Prefix | When Available |
|------|--------|----------------|
| Link-local | fe80::/10 | Always |
| ULA | fd00::/8 | DODAG root present |
| GUA | 2000::/3 | BR with upstream prefix |

#### 3.2 Isolated Mesh Support

- Any router can self-elect as DODAG root
- Election: lowest EUI-64 wins
- Self-elected root generates ULA prefix

#### 3.3 Multiple Border Routers

- Each BR advertises its own prefix(es)
- No coordination required
- Nodes handle multiple addresses

**Exit Criteria:**
- Nodes can ping (link-local)
- ULA addresses work
- Isolated mesh self-organizes

---

### Phase 4: RPL Routing

**Goal:** Mesh formation with MRHOF objective function.

#### 4.1 Control Messages

DIO, DIS, DAO, DAO-ACK per RFC 6550.

#### 4.2 Trickle Timer

Imin=4s, Imax=17min, k=10.

#### 4.3 Non-Storing Mode

6LoRH source routing for downward traffic.

**Exit Criteria:**
- 5-node mesh forms DODAG
- Upward and downward routing work
- Parent switching on link failure

---

### Phase 5: Security Layer

**Goal:** TOFU trust model, OSCORE encryption.

#### 5.1 Trust Model (per spec section 8.5)

| Method | Infrastructure | Trust Level |
|--------|---------------|-------------|
| TOFU | None | Pinned |
| DANE | DNSSEC | Verified |
| PKIX | CA | Verified |

**TOFU is mandatory. DANE and PKIX are optional.**

#### 5.2 Key Store

```rust
pub struct KeyStore {
    pub my_keypair: Ed25519Keypair,
    pub peers: HashMap<IID, PeerKey>,  // IID → pubkey + trust level
    pub oscore_contexts: HashMap<IID, OscoreContext>,
}
```

#### 5.3 OSCORE

RFC 8613 for end-to-end CoAP encryption.

**Exit Criteria:**
- TOFU key exchange works
- OSCORE-protected CoAP works
- Key pinning with change detection

---

### Phase 6: Local Client Interface

**Goal:** IPv6+CoAP interface for phone apps and local clients.

#### 6.1 Transport Bindings (per spec section 17.3)

| Transport | Framing |
|-----------|---------|
| Serial/USB | SLIP (RFC 1055) |
| BLE | SLIP over BLE UART or 6LoWPAN over BLE |
| RTOS IPC | Direct buffers |

#### 6.2 CoAP Resources

| Resource | Purpose |
|----------|---------|
| /config | Node configuration |
| /status | Status (observable) |
| /keys | Trust store CRUD |
| /sensors/* | SenML sensor data |
| /msg/* | Messaging |

**Exit Criteria:**
- SLIP framing works over serial
- BLE UART works
- CoAP resources implemented
- Client can address mesh nodes through local node

---

### Phase 7: SenML Sensors

**Goal:** RFC 8428 SenML for all sensor data.

#### 7.1 Sensor Profiles (per spec Appendix F)

| Sensor | Resource | Key Fields |
|--------|----------|------------|
| Location | /sensors/location | lat, lon, alt, speed, heading |
| Battery | /sensors/battery | pct, mv, charging |
| Temperature | /sensors/temp | temp (Cel) |
| Humidity | /sensors/humidity | rh |
| Pressure | /sensors/pressure | press (Pa) |
| Radio | /sensors/radio | rssi, snr, duty |

#### 7.2 Base Name Convention

```
urn:dev:mac:<EUI-64>:
```

**Exit Criteria:**
- All sensor profiles implemented
- Observable resources work
- Position beaconing works

---

### Phase 8: Applications

**Goal:** Tactical radio features per spec section 18.

#### 8.1 Messaging (spec 18.1)

- Unicast, multicast, broadcast
- Delivery receipts
- Canned messages
- Store-and-forward (optional)

#### 8.2 Position Sharing (spec 18.2)

- Position beacons via SenML
- Position cache (blue force tracking)
- Privacy controls

#### 8.3 Waypoints (spec 18.3)

- CRUD on /waypoints
- Share via unicast/broadcast
- Routes as ordered waypoint lists

#### 8.4 Emergency/SOS (spec 18.4)

- Priority multicast
- Controlled relay
- Hardware button support
- Network prioritization

#### 8.5 Presence (spec 18.5)

- Status: available/busy/away/offline/emergency
- Activity hints
- Auto-update from GPS

#### 8.6 Check-In/Roll Call (spec 18.6)

- Individual check-in
- Leader-initiated multicast roll call
- Missing node detection

#### 8.7 Range Testing (spec 18.7)

- Extended ping with radio telemetry
- Traceroute through mesh

#### 8.8 Groups (spec 18.8)

- Multicast addressing (RFC 7390)
- Optional OSCORE group encryption (RFC 9203)

**Exit Criteria:**
- All P0 applications working
- SOS priority handling works
- Group messaging works

---

### Phase 9: Border Router

**Goal:** Full 6LBR connecting mesh to internet.

#### 9.1 Components

| Component | Function |
|-----------|----------|
| DODAG Root | RPL root, prefix advertisement |
| Prefix Manager | ULA generation, GUA delegation |
| Source Router | 6LoRH insertion for downward traffic |
| Resource Directory | CoAP RD (RFC 9176) |
| MQTT-SN Gateway | MQTT-SN ↔ MQTT bridge |

#### 9.2 Prefix Sources

1. ULA (self-generated, persisted)
2. Static GUA configuration
3. DHCPv6-PD from upstream
4. Tunnel broker

**Exit Criteria:**
- Internet host can ping mesh node
- Mesh node can reach internet
- Resource Directory operational

---

### Phase 10: Tooling & Polish

#### 10.1 lichen-craft CLI

```bash
lichen-craft encode --coap GET /sensors/temp --compress rule0 --sign key.pem
lichen-craft decode --input packet.bin --keys keydir/
lichen-craft keygen --output node.key
```

#### 10.2 Wireshark Dissector

Lua plugin for full protocol decode.

#### 10.3 Network Simulator

Discrete-event simulation with configurable topology and link quality.

#### 10.4 Web Dashboard

Border router web UI for monitoring and configuration.

**Exit Criteria:**
- All tools functional
- Documentation complete
- Example applications working

---

## 4. IETF-Style Documents

| Document | Content | Phase |
|----------|---------|-------|
| draft-lichen-link | Link layer, LLSec, Ed25519 | 1 |
| draft-lichen-schc | SCHC profile for LICHEN | 2 |
| draft-lichen-addr | IPv6 addressing, ULA, isolated mesh | 3 |
| draft-lichen-rpl | RPL configuration, MRHOF | 4 |
| draft-lichen-security | TOFU, DANE, OSCORE profile | 5 |
| draft-lichen-lci | Local Client Interface | 6 |
| draft-lichen-senml | SenML sensor profiles | 7 |
| draft-lichen-apps | Application protocols | 8 |
| draft-lichen-border | Border router behavior | 9 |

---

## 5. Dependencies

### Zephyr RTOS

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

**What Zephyr doesn't have (we build):**
- SCHC compression
- Ed25519 truncated signatures (use monocypher)
- LICHEN link layer framing
- RPL tuning for LoRa timing
- Application layer

### Rust Crates (GPL-3.0 compatible)

| Crate | Use | License |
|-------|-----|---------|
| ed25519-dalek | Signatures | BSD-3 |
| aes-gcm | OSCORE encryption | MIT/Apache-2.0 |
| heapless | no_std collections | MIT/Apache-2.0 |
| coap-lite | CoAP parsing | MIT |
| smoltcp | IP stack (Linux node) | 0BSD |

### C Libraries (for Zephyr modules)

| Library | Use | License |
|---------|-----|---------|
| monocypher | Ed25519, AES | Public domain |
| libschc | SCHC reference | MIT |

### Fallback: RIOT OS (if STM32WL needs it)

| Component | RIOT Module | Notes |
|-----------|-------------|-------|
| IPv6/6LoWPAN | GNRC | Proven ~10KB RAM |
| RPL | GNRC RPL | Lightweight |
| CoAP | gcoap | Efficient |
| LoRa | sx126x/sx127x | Drivers available |

---

## 6. Risk Register

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| **STM32WL memory overflow** | High | Medium | Early validation in Phase 0; RIOT fallback ready |
| Zephyr LoRa+6LoWPAN integration issues | Medium | Medium | LoRa is not 802.15.4; may need adaptation layer |
| Truncated Ed25519 security concerns | High | Low | Document analysis; ECDSA fallback option |
| RPL convergence too slow for LoRa | Medium | Medium | Tune Trickle; test in simulator first |
| BLE+LoRa concurrent operation | Medium | Low | Platform-specific; test early |
| Duty cycle violations (EU) | High | Low | Build duty cycle tracker |

---

## 7. Resolved Design Decisions

**Added in this revision:**

| Decision | Resolution |
|----------|------------|
| Embedded RTOS | Zephyr (primary), RIOT (STM32WL fallback if needed) |
| Why not Arduino | No native IPv6/6LoWPAN/RPL/CoAP; Zephyr has all |

These are settled and reflected in the spec:

| Decision | Resolution |
|----------|------------|
| Project name | LICHEN (LoRa IPv6 CoAP Hybrid Extended Network) |
| License | CC-BY-4.0 (docs), GPL-3.0 (code) |
| Hardware | Meshtastic-compatible (reflash) |
| Trust model | TOFU baseline, DANE/PKIX optional, no PSK, no mandatory CA |
| IPv6 addressing | Link-local always, ULA default, GUA optional |
| Isolated meshes | Self-elect root (lowest EUI-64), generate ULA |
| Multiple BRs | Tolerated, no coordination required |
| Local interface | IPv6+CoAP over SLIP/BLE (not protobuf) |
| Sensor data | SenML (RFC 8428) over CBOR |

---

## 8. Open Questions

| Question | Options | Notes |
|----------|---------|-------|
| Truncated Ed25519 derivation | Deterministic scheme TBD | Need exact algorithm |
| SCHC rule distribution | Pre-provisioned vs. negotiated | Lean toward pre-provisioned |
| Time synchronization | NTP/CoAP, GPS, DIO piggyback | Needed for replay protection |
| DANE record format | TLSA for `_25519._mesh.<name>` | Need exact structure |
| Zephyr 6LoWPAN over LoRa | Adaptation layer design | LoRa ≠ 802.15.4 |

---

## 9. Success Criteria

### MVP (Minimum Viable Network)

- [ ] 3+ nodes form stable DODAG
- [ ] Position sharing works
- [ ] Text messaging works
- [ ] All traffic Ed25519 authenticated
- [ ] SCHC compression < 15 bytes for telemetry
- [ ] Runs on Heltec LoRa 32 V3 (Zephyr)
- [ ] **STM32WL validated** (Zephyr or RIOT)

### v1.0 (Production Ready)

- [ ] 50+ node mesh stable over 24 hours
- [ ] OSCORE encryption on all CoAP
- [ ] Parent switching < 30 seconds
- [ ] All applications working (messaging, SOS, waypoints, etc.)
- [ ] Zephyr on ESP32, nRF52840, RP2040, (STM32WL or RIOT)
- [ ] Rust gateway/simulator interop with Zephyr nodes
- [ ] All I-Ds complete

---

## 10. Next Steps

1. Create GitHub repo structure
2. Set up CI/CD
3. Begin Phase 0 tasks
4. File beads issues for Phase 0 work items

---

*This plan is a living document. Track implementation progress in beads.*
