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
- **Dual implementation:** Rust (reference) + C (constrained devices)
- **Decentralized:** No PSK, no mandatory CA, TOFU baseline trust

---

## 1. Repository Structure

```
LICHEN/
├── docs/
│   ├── LICHEN-spec.md           # Protocol specification (CC-BY-4.0)
│   ├── LICHEN-plan.md           # This file
│   └── draft-lichen-*.md        # IETF-style I-Ds
├── rust/
│   ├── Cargo.toml               # Workspace root
│   ├── lichen-phy/              # LoRa radio abstraction (SX126x, SX127x)
│   ├── lichen-link/             # Link layer (LLSec, Ed25519 signatures)
│   ├── lichen-schc/             # SCHC compression engine
│   ├── lichen-6lowpan/          # 6LoWPAN adaptation
│   ├── lichen-ipv6/             # IPv6 minimal + addressing
│   ├── lichen-rpl/              # RPL routing + Trickle
│   ├── lichen-coap/             # CoAP + OSCORE + Observe
│   ├── lichen-senml/            # SenML encoding/decoding
│   ├── lichen-apps/             # Applications (messaging, SOS, etc.)
│   ├── lichen-lci/              # Local Client Interface
│   ├── lichen-node/             # Full node binary
│   ├── lichen-gateway/          # Border router binary
│   ├── lichen-sim/              # Network simulator
│   └── lichen-ffi/              # C bindings (cbindgen)
├── c/
│   ├── include/lichen/          # Public headers
│   ├── src/
│   │   ├── phy/                 # Radio drivers
│   │   ├── link/                # Link layer
│   │   ├── schc/                # SCHC
│   │   ├── ipv6/                # IPv6 + 6LoWPAN
│   │   ├── rpl/                 # RPL
│   │   ├── coap/                # CoAP + OSCORE
│   │   ├── senml/               # SenML
│   │   ├── apps/                # Applications
│   │   └── lci/                 # Local Client Interface
│   ├── port/
│   │   ├── esp32/               # ESP32 + ESP32-S3
│   │   ├── nrf52/               # nRF52840
│   │   ├── rp2040/              # RP2040
│   │   └── stm32wl/             # STM32WL
│   └── CMakeLists.txt
├── test/
│   ├── vectors/                 # Shared test vectors (JSON)
│   ├── interop/                 # Rust ↔ C interop tests
│   └── hardware/                # Hardware-in-loop tests
├── tools/
│   ├── lichen-craft/            # Packet builder/parser CLI
│   ├── wireshark-dissector/     # Wireshark Lua plugin
│   └── lichen-keygen/           # Key generation/provisioning
├── apps/
│   ├── lichen-cli/              # Command-line client
│   ├── lichen-tui/              # Terminal UI
│   └── lichen-web/              # Web dashboard (border router)
└── examples/
    ├── sensor-node/             # Reference leaf node
    ├── router/                  # Reference router
    └── border-router/           # Reference 6LBR
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
| STM32WL | 64KB | 256KB | Constrained baseline |

---

## 3. Phase Plan

### Phase 0: Foundation

**Goal:** Project scaffolding, tooling, CI/CD.

| Task | Output |
|------|--------|
| Create Rust workspace with `no_std` crates | `rust/Cargo.toml` |
| Create C build system (CMake + platform ports) | `c/CMakeLists.txt` |
| Define shared constants (frequencies, sync word 0x34, ports) | Shared headers |
| Set up GitHub Actions CI | `.github/workflows/` |
| Create test vector framework | `test/vectors/` |
| Write `draft-lichen-link-01.md` | `docs/` |

**Exit Criteria:**
- `cargo build --workspace` succeeds (stubs)
- `cmake --build` succeeds for all platforms
- CI runs on push

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

### Rust Crates (GPL-3.0 compatible)

| Crate | Use | License |
|-------|-----|---------|
| embedded-hal | Hardware abstraction | MIT/Apache-2.0 |
| ed25519-dalek | Signatures | BSD-3 |
| aes-gcm | OSCORE encryption | MIT/Apache-2.0 |
| heapless | no_std collections | MIT/Apache-2.0 |
| defmt | Embedded logging | MIT/Apache-2.0 |

### C Libraries

| Library | Use | License |
|---------|-----|---------|
| monocypher | Ed25519, AES | Public domain |
| libschc | SCHC reference | MIT |

---

## 6. Resolved Design Decisions

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

## 7. Open Questions

| Question | Options | Notes |
|----------|---------|-------|
| Truncated Ed25519 derivation | Deterministic scheme TBD | Need exact algorithm |
| SCHC rule distribution | Pre-provisioned vs. negotiated | Lean toward pre-provisioned |
| Time synchronization | NTP/CoAP, GPS, DIO piggyback | Needed for replay protection |
| DANE record format | TLSA for `_25519._mesh.<name>` | Need exact structure |

---

## 8. Success Criteria

### MVP (Minimum Viable Network)

- [ ] 3+ nodes form stable DODAG
- [ ] Position sharing works
- [ ] Text messaging works
- [ ] All traffic Ed25519 authenticated
- [ ] SCHC compression < 15 bytes for telemetry
- [ ] Runs on Heltec LoRa 32 V3

### v1.0 (Production Ready)

- [ ] 50+ node mesh stable over 24 hours
- [ ] OSCORE encryption on all CoAP
- [ ] Parent switching < 30 seconds
- [ ] All applications working (messaging, SOS, waypoints, etc.)
- [ ] C implementation on all target platforms
- [ ] Full Rust ↔ C interop
- [ ] All I-Ds complete

---

## 9. Next Steps

1. Create GitHub repo structure
2. Set up CI/CD
3. Begin Phase 0 tasks
4. File beads issues for Phase 0 work items

---

*This plan is a living document. Track implementation progress in beads.*
