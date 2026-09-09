<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Local Client Interface

## 17. Local Client Interface

### 17.1. Overview

The Local Client Interface (LCI) connects external applications (phone apps,
desktop clients, RTOS tasks) to the mesh node. Unlike Meshtastic's proprietary
protobuf-over-GATT approach, LCI treats the local connection as another IPv6
interface, using the same CoAP protocol stack as mesh traffic.

**Design Principles:**

1. **Unified protocol:** CoAP everywhere, no separate local API
2. **Transport-agnostic:** Same framing works over BLE, serial, USB, IPC
3. **Client is a neighbor:** Gets link-local IPv6 address, routes through node
4. **Standard tools work:** Any CoAP client can control the node
5. **Push via Observe:** Notifications use CoAP Observe (RFC 7641)

### 17.1.1. Legacy Interface Deprecation

An earlier draft protocol under `spec/lichen-native/` defined a CBOR integer-key
framing scheme (0xC1 start byte, message type codes 0x01-0x61). That protocol
was a prototype exploration and is **not authoritative** for LCI.

**Deprecated elements (do not implement):**

- 0xC1 + length + CBOR frame envelope
- Integer message type codes (hello=0x01, config_get=0x10, raw_tx=0x60, etc.)
- Integer configuration keys
- `raw_tx` / `raw_rx` CBOR messages
- `/messages` REST-style resource from Python demos

**Current LCI contract:**

- SLIP-framed IPv6 packets (or native IPv6 over BLE L2CAP / IPC)
- CoAP resources at well-known paths (`/config`, `/status`, `/diag/raw/*`)
- CBOR payloads with string keys for human readability and tooling compatibility

The `spec/lichen-native/` directory is retained for historical reference. Each
file there carries a status banner; implementers finding those files should
follow the cross-references to this document.

### 17.2. Architecture

```
+------------------------------------------------------------------+
|                         Client Device                             |
|  (Phone, Laptop, RTOS Task)                                       |
|                                                                   |
|  +---------------+  +---------------+  +-----------------------+  |
|  | Mesh App      |  | Config Tool   |  | Other CoAP Clients    |  |
|  +-------+-------+  +-------+-------+  +-----------+-----------+  |
|          |                  |                      |              |
|          +------------------+----------------------+              |
|                             |                                     |
|                      +------+-------+                             |
|                      | CoAP Client  |                             |
|                      | fe80::client |                             |
|                      +------+-------+                             |
+----------------------------|--------------------------------------+
                             | SLIP / BLE / IPC
+----------------------------|--------------------------------------+
|                      +------+-------+          Mesh Node          |
|                      | Local I/F    |                             |
|                      | fe80::1      |                             |
|                      +------+-------+                             |
|                             |                                     |
|                      +------+-------+                             |
|                      |  IPv6 Stack  |                             |
|                      |  CoAP Server |                             |
|                      |  fe80::node  |                             |
|                      +------+-------+                             |
|                             |                                     |
|                      +------+-------+                             |
|                      | LoRa Radio   |                             |
|                      | Interface    |                             |
|                      +--------------+                             |
+-------------------------------------------------------------------+
```

The client and node communicate via link-local IPv6. The node acts as a
router: traffic to mesh addresses is forwarded over LoRa.

### 17.3. Transport Bindings

All transports carry IPv6 packets. Framing adapts to the transport.

#### 17.3.1. Serial / USB (SLIP)

SLIP (RFC 1055) framing over UART or USB CDC-ACM:

```
+------+---------------------+------+
| 0xC0 |  IPv6 Packet        | 0xC0 |
| END  |  (escaped)          | END  |
+------+---------------------+------+
```

Escaping:
- 0xC0 (END) in data -> 0xDB 0xDC
- 0xDB (ESC) in data -> 0xDB 0xDD

Recommended baud: 115200 or higher.

#### 17.3.2. Bluetooth Low Energy

**Option A: SLIP over BLE UART (Nordic UART Service or similar)**

- UUID: vendor-specific or 6E400001-B5A3-F393-E0A9-E50E24DCCA9E (NUS)
- TX/RX characteristics carry SLIP-framed IPv6
- Simple, works with existing BLE serial libraries

**Option B: 6LoWPAN over BLE (RFC 7668)**

- Standard IPSP (Internet Protocol Support Profile)
- L2CAP connection-oriented channels
- More overhead, but fully standard
- Header compression via 6LoWPAN IPHC

Implementations SHOULD support Option A. Option B is OPTIONAL.

#### 17.3.3. Bluetooth Classic (SPP)

SLIP framing over RFCOMM/SPP. Same as serial.

#### 17.3.4. RTOS IPC (Same-Device)

For applications running on the same MCU as the network stack:

```c
// Send IPv6 packet to network stack
void lci_send(const uint8_t *ipv6_pkt, size_t len);

// Receive IPv6 packet from network stack
size_t lci_recv(uint8_t *buf, size_t max_len, uint32_t timeout_ms);
```

Implementation may use:
- FreeRTOS queues / stream buffers
- Zephyr message queues / pipes
- Direct function calls (if same thread context)

No framing needed; packets are discrete.

### 17.4. Client IPv6 Address

The client obtains a link-local address for the local interface:

**Static (simple):**
```
Client: fe80::2
Node:   fe80::<node IID>
```

**EUI-64 derived (client side):**
```
Client: fe80::<IID from device MAC>
Node:   fe80::<node IID>
```

`<node IID>` is always the node's key-derived IID: `IID = SHA-512(pubkey)[0:8]`
with the U/L bit cleared (spec/04-network.md §6.2, spec/06-security.md §8.5).
The node's wire EUI-64 is obtained from that IID by toggling the U/L bit exactly
once (spec/02-physical-link.md §4.2); it is never the source of the IID. The
client is a generic IPv6 host and MAY use a static address or one derived from
its device MAC; such an IID is link-interoperability only and is not a LICHEN
node identity. `fe80::1` in examples throughout this document is illustrative
shorthand for the node's link-local address.

The node acts as default router for the client. Client's routing table:

```
fe80::/10       -> local interface (direct)
::/0            -> fe80::1 (node)
```

### 17.5. CoAP Resources

The node exposes a CoAP server on UDP port 5683. All resources below are
relative to the node's link-local address.

The LCI CoAP resources in this section are the authoritative native application
contract. The older CBOR integer-key draft under `spec/lichen-native/` is a
historical prototype contract only; new BLE, USB, serial, IP, simulator, and
Python-native clients MUST NOT use its `0xC1` framing, integer config keys,
`raw_tx`, or `raw_rx` messages as LCI.

#### 17.5.1. Discovery

```
GET coap://[fe80::1]/.well-known/core

Response:
</config>;rt="config",
</config/radio>;rt="config",
</config/identity>;rt="config",
</status>;rt="status";obs,
</status/neighbors>;rt="status";obs,
</status/routes>;rt="status",
</keys>;rt="keystore",
</diag>;rt="diagnostics",
</msg/inbox>;rt="msg.inbox";ct=60;obs,
</msg/sent>;rt="msg.sent";ct=60,
</msg/ack>;rt="msg.ack";ct=60,
</deaddrop>;rt="deaddrop";ct=112;obs,
</confessions>;rt="confessions";ct=112;obs
```

#### 17.5.2. Configuration Resources

**Node Configuration**

```
GET /config
Content-Format: application/cbor

{
  "name": "my-node",
  "role": "router",         // "leaf", "router", "border-router"
  "radio": "/config/radio",
  "identity": "/config/identity"
}
```

```
PUT /config
Content-Format: application/cbor

{
  "name": "new-name",
  "role": "router"
}

Response: 2.04 Changed
```

**Radio Configuration**

```
GET /config/radio
Content-Format: application/cbor

{
  "freq_mhz": 906.875,
  "bw_khz": 125,
  "sf": 9,
  "cr": "4/5",
  "tx_power_dbm": 20,
  "sync_word": "0x34"
}
```

```
PUT /config/radio
Content-Format: application/cbor

{
  "sf": 10,
  "tx_power_dbm": 17
}

Response: 2.04 Changed
```

**Identity (Read-Only)**

```
GET /config/identity
Content-Format: application/cbor

{
  "eui64": "0x0011223344556677",
  "pubkey": "<base64 Ed25519 public key>",
  "pubkey_fingerprint": "SHA256:xY7...",
  "addrs": {
    "link_local": "fe80::0211:22ff:fe33:4455",
    "primary": "0200:1234:5678:9abc::0211:22ff:fe33:4455"
  }
}
```

#### 17.5.3. Status Resources

**Node Status (Observable)**

```
GET /status
Observe: 0
Content-Format: application/cbor

{
  "uptime_s": 3600,
  "battery_pct": 87,
  "battery_mv": 3950,
  "mem_free_kb": 42,
  "time": {
    "wall_clock_valid": true,
    "unix_time": 1716742800,
    "source_class": "gnss",
    "source_name": "onboard-gnss",
    "age_s": 120
  },
  "dodag": {
    "joined": true,
    "rank": 512,
    "parent": "fe80::1234:5678:9abc:def0",
    "root": "0200:1234:5678:9abc::1"
  },
  "radio": {
    "rx_packets": 1234,
    "tx_packets": 567,
    "rx_errors": 12,
    "duty_cycle_pct": 2.3
  },
    "ccp": {
    "rx_channel": 5,
    "scheduler_active": true,
    "preferred_rx_valid_until_sfn": 12350
  }

}
```

The `time` object exposes the firmware time provider state (see
`docs/firmware-time-provider.md`). When `wall_clock_valid` is false, `unix_time`
is omitted or zero and the node cannot provide authoritative timestamps. The
`source_class` indicates how time was obtained (gnss, network, local-client,
manual, internal-rtc). The `age_s` field shows seconds since the last accepted
time sample.

Status updates pushed via Observe on significant changes.

**Cross-Mesh Log Correlation (GNSS-Enabled):**

All diagnostic events (`/status/node`, `/status/queues`, neighbor tables,
routing changes) carry GNSS-derived timestamps. Because all nodes share a
common wall-clock reference, events from different nodes and different meshes
are directly comparable without NTP-style clock correction. This enables:

- Reconstructing cross-mesh timelines for debugging planetary-scale routing
- Correlating custody-transfer handshake logs across sender/relay/BR/recipient
- Comparing queue depth and duty cycle events across nodes to diagnose congestion
- Post-incident analysis using log exports from multiple nodes with aligned timestamps

Implementations SHOULD include `"ts": <unix_timestamp>` in all diagnostic
event payloads exposed via LCI.

**Neighbor Table (Observable)**

```
GET /status/neighbors
Content-Format: application/cbor

{
  "neighbors": [
    {
      "addr": "fe80::aaaa:bbbb:cccc:dddd",
      "rssi_dbm": -85,
      "snr_db": 7.5,
      "etx": 1.2,
      "last_seen_s": 30,
      "trust": "tofu"
    },
    {
      "addr": "fe80::1111:2222:3333:4444",
      "rssi_dbm": -72,
      "snr_db": 12.0,
      "etx": 1.0,
      "last_seen_s": 5,
      "trust": "dane"
    }
  ]
}
```

**Routing Table**

```
GET /status/routes
Content-Format: application/cbor

{
  "routes": [
    {
      "prefix": "0200:1234:5678:9abc::/64",
      "via": "fe80::1234:5678:9abc:def0",
      "metric": 512,
      "lifetime_s": 1800
    }
  ],
  "default_route": "fe80::1234:5678:9abc:def0"
}
```

#### 17.5.4. Diagnostic Resources

Diagnostic resources are optional. Firmware MAY omit `/diag` and `/diag/raw/*`
from `/.well-known/core`; clients MUST treat 4.04 Not Found or 5.01 Not
Implemented as unsupported diagnostics rather than falling back to the legacy
CBOR native protocol.

**Diagnostics Summary**

```
GET /diag
Content-Format: application/cbor

{
  "available": true,
  "raw": {
    "available": true,
    "rx": "/diag/raw/rx",
    "rx_events": "/diag/raw/rx/events",
    "tx": "/diag/raw/tx",
    "max_frame_len": 255
  }
}
```

**Raw RX Status and Arming**

```
GET /diag/raw/rx
Content-Format: application/cbor

{
  "enabled": false,
  "remaining_s": 0,
  "max_ttl_s": 300
}
```

```
PUT /diag/raw/rx
Content-Format: application/cbor

{
  "enabled": true,
  "ttl_s": 60,
  "include_payload": true
}

Response: 2.04 Changed
```

When raw RX is enabled, clients subscribe with CoAP Observe:

```
GET /diag/raw/rx/events
Observe: 0
Content-Format: application/cbor

{
  "frame": h'c1020304',
  "rssi_dbm": -85,
  "snr_db": 9,
  "uptime_ms": 3662000,
  "freq_hz": 915000000,
  "crc_ok": true
}
```

Raw RX MUST be disabled by default and MUST use a finite arming lifetime.
Receiving raw frames MUST NOT divert frames from the normal IPv6 stack.

**Raw TX**

```
POST /diag/raw/tx
Content-Format: application/cbor

{
  "frame": h'c1020304',
  "wait": true
}

Response: 2.04 Changed
```

Raw TX requests MAY include implementation-defined radio overrides only when
the firmware can enforce regional limits. Implementations MUST rate-limit raw
TX, MUST reject frames or overrides that violate configured PHY/regulatory
constraints, and SHOULD omit raw TX entirely in production firmware.

Raw diagnostics MUST require local administrative authorization. BLE transports
MUST require LE Secure Connections for these resources; deployments that expose
raw diagnostics beyond a local trusted link MUST protect them with OSCORE or an
equivalent authenticated admin credential. Firmware SHOULD require a build-time
diagnostic enablement flag and MAY require a local physical confirmation before
arming raw RX or accepting raw TX.

#### 17.5.5. Key Store

**List Keys**

```
GET /keys
Content-Format: application/cbor

{
  "keys": [
    {
      "iid": "1234:5678:9abc:def0",
      "pubkey_fp": "SHA256:xY7...",
      "trust": "tofu",
      "first_seen": "2026-05-26T12:00:00Z",
      "last_seen": "2026-05-26T14:30:00Z"
    }
  ]
}
```

**Get Single Key**

```
GET /keys/1234:5678:9abc:def0
Content-Format: application/cbor

{
  "iid": "1234:5678:9abc:def0",
  "pubkey": "<base64>",
  "trust": "tofu",
  "first_seen": "2026-05-26T12:00:00Z",
  "last_seen": "2026-05-26T14:30:00Z"
}
```

**Add/Update Key (Manual Trust)**

```
PUT /keys/1234:5678:9abc:def0
Content-Format: application/cbor

{
  "pubkey": "<base64>",
  "trust": "verified"
}

Response: 2.04 Changed
```

**Delete Key**

```
DELETE /keys/1234:5678:9abc:def0

Response: 2.02 Deleted
```

#### 17.5.6. Mesh Reachability

The client can reach any mesh node by addressing it directly. The local
node routes the traffic. This direct IPv6 + CoAP path is the authoritative
LCI mesh access model. No special proxy resource is required, and `/mesh` is
not an LCI forward-proxy resource.

```
# Client sends directly to mesh node
GET coap://[0200:1234:5678:9abc::aaaa:bbbb:cccc:dddd]/sensors/temp

# Node routes via LoRa mesh, returns response to client
Response: 2.05 Content
{temperature: 23.5}
```

For discovery, the client can query the Resource Directory (if available):

```
GET coap://[0200:1234:5678:9abc::1]/rd-lookup/res?rt=temperature
```

Implementations MAY expose an optional RFC 7252 forward proxy at `/proxy` for
compatibility with constrained local transports or host stacks that cannot
route directly to mesh IPv6 addresses. Clients MUST NOT require `/proxy` for
normal LCI operation, and discovery of `</proxy>;rt="proxy"` only signals this
compatibility helper. Proxy clients use the standard CoAP `Proxy-Uri` option to
name the mesh target; the gateway strips proxy options before forwarding.

```
GET coap://[fe80::1]/proxy
Proxy-Uri: coap://[0200:1234:5678:9abc::aaaa:bbbb:cccc:dddd]/status
```

#### 17.5.7. Messaging (Application-Level)

For human messaging (chat-like), nodes MAY implement:

```
# Send message
POST /msg/inbox
Content-Format: application/cbor

{
  "to": "0200:1234:5678:9abc::aaaa:bbbb:cccc:dddd",
  "body": "Hello from the mesh!",
  "ack": true
}

Response: 2.01 Created
Location-Path: /msg/sent/42
```

```
# Receive messages (Observable)
GET /msg/inbox
Observe: 0
Content-Format: application/cbor

{
  "messages": [
    {
      "id": 17,
      "from": "0200:1234:5678:9abc::1111:2222:3333:4444",
      "body": "Hi there!",
      "received": "2026-05-26T14:35:00Z"
    }
  ]
}
```

This is OPTIONAL. Applications MAY instead use CoAP directly to mesh nodes.
The legacy Python demo `/messages` resource is not part of LCI and MUST NOT be
advertised as a native messaging resource.

#### 17.5.8. Dead Drop

The `/deaddrop` resource provides a rate-limited, OSCORE-protected store for
asynchronous data exchange. Nodes and clients can POST SenML payloads for later
pickup by others (useful for delayed messaging, sensor logs without live
connection). Follows SenML profile from Appendix F.

**Access and Protection:**

- All writes (POST) MUST use OSCORE (pairwise preferred; group context allowed)
- Unauthenticated POSTs return 4.01 Unauthorized
- Reads (GET) MAY be public but sensitive drops SHOULD require OSCORE match
- Rate limits enforced per OSCORE context or source IID (see 18.9 in apps spec)

**Example Usage:**

```
POST coap://[fe80::1]/deaddrop
Content-Format: application/senml+cbor
OSCORE: <context-id=42>

[
  {"bn":"urn:dev:mac:0011223344556677:","bt":1721650000},
  {"n":"type","vs":"message"},
  {"n":"body","vs":"Pickup coords for supply cache at 48.1N 11.5E"},
  {"n":"expires","v":1721736400}
]
```

Response: `2.01 Created` with `Location-Path: /deaddrop/d4a3f2`

```
GET coap://[fe80::1]/deaddrop?obs=0
Content-Format: application/senml+cbor
```

Returns array of available drops (filtered by access). Rate limits, OSCORE rules, SenML details, SCHC handling, and full client UI guidance (Observe, templates, rate indicators, privacy toggles) are authoritative in 12-apps.md:18.9. LCI clients implement the CoAP contract exactly as specified there.

#### 17.5.9. Confessions

The `/confessions` resource provides an anonymous, ephemeral messaging board for
peer communication without sender attribution. RAM-only storage; no flash writes
for confessions data. Cleared on reboot.

**Access and Protection:**

- All writes (POST) SHOULD use SenML + CBOR (Content-Format 112)
- OSCORE is OPTIONAL for confessions (anonymous postings gain from no attribution)
- Reads (GET) are public and do not require OSCORE
- Rate limits are the tightest in LICHEN: 1 POST per 30 s, 12 per hour per source IID
- No-log guarantee: implementations MUST NOT persist confessions to flash

**Example Usage:**

```
POST coap://[fe80::1]/confessions
Content-Format: application/senml+cbor

[
  {"bn":"urn:dev:mac:0011223344556677:","bt":1721654321},
  {"n":"type","vs":"confession"},
  {"n":"content","vs":"Left the base unlocked at 0200."},
  {"n":"anonymous","v":1}
]
```

Response: `2.01 Created` with `Location-Path: /confessions/8a4f2b`

```
GET coap://[fe80::1]/confessions?count=5
Content-Format: application/senml+cbor

{
  "count": 1,
  "confessions": [
    {"id": "8a4f2b", "content": "...", "ts": 1721654321, "age_s": 900}
  ],
  "rate_remaining": 11,
  "rate_reset_s": 29
}
```

Rate limits, OSCORE considerations, no-log guarantee, eviction policy, e-ink UI
flow, and test vectors are authoritative in 12-apps.md:18.10. LCI clients
implement the CoAP contract exactly as specified there.

### 17.6. Security

#### 17.6.1. Transport Security

The local link may be unencrypted (trusted physical access) or encrypted:

| Transport | Encryption |
|-----------|------------|
| USB/Serial | None (physical security) |
| BLE | BLE pairing (LE Secure Connections) |
| WiFi | WPA2/3 |
| RTOS IPC | None (same device) |

#### 17.6.2. Application Security

For sensitive operations, use OSCORE over the local link:

- OSCORE context established via pairing
- Protects against compromised transport
- Same mechanism as mesh traffic

#### 17.6.3. Access Control

Implementations SHOULD support restricting local client access:

| Level | Allowed Operations |
|-------|-------------------|
| Read-only | GET on non-sensitive resources; excludes `/diag/raw/*` |
| Standard | GET, Observe, direct mesh CoAP reachability, optional `/proxy`; excludes `/diag/raw/*` |
| Admin | All operations including PUT /config, DELETE /keys, `/diag/raw/*` |

Access level determined by transport (e.g., USB = admin, BLE = standard).

### 17.7. Implementation Notes

**Minimal Implementation:**

A constrained node MUST implement:
- SLIP framing (serial)
- /.well-known/core
- /config (read-only acceptable)
- /status

**Full Implementation:**

A capable node (border router, gateway) SHOULD implement:
- All transports (SLIP, BLE, WiFi if available)
- All resources
- Observe on status resources
- OSCORE for local link

**Memory Impact:**

| Component | Additional RAM | Additional Flash |
|-----------|----------------|------------------|
| SLIP framing | 256 B | 512 B |
| LCI CoAP resources | 1-2 KB | 4-8 KB |
| BLE UART service | 512 B | 2 KB |

### 17.8. Unified UI Specification

All LICHEN user interfaces — phone app, on-device display, terminal TUI,
web dashboard — share a single information architecture. The mental model
is identical; only the rendering adapts to the surface.

**Design principles:**

1. **Same screens everywhere.** Every surface shows the same 4+2 screens
   in the same order. Users switching between phone and e-ink don't relearn
   navigation.
2. **Information density over decoration.** Every pixel earns its place. If
   a UI element doesn't answer a question the user has, delete it. No
   gradients, no drop shadows, no rounded-corner cards around single values.
3. **Status is always visible.** Battery, signal, time, and mesh state are
   persistent — never hidden behind a tap or scroll.
4. **Progressive disclosure.** Primary screens show what you need 90% of
   the time. Details are one action deeper. Settings are two actions deeper.
5. **Text is UI.** Well-formatted text with monospace alignment conveys more
   information per pixel than icons. Use icons only for universal concepts
   (battery, signal bars, message status).

#### 17.8.1. Screen Vocabulary

**Primary screens (tab bar / button cycle):**

| # | Screen | Shows | Updates |
|---|--------|-------|---------|
| 1 | **Messages** | Conversations, custody status (Sending/Sent/Delivered/Expired) | On Observe notification |
| 2 | **Map** | Peer positions, own position, bearing/distance | On position beacon |
| 3 | **Peers** | Who's on mesh: IID, name, signal, hops, last seen, trust | On announce/status |
| 4 | **Status** | Own node: battery, duty cycle, DODAG, radio stats, custody store | On change |

**Secondary screens (accessed from primary):**

| # | Screen | Shows | Access |
|---|--------|-------|--------|
| 5 | **Settings** | Config: name, channel, TX power, announce rate | From Status |
| 6 | **Keys** | Trust store: pinned keys, TOFU history, verification | From Peers |

Six screens total. That's the entire UI.

#### 17.8.2. Status Bar

Persistent across all screens. Same layout on all surfaces.

```
┌──────────────────────────────────────┐
│ ▮▮▮▯ 87%  ⊕3hop  12:34  ✉2  ◉SYNCED │
└──────────────────────────────────────┘
```

| Element | Meaning | Source |
|---------|---------|--------|
| ▮▮▮▯ 87% | Battery level | /status battery_pct |
| ⊕3hop | RPL rank (hops to root) | /status dodag.rank |
| 12:34 | GNSS time (HH:MM) | time provider |
| ✉2 | Unread message count | /msg/inbox unread |
| ◉SYNCED | TDMA sync state | CCP desync FSM |

On e-ink: status bar is top line, partial-refresh only on change.
On phone: status bar is persistent header or system notification.
On TUI: status bar is top or bottom terminal line.

#### 17.8.3. Messages Screen

The primary screen. Conversation list, most recent first.

```
┌──────────────────────────────────────┐
│ MESSAGES                        [New]│
├──────────────────────────────────────┤
│ Alice           12:31  ✓✓ Delivered  │
│  Got it, on my way                   │
│                                      │
│ Bob             12:28  ✓  Sent       │
│  Meet at checkpoint 3                │
│                                      │
│ SAR Team (5)    12:15  ✓✓ Delivered  │
│  All clear sector 7                  │
│                                      │
│ Charlie         11:50  ⚠ Expired     │
│  Anyone at base camp?                │
└──────────────────────────────────────┘
```

**Custody status indicators** (from §18.1.2 sender UX states):

| Indicator | Meaning |
|-----------|---------|
| ⏳ | Sending (no custody yet) |
| ✓ | Sent (custody accepted) |
| ✓✓ | Delivered (receipt or ack_through) |
| ⚠ | May not have been delivered (TTL expired) |

Tapping/selecting a conversation opens the message thread. Conversation
view shows individual messages with timestamps and status.

On e-ink: show 3-4 conversations per screen. Buttons: up/down scroll,
select opens thread, long-press opens compose (canned or T9-style).

#### 17.8.4. Map Screen

Peer positions relative to self. Text-first, not tile-map.

```
┌──────────────────────────────────────┐
│ MAP                     N↑  42.3614° │
├──────────────────────────────────────┤
│                  · Alice (0.3km NW)  │
│         ·Bob                         │
│        (1.2km W)                     │
│                                      │
│               ★ You                  │
│                                      │
│                     ·Charlie         │
│                      (0.8km SE)      │
│                                      │
│  ·SAR-Base (2.1km S)                 │
└──────────────────────────────────────┘
```

On capable surfaces (phone, web): optional tile map background with peer
dots overlaid. The text bearing/distance list is always available as
fallback.

On e-ink: bearing/distance list only (no map tiles). Sorted by distance.

```
┌────────────────────┐
│ PEERS NEARBY       │
│ Alice   0.3km  NW ✓│
│ Charlie 0.8km  SE ✓│
│ Bob     1.2km  W  ✓│
│ SAR-Bas 2.1km  S  ✓│
│ Delta   4.7km  NE ?│
└────────────────────┘
```

✓ = recent position (< 5 min). ? = stale position (> 5 min).

#### 17.8.5. Peers Screen

Everyone the node knows about. Sorted by signal quality.

```
┌──────────────────────────────────────┐
│ PEERS (7 visible, 12 known)         │
├──────────────────────────────────────┤
│ Alice      -72dBm  12.0dB  1hop  5s │
│ Bob        -85dBm   7.5dB  2hop 30s │
│ Charlie    -91dBm   3.2dB  3hop  2m │
│ SAR-Base   -78dBm   9.0dB  1hop 10s │
│ Delta      -95dBm   1.1dB  4hop  5m │
│ Echo       -88dBm   5.5dB  2hop  1m │
│ Foxtrot   [via BR]         6hop 15m │
├──────────────────────────────────────┤
│ 5 more via backbone (not direct)    │
└──────────────────────────────────────┘
```

Columns: name, RSSI, SNR, hop count, last seen. Selecting a peer shows
detail: IID, public key fingerprint, trust state (TOFU/pinned), message
history, position if known.

"via BR" indicates the peer is in a different DODAG, reachable through
backbone. No RSSI/SNR for backbone peers (no direct radio link).

#### 17.8.6. Status Screen

Own node health. The dashboard.

```
┌──────────────────────────────────────┐
│ STATUS                    [Settings] │
├──────────────────────────────────────┤
│ Battery:    87% (3950mV) ~18h remain │
│ Uptime:     3h 42m                   │
│ Time:       12:34:56 UTC (GNSS)      │
│                                      │
│ Radio:                               │
│  Duty:      2.3% (limit 5%)         │
│  TX/RX:     567 / 1234 packets       │
│  Errors:    12 (0.97%)               │
│  Channel:   CH3 (SF10)               │
│                                      │
│ Mesh:                                │
│  DODAG:     joined (rank 512)        │
│  Root:      SAR-Base (1 hop)         │
│  Peers:     7 direct, 5 backbone     │
│  Custody:   2 held (1.2 KB)          │
│                                      │
│ Position:   42.3614°N 71.0579°W      │
│  Fix:       3D, 8 sats, HDOP 1.2    │
└──────────────────────────────────────┘
```

Custody store line shows how many messages this node is holding for others
and the storage used. Relevant for powered relays/BRs.

#### 17.8.7. Surface Adaptations

The information architecture is fixed. Rendering adapts:

| Surface | Resolution | Input | Color | Refresh |
|---------|-----------|-------|-------|---------|
| T-Echo e-ink | 200×200 1-bit | 3 buttons | B&W | Partial 50ms, full 200ms |
| Phone app | Variable | Touch | Full | Immediate |
| TUI | Terminal grid | Keyboard | 256-color | Immediate |
| Web dashboard | Variable | Mouse/keyboard | Full | WebSocket push |

**E-ink specifics:**
- 3 buttons: PREV / SELECT / NEXT
- PREV/NEXT cycle screens; within a screen, scroll
- SELECT opens detail / compose / settings
- Long-press SELECT: SOS (from any screen)
- Partial refresh for status bar and scroll; full refresh on screen change
- Sleep after 30s inactivity; wake on button or radio event
- Unread badge persists on sleep screen: "✉3 new messages"

**Phone specifics:**
- Bottom tab bar: Messages / Map / Peers / Status
- Swipe between tabs; pull-to-refresh
- Map tab uses native map view with peer overlay
- Push notifications for new messages (via BLE Observe)
- Compose with full keyboard

**TUI specifics:**
- Tab/number keys switch screens (1-4 primary, 5-6 secondary)
- Vim-style navigation (j/k scroll, Enter select, q back)
- Color: green=good, yellow=warning, red=critical for signal/battery
- Resize-aware; works in 80×24 minimum

**Web specifics:**
- Single-page app, WebSocket for Observe notifications
- Same 4-tab layout; sidebar for peer detail
- Map uses Leaflet/OpenStreetMap

#### 17.8.8. Data Binding

All UI surfaces are CoAP Observe clients to the local node. The node is
the single source of truth. UIs do not maintain independent state.

| Screen | CoAP Resource | Observe? |
|--------|---------------|----------|
| Messages | /msg/inbox | Yes |
| Map | /pos (multicast) + /status | Yes |
| Peers | /status/neighbors | Yes |
| Status | /status/node | Yes |
| Settings | /config | No (poll on open) |
| Keys | /keys | No (poll on open) |

New messages, position updates, peer changes, and status changes are
pushed via Observe notifications. The UI reacts; it never polls in a loop.

#### 17.8.9. Message Compose

Compose adapts to input capability:

| Surface | Input method |
|---------|-------------|
| E-ink (3 button) | Canned messages (§18.1.3) + T9-style character picker |
| Phone | Full keyboard |
| TUI | Full keyboard |
| Web | Full keyboard |

E-ink compose flow:
1. Select "New" from Messages screen
2. Pick recipient (from Peers list or recent conversations)
3. Choose: Canned message (fast, one button cycle) or Free text (T9)
4. Confirm and send
5. Screen shows "⏳ Sending..." then updates to "✓ Sent" on custody ACK

Canned messages are the 80% case for e-ink. Free text is available but
slow. Phone/TUI/web always use free text with canned as shortcuts.

---

[← Previous: Implementation](10-implementation.md) | [Index](README.md) | [Next: Applications →](12-apps.md)
