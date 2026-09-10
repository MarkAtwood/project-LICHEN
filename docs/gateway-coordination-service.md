<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# Gateway Coordination Service Design

**Status:** Design only. This document lives in `docs/`, not `spec/`, because
it describes operational infrastructure, not protocol behavior. Do not
implement from this document — it is a planning artifact, not a specification.

---

## Purpose

LICHEN mesh nodes communicate peer-to-peer over LoRa. No infrastructure
required. Gateways are the optional bridge between meshes and the internet:
they terminate the LoRa side, translate to/from IPv6, and relay traffic to
other gateways or upstream services.

The gateway coordination service is the managed infrastructure that makes
gateways useful without requiring each operator to be a network engineer.
It handles:

- Gateway-to-gateway encrypted tunnels (backhaul)
- NAT traversal (gateways behind home routers just work)
- OTA firmware distribution
- Monitoring and health dashboards
- Multi-mesh routing (traffic between separate LICHEN meshes)

The coordination service is **not** the mesh. Mesh traffic is peer-to-peer.
The coordination service manages the gateways that connect meshes to each
other and to the internet.

---

## Architecture

```
  LoRa Mesh A          LoRa Mesh B          LoRa Mesh C
      |                     |                     |
  [Gateway A]          [Gateway B]          [Gateway C]
      |                     |                     |
      +--- WireGuard -------+--- WireGuard -------+
                            |
                    [Headscale Control]
                            |
                      [DERP Relay(s)]
```

### Components

**Headscale control server:** Open-source Tailscale control plane. Manages
gateway authentication, WireGuard key exchange, ACLs, and routing policy.
Each gateway runs a Tailscale/Headscale client that maintains a WireGuard
tunnel to other gateways. Headscale coordinates who can talk to whom.

**DERP relay(s):** Designated Encrypted Relay for Packets. Headscale's NAT
traversal mechanism. When two gateways can't establish a direct WireGuard
connection (both behind NAT), traffic routes through a DERP relay. The relay
sees encrypted WireGuard packets — it cannot decrypt them.

**Gateway agent:** Runs on each gateway (RPi, etc.). Manages the Headscale
client, reports health telemetry, pulls OTA updates, and translates between
the LoRa mesh (Yggdrasil addresses) and the WireGuard backhaul.

**Dashboard:** Web UI for gateway operators. Shows gateway status, uptime,
traffic volume, mesh statistics (only what the gateway itself can see —
neighbor count, packet rates), and OTA status.

### Address Translation and Cross-Mesh Routing

LICHEN nodes use Yggdrasil `AddrForKey(Ed25519PublicKey)` addresses (`0200::/8`
`/128`s). These addresses are stable and globally unique but are derived from
public keys — they're scattered randomly across the address space and cannot
be aggregated into prefixes. There is no "Gateway B owns `0200:abcd::/64`"
because that's not how the addresses work.

This means cross-mesh routing requires *someone* to know the mapping from a
destination `/128` to the gateway that can reach it. A routing table IS a
node-to-gateway map. This is a fundamental tension between routing efficiency
and privacy.

**Solution: Yggdrasil routing over the WireGuard backhaul.** Gateways run
Yggdrasil peering sessions with each other through the WireGuard tunnels that
Headscale provides. Yggdrasil's spanning-tree routing protocol finds paths to
`/128` addresses using greedy DHT-based routing — no single node holds a
global routing table. Each gateway knows:

- Its own local nodes (unavoidable — it's the RPL DODAG root, it learned
  them via DAO messages)
- Its immediate Yggdrasil peers (other gateways it's connected to)
- A tree coordinate for greedy forwarding

A packet from Mesh A to a node in Mesh B traverses:

1. Node sends IPv6 packet with Yggdrasil source/destination addresses
2. Gateway A receives over LoRa, decapsulates from SCHC
3. Gateway A doesn't have a local route for the destination `/128`
4. Yggdrasil's greedy routing forwards through the gateway overlay to
   Gateway B (which does have that node in its local DODAG)
5. Gateway B encapsulates in SCHC, transmits over LoRa
6. Destination node receives with original Yggdrasil addresses intact

No NAT, no address rewriting. A node's address is the same whether it's on
the local mesh, across a gateway, or across ten gateways. The WireGuard
tunnels carry Yggdrasil-routed IPv6 packets.

**Privacy consequence:** No single point holds the complete node-to-gateway
map. Each gateway knows only its own local nodes. The coordination service
(Headscale) provides WireGuard tunnels but never sees Yggdrasil routing state.
Yggdrasil's tree-based forwarding means intermediate gateways that relay
traffic only see the next hop, not the full path. Compel one gateway and you
get its local DODAG — not the whole network.

---

## Privacy Architecture

**Principle: the coordination service is blind to mesh internals.**

This is an architectural decision, not a policy preference. The service is
designed so that uncomfortable data requests are technically impossible to
fulfill, not merely refused.

### What the coordination service knows

| Data | Stored? | Retention | Why |
|------|---------|-----------|-----|
| Gateway WireGuard public key | Yes | While enrolled | Headscale needs it |
| Gateway IP address | Yes | Current session only | NAT traversal |
| Gateway online/offline state | Yes | Real-time only, no history | Dashboard |
| Traffic volume per gateway | Yes | 30 days, then deleted | Billing |
| Gateway software version | Yes | Current only | OTA targeting |
| Gateway operator identity | Yes | While enrolled | Account management |

### What the coordination service does NOT know

| Data | Why not |
|------|---------|
| Which nodes are behind a gateway | Never reported; routing is Yggdrasil peer-to-peer between gateways |
| Global node-to-gateway map | No single point holds it; Yggdrasil tree routing is distributed |
| Mesh topology | Only visible to participating nodes via RPL |
| Message content | OSCORE end-to-end encrypted; gateways relay ciphertext |
| Node identities | Never leave the mesh or the gateway's local memory |
| Node-to-node communication patterns | Not visible above the WireGuard tunnel (aggregate traffic) |
| OSCORE keys | Negotiated per-pair via EDHOC, never touch the coordination service |

### What individual gateways DO know (honest accounting)

A gateway is a DODAG root. It necessarily knows every node in its local
mesh — nodes register via RPL DAO messages. This is unavoidable: you
cannot route to a node without knowing it exists.

| Data | Known to the gateway | Known to the coordination service |
|------|---------------------|----------------------------------|
| Local node Yggdrasil `/128` addresses | Yes (RPL DAO) | No |
| Local mesh topology (hop counts, relay paths) | Yes (RPL routing table) | No |
| Traffic volume per local node | Yes (it relays the traffic) | No (only aggregate per-gateway) |
| Nodes behind OTHER gateways | No (Yggdrasil greedy routing) | No |
| Message content | No (OSCORE encrypted) | No |

**Compel one gateway → get one mesh's node list.** This is the irreducible
minimum. You cannot route without routing state. The architectural defense
is that no single point holds the *global* map — only the local mesh's
nodes. And the coordination service holds none of it.

### DERP relay privacy

DERP relays see:
- Source and destination gateway WireGuard public keys
- Encrypted packet bytes
- Packet sizes and timing

DERP relays do NOT see:
- Packet content (WireGuard encrypted)
- Which nodes generated the traffic
- Yggdrasil addresses (inside the WireGuard envelope)

**DERP relays do not log.** No packet captures, no connection logs, no
traffic analysis data. The relay holds no persistent state about traffic
that has passed through it.

### Data retention policy

- **Real-time state** (gateway online, current IP): in memory only, not
  persisted to disk, lost on service restart.
- **Billing data** (traffic volume per gateway per day): 30 days, then
  hard-deleted. No archival, no backup retention.
- **Account data** (operator email, payment): retained while account is
  active. Deleted on account closure, 30-day grace period.
- **Audit logs** (admin actions on the control server): 90 days, then
  deleted. No traffic data in audit logs.
- **Everything else:** not collected in the first place.

---

## Lawful Access Posture

The coordination service is designed for a specific legal posture:
**"we don't have it"** is always preferable to **"we'd rather not share."**

- **Content:** Not available. OSCORE end-to-end encryption. The
  coordination service never holds keys and never sees plaintext.
- **Metadata:** Minimized by design. No node-to-gateway mapping, no mesh
  topology, no communication patterns. Gateway connection metadata (IP,
  online/offline, volume) retained 30 days for billing only.
- **CALEA:** Likely not applicable. The coordination service is not a
  telecommunications carrier or facilities-based broadband provider. It
  coordinates gateways; it does not provide the communication path.
  Confirm with counsel before launch.
- **Subpoenas:** Can compel gateway operator account info and 30-day
  connection/volume logs. Cannot compel content (don't have it), node
  identities (don't have them), or mesh topology (don't have it).
- **National Security Letters:** Can compel subscriber info. Same
  limitations apply — can't produce what doesn't exist.

### Warrant canary

Publish a quarterly transparency report and warrant canary. If the canary
disappears, the community knows.

### Architecture is policy

These privacy properties are enforced by system architecture, not by
access controls or employee policies. The data doesn't exist in the
coordination service. There is no admin override, no debug mode, no
"break glass" that reveals mesh internals. A rogue employee, a
compromised server, or a court order all hit the same wall: the data
was never collected.

---

## Service Tiers

| Tier | Price | What's included |
|------|-------|----------------|
| Community | Free | Managed Headscale, NAT traversal, OTA, basic dashboard, community forum |
| Starter | $15/mo/gateway | Everything in Community + priority DERP, traffic analytics, email support |
| Pro | $75/mo/gateway | Everything in Starter + SLA, fleet API, alerting, dedicated DERP, phone support |
| Event | Flat fee | Temporary deployment for conferences/events, includes setup support |

**All tiers run on the same managed Headscale instance.** Community
gateways are not self-hosted islands — they're on the same coordination
network as paying gateways. Every gateway can route to every other
gateway regardless of tier. This is critical: the value of the network
is proportional to its size. Fragmenting free users onto their own
infrastructure would shrink the network and hurt paying customers.

The free tier is real. No time limits, no nag screens, no artificial
degradation. Community gateways get NAT traversal, OTA updates, and
multi-mesh routing. Paid tiers buy better support, SLA guarantees,
analytics, and priority relay infrastructure — not basic connectivity.

The code is still open source. A gateway operator *can* self-host
Headscale if they want to run a private network. But the default is the
managed instance, and the incentive is to stay on it.

---

## OTA Firmware Distribution

The coordination service distributes firmware updates to enrolled gateways.

- Updates are signed with the LICHEN release key (Ed25519). The gateway
  verifies the signature before applying. The coordination service cannot
  push unsigned or tampered firmware.
- Gateway operators can opt out of automatic updates. The dashboard shows
  available versions; the operator chooses when to apply.
- Node firmware (T-Echo, RAK4631) is distributed via the gateway's local
  OTA mechanism, not via the coordination service. The coordination
  service updates gateways; gateways update their local nodes.

---

## Multi-Mesh Routing

When gateways from different meshes are enrolled in the coordination
service, traffic can route between meshes via Yggdrasil peering over the
WireGuard tunnels. See "Address Translation and Cross-Mesh Routing" above
for the full packet flow.

The coordination service does not make routing decisions and does not see
routing state. It provides WireGuard tunnels (connectivity); Yggdrasil
running between gateways handles path selection (routing). Headscale ACLs
control which gateways can peer, but the routing within those peerings is
Yggdrasil's spanning-tree protocol, not a centralized decision.

No gateway needs a global view of all nodes across all meshes. Yggdrasil's
greedy tree routing forwards packets hop-by-hop through the gateway overlay
using tree coordinates, not destination lookup tables. A gateway only needs
to know its local nodes (RPL) and its Yggdrasil peers (other gateways).

---

## Infrastructure Requirements

**Managed service (Starter/Pro):**
- 1 VPS for Headscale control server (2 vCPU, 4 GB RAM handles hundreds
  of gateways)
- 1-3 DERP relays in different regions (1 vCPU, 1 GB RAM each)
- Object storage for OTA firmware images
- Dashboard hosting (static site + API backend on the Headscale VPS)
- Total infrastructure cost: ~$50-150/month

**Marginal cost per gateway:** Near zero. Headscale and DERP scale
linearly and the per-gateway resource consumption is minimal. This is the
highest-margin revenue stream.

---

## What This Service Is Not

- **Not a VPN provider.** It connects gateways, not end users.
- **Not a mesh operator.** The mesh runs independently. The coordination
  service manages backhaul infrastructure.
- **Not a data broker.** It cannot see mesh traffic content and does not
  collect mesh metadata.
- **Not an emergency service.** SOS/911 bridging is a gateway firmware
  capability. The coordination service does not participate in emergency
  call routing.
- **Not required.** LICHEN meshes work without it. Gateways can operate
  standalone or with self-hosted Headscale. The managed service is
  convenience, not dependency.
