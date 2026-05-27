<!-- Part of LICHEN Protocol Specification -->

# Routing

## 7. Routing Overview

### 7.1. Three-Tier Architecture

LICHEN uses a three-tier routing architecture optimized for different traffic patterns:

| Tier | Protocol | Traffic Type | Mechanism |
|------|----------|--------------|-----------|
| 1 | **RPL** | Border router ↔ mesh | Proactive DODAG tree |
| 2 | **Announce** | Peer-to-peer (active nodes) | Proactive gradient |
| 3 | **LOADng** | Peer-to-peer (fallback) | Reactive discovery |

**Rationale:**

- **RPL** excels at tree-shaped traffic (sensor → gateway → cloud). Most IoT traffic fits this pattern.

- **Announce routing** provides instant peer-to-peer paths for active mesh participants. Nodes that announce are immediately reachable via gradient following. No discovery latency.

- **LOADng** handles edge cases: new nodes, nodes that missed announces, or rarely-contacted destinations. Reactive discovery when gradient doesn't exist.

### 7.2. Routing Decision

```
def route_packet(dst):
    if is_off_mesh(dst):
        # External destination (GUA not in mesh, or unknown)
        return forward_to_rpl_parent()

    gradient = gradient_table.lookup(dst)
    if gradient and not gradient.expired:
        # Known peer - follow gradient
        return forward_to(gradient.next_hop)

    else:
        # Unknown peer - reactive discovery
        loadng_discover(dst)
        return queue_pending(dst, packet)
```

**Address classification:**

| Address Type | Classification | Routing |
|--------------|----------------|---------|
| Link-local (fe80::/10) | Direct neighbor | Send to neighbor |
| ULA (fd00::/8) in mesh prefix | Mesh peer | Gradient or LOADng |
| GUA in mesh prefix | Mesh peer | Gradient or LOADng |
| Other GUA | Off-mesh | RPL to border router |
| Unknown | Off-mesh | RPL to border router |

---

## 8. RPL (Border Router Traffic)

### 8.1. Purpose

RPL (RFC 6550) handles traffic to and from border routers:
- **Upward:** Mesh nodes → Border router → Internet
- **Downward:** Internet → Border router → Mesh nodes (source routed)

RPL is NOT used for peer-to-peer mesh traffic (see Sections 9-10).

### 8.2. DODAG Topology

```
                    [Border Router]
                    (DODAG Root)
                         |
              +----------+----------+
              |                     |
          [Router 1]            [Router 2]
              |                     |
        +-----+-----+         +-----+-----+
        |           |         |           |
    [Node A]    [Node B]  [Node C]    [Node D]
```

### 8.3. Configuration

| Parameter | Value |
|-----------|-------|
| Mode | Non-storing (MOP=1) |
| Objective Function | MRHOF with ETX |
| Trickle Imin | 4 sec |
| Trickle Imax | 17 min |

See Appendix B for full RPL configuration.

### 8.4. Control Messages

| Message | Purpose |
|---------|---------|
| DIO | DODAG advertisement (downward flood) |
| DIS | Solicit DIO (join request) |
| DAO | Route advertisement to root |
| DAO-ACK | Confirm DAO receipt |

### 8.5. Downward Routing

Non-storing mode: root inserts Source Routing Header (6LoRH) for downward packets.

---

## 9. Announce Routing (Peer-to-Peer Primary)

### 9.1. Purpose

Announce routing provides zero-latency peer-to-peer paths for active mesh participants. Nodes periodically broadcast signed announcements; other nodes build gradients toward announcers.

**Key insight:** Most peer-to-peer traffic is between nodes that are actively participating in the mesh. These nodes announce regularly. No discovery needed.

### 9.2. Announce Message

Nodes broadcast announces periodically:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=ANN  | Flags     | Hop Count   | Seq Num               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator IID (8 bytes)                   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Public Key (32 bytes)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature (48 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Optional: App Data (variable)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Total: ~92 bytes minimum.

**Fields:**
- **Type:** Announce message identifier
- **Flags:** Reserved
- **Hop Count:** Incremented at each relay
- **Seq Num:** Monotonic, detects duplicates and freshness
- **Originator IID:** 8-byte Interface Identifier of announcer
- **Public Key:** Ed25519 public key (32 bytes)
- **Signature:** Schnorr signature over (IID, pubkey, seq, app_data)
- **App Data:** Optional application data (node name, capabilities, etc.)

### 9.3. Announce Processing

**On receive announce:**

```
def process_announce(announce, from_neighbor):
    # Verify signature
    if not verify_schnorr(announce.pubkey, announce.signature, announce.signed_data):
        drop("invalid signature")
        return

    # Check for duplicate/old
    existing = gradient_table.get(announce.originator)
    if existing and existing.seq_num >= announce.seq_num:
        drop("stale announce")
        return

    # Install/update gradient
    gradient_table.update(
        destination=announce.originator,
        next_hop=from_neighbor,
        hop_count=announce.hop_count,
        seq_num=announce.seq_num,
        source="announce",
        expires=now() + GRADIENT_TIMEOUT
    )

    # Forward if hop count allows
    if announce.hop_count < MAX_ANNOUNCE_HOPS:
        announce.hop_count += 1
        broadcast(announce)
```

### 9.4. Announce Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| ANNOUNCE_INTERVAL | 300 sec | Time between announces |
| MAX_ANNOUNCE_HOPS | 15 | Maximum propagation |
| GRADIENT_TIMEOUT | 600 sec | 2× announce interval |
| ANNOUNCE_JITTER | 0-30 sec | Random delay to prevent collision |

### 9.5. Bandwidth Budget

For a 20-node mesh:
- 20 nodes × 92 bytes × 12 announces/hr = 22 KB/hr
- At SF10/125kHz: ~15 seconds airtime/hr network-wide
- ~0.04% of 1% duty cycle

Acceptable overhead for instant peer-to-peer routing.

### 9.6. Security

Announces are self-authenticating:
1. Signature proves sender holds private key for pubkey
2. TOFU binding associates pubkey with IID
3. Cannot forge announce for another node's address

First announce from a new node establishes TOFU binding.

---

## 10. LOADng (Peer-to-Peer Fallback)

### 10.1. Purpose

LOADng provides reactive route discovery when no gradient exists:
- New nodes not yet heard announcing
- Nodes that stopped announcing (sleeping, failed)
- First contact before any announce received

### 10.2. When LOADng is Used

```
if gradient_table.lookup(dst) returns None or expired:
    initiate LOADng discovery
```

### 10.3. Route Request (RREQ)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=RREQ | Flags     | Hop Limit   | Seq Num               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator Address (16 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address (16 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature (48 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

RREQ is flooded. Each node:
1. If I am destination → send RREP
2. If I have gradient to destination → send RREP (intermediate reply)
3. If seen before (originator + seq) → drop
4. Otherwise → record reverse gradient, decrement hop limit, rebroadcast

### 10.4. Route Reply (RREP)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Type=RREP | Flags     | Hop Count   | Seq Num               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator Address (16 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address (16 bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Signature (48 bytes)                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

RREP follows reverse path. Each hop installs forward gradient.

### 10.5. Gradient Unification

RREP installs the same gradient entry as announces:

```
gradient_table.update(
    destination=rrep.destination,
    next_hop=from_neighbor,
    hop_count=rrep.hop_count,
    source="rrep",  # different source, same table
    expires=now() + GRADIENT_TIMEOUT
)
```

Once discovered, the destination is in gradient table. Future traffic uses gradient, not LOADng.

### 10.6. Route Error (RERR)

When link fails, send RERR toward affected sources. Recipients invalidate gradient entries through broken link.

### 10.7. Parameters

| Parameter | Value |
|-----------|-------|
| RREQ_WAIT_TIME | 5 sec |
| RREQ_RETRIES | 3 |
| INITIAL_HOP_LIMIT | 4 (expanding ring) |
| MAX_HOP_LIMIT | 15 |

See Appendix B2 for full LOADng configuration.

---

## 11. Gradient Table

### 11.1. Unified Structure

All routing methods populate a single gradient table:

```
GradientEntry:
    destination: IID or IPv6Address
    next_hop: link-local address of neighbor
    hop_count: distance in hops
    seq_num: for freshness comparison
    source: "announce" | "rrep" | "data" | "rpl"
    expires: timestamp
```

### 11.2. Passive Learning

Forwarding nodes can learn gradients from data traffic:

```
on_forward_packet(packet, from_neighbor):
    # I just received a packet FROM this source
    # Therefore, to REACH this source, send to from_neighbor
    gradient_table.update(
        destination=packet.source,
        next_hop=from_neighbor,
        source="data",
        expires=now() + DATA_GRADIENT_TIMEOUT
    )
```

DATA_GRADIENT_TIMEOUT is shorter (60 sec) since it's opportunistic.

### 11.3. Entry Priority

When multiple sources provide gradient for same destination:

| Source | Priority | Rationale |
|--------|----------|-----------|
| announce | High | Explicitly advertised, fresh |
| rrep | High | Explicitly discovered |
| data | Low | Opportunistic, may be stale |

Higher priority entry replaces lower. Same priority: prefer lower hop count.

---

## 12. Summary

```
                         ┌─────────────────┐
                         │  Border Router  │
                         │   (Internet)    │
                         └────────┬────────┘
                                  │
                            RPL (DODAG)
                          upward/downward
                                  │
┌─────────────────────────────────┴─────────────────────────────────┐
│                                                                    │
│    Node A ◄──────── Gradient ────────► Node B                     │
│       │            (from announces)        │                       │
│       │                                    │                       │
│    Node C ◄─── LOADng (if no gradient) ──► Node D                 │
│                                                                    │
│                      Mesh Interior                                 │
└────────────────────────────────────────────────────────────────────┘
```

| Traffic | Primary | Fallback |
|---------|---------|----------|
| To/from internet | RPL | — |
| Peer (active node) | Announce gradient | LOADng |
| Peer (unknown node) | LOADng | RPL via root (inefficient) |
| Broadcast | Hop-limited flood | — |

The three-tier approach optimizes for each traffic pattern while providing fallbacks for edge cases.

---

[← Previous: Network Layer](04-network.md) | [Index](README.md) | [Next: Security →](06-security.md)
