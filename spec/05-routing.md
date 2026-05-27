<!-- Part of LICHEN Protocol Specification -->

# Routing

## 7. Routing

### 7.1. Overview

LICHEN uses a **hybrid routing architecture** combining two protocols:

| Protocol | Traffic Type | Mechanism |
|----------|--------------|-----------|
| **RPL** (RFC 6550) | To/from border router | Proactive tree (DODAG) |
| **LOADng** (draft-clausen-lln-loadng) | Mesh-internal peer-to-peer | Reactive on-demand |

**Rationale:**

RPL builds a tree (DODAG) rooted at the border router. This is efficient for:
- Sensor data flowing UP to the border router
- Commands flowing DOWN from the border router

However, RPL is inefficient for peer-to-peer traffic within the mesh. Two
adjacent leaf nodes must route through their common ancestor:

```
        Root
       /    \
      A      B
     /        \
    C          D

C → D via RPL: C → A → Root → B → D (4 hops)
C → D direct:  C → D                 (1 hop, if in range)
```

At LoRa data rates with 1% duty cycle, wasting 4× the airtime is unacceptable.

LOADng provides reactive routing for peer-to-peer traffic, discovering efficient
paths on demand rather than forcing traffic through the DODAG tree.

### 7.2. Routing Decision

When a node needs to send a packet:

```
if dst is link-local (fe80::/10):
    send directly to neighbor (one hop)

elif dst is mesh-local (ULA fd00::/8 or mesh GUA):
    # Peer-to-peer: use LOADng
    route = loadng_cache.lookup(dst)
    if route exists:
        forward via route.next_hop
    else:
        queue packet
        initiate LOADng route discovery (RREQ)

else:
    # External destination: use RPL toward border router
    forward to rpl_preferred_parent
```

**Fallback:** If LOADng route discovery fails after timeout, the packet MAY
be sent via RPL through the root as a last resort. This is inefficient but
ensures eventual delivery if a path exists.

---

## 8. RPL (Border Router Traffic)

### 8.1. Purpose

RPL (RFC 6550) handles traffic to and from the border router:
- Upward: Mesh nodes → Border router → Internet
- Downward: Internet → Border router → Mesh nodes (via source routing)

### 8.2. Topology

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

All nodes maintain a path toward the root (upward route). The root maintains
paths to all nodes (downward routes via DAO).

### 8.3. Control Messages

| Message | ICMPv6 Code | Direction | Purpose |
|---------|-------------|-----------|---------|
| DIO | 0x9B, 0x01 | Downward | DODAG Information Object |
| DIS | 0x9B, 0x00 | Upward | DODAG Information Solicitation |
| DAO | 0x9B, 0x02 | Upward | Destination Advertisement Object |
| DAO-ACK | 0x9B, 0x03 | Downward | DAO acknowledgment |

### 8.4. DIO (DODAG Information Object)

Broadcast by routers to advertise DODAG membership:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   RPLInstanceID   |    Version    |            Rank           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|G|0|MOP|Prf|           DTSN            |     Flags     | Res   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                          DODAGID                              +
|                       (128 bits)                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Options                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 8.5. Objective Function

**MRHOF with ETX (RFC 6719):** Minimize expected transmissions.

Recommended for LoRa because link quality varies significantly with distance,
obstacles, and interference.

### 8.6. Rank Calculation

```
Rank(N) = Rank(Parent) + RankIncrease
RankIncrease = (ETX * MinHopRankIncrease) / 128
```

Default MinHopRankIncrease: 256

### 8.7. Trickle Timer

DIO transmissions follow Trickle algorithm (RFC 6206):

| Parameter | Value | Description |
|-----------|-------|-------------|
| Imin | 2^12 ms (~4 sec) | Minimum interval |
| Imax | 2^20 ms (~17 min) | Maximum interval |
| k | 10 | Redundancy constant |

### 8.8. Non-Storing Mode

LICHEN uses **non-storing mode** exclusively:

- Leaf nodes send DAOs to the DODAG root (not to their parent)
- Root maintains routing table for entire mesh
- Downward traffic uses source routing (6LoRH, RFC 8138)

**Rationale:** Non-storing mode minimizes memory requirements on constrained
leaf nodes. Only the root (typically a border router with more resources)
needs to store the full routing table.

### 8.9. Downward Routes (Source Routing)

For downward traffic, the root inserts a Source Routing Header (6LoRH):

```
+--------+--------+--------+--------+
| 6LoRH  | Hop 1  | Hop 2  | Hop 3  |
+--------+--------+--------+--------+
   1B      2B       2B       2B
```

Compressed addresses (16-bit short addresses) minimize overhead.

### 8.10. Loop Avoidance

- Rank must strictly increase toward leaves
- Data-path validation via RPL Packet Information (RPI)
- Inconsistency detection triggers local repair

---

## 9. LOADng (Peer-to-Peer Traffic)

### 9.1. Purpose

LOADng (Lightweight Ad hoc On-Demand - Next Generation) provides reactive
routing for mesh-internal peer-to-peer traffic:

- Node-to-node messaging
- Position sharing between peers
- SOS alerts to nearby nodes
- Any traffic where both endpoints are within the mesh

### 9.2. Protocol Overview

LOADng is a simplified reactive routing protocol based on AODV:

1. **Route Discovery:** When a route is needed, flood a Route Request (RREQ)
2. **Route Reply:** Destination (or intermediate with route) sends RREP back
3. **Route Maintenance:** Route Error (RERR) when link breaks
4. **Route Cache:** Discovered routes cached with timeout

### 9.3. Control Messages

| Message | Purpose |
|---------|---------|
| RREQ | Route Request - flooded to discover route |
| RREP | Route Reply - unicast back to originator |
| RERR | Route Error - notify of broken link |
| RACK | Route Acknowledgment (optional) |

All LOADng messages are carried as ICMPv6 (type TBD, allocated from experimental range).

### 9.4. Route Request (RREQ)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Msg Type| Hop Limit | Seq Num       | Metric        | Flags   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator Address                         |
|                         (128 bits)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
|                         (128 bits)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Flooding:** RREQ is broadcast with Hop Limit. Each node:
1. Checks if it has route to destination → send RREP
2. Checks if RREQ already seen (by originator + seq) → drop
3. Decrements Hop Limit, rebroadcasts if > 0
4. Records reverse route to originator

### 9.5. Route Reply (RREP)

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Msg Type| Hop Count | Seq Num       | Metric        | Flags   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Originator Address                         |
|                         (128 bits)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Destination Address                        |
|                         (128 bits)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

**Unicast:** RREP follows reverse path recorded during RREQ flooding.

### 9.6. Route Cache

Each node maintains a route cache:

```
Route Entry:
  destination: IPv6 address
  next_hop: IPv6 address (link-local)
  hop_count: number of hops
  metric: path cost
  seq_num: destination sequence number
  valid_until: expiration timestamp
```

**Cache size:** 32 entries (configurable). LRU eviction when full.

**Timeout:** Routes expire after 5 minutes of inactivity. Active routes
(recently used) are refreshed.

### 9.7. Route Error (RERR)

When a link breaks (transmission failure detected), send RERR toward
affected originators:

```
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Msg Type| Flags     | Error Code    | Reserved                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Unreachable Address                        |
|                         (128 bits)                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

Nodes receiving RERR invalidate cached routes through the broken link.

### 9.8. Interaction with RPL

LOADng and RPL coexist on the same nodes:

| Aspect | RPL | LOADng |
|--------|-----|--------|
| Routes to | Border router | Mesh peers |
| Mechanism | Proactive tree | Reactive discovery |
| State | DODAG, parent | Route cache |
| Control traffic | DIO/DAO (Trickle-controlled) | RREQ/RREP (on-demand) |

**No conflict:** They serve different traffic patterns and maintain separate
routing state.

### 9.9. Optimizations for LoRa

**RREQ suppression:** If a node recently forwarded an RREQ for the same
(originator, destination, seq), suppress duplicates (jitter helps).

**Gratuitous RREP:** Intermediate nodes with fresh routes MAY respond to
RREQ without forwarding, reducing flood scope.

**Expanding ring search:** Start RREQ with low Hop Limit (2), increase if
no RREP. Limits flood for nearby destinations.

**Piggyback on data:** Route refresh can piggyback on data packets to
avoid separate control messages.

---

## 10. Summary

| Traffic Type | Protocol | Discovery | Path |
|--------------|----------|-----------|------|
| To border router | RPL | Proactive (DIO) | DODAG upward |
| From border router | RPL | Proactive (DAO) | Source routed |
| Peer-to-peer in mesh | LOADng | Reactive (RREQ/RREP) | Cached route |
| Broadcast/multicast | Hop-limited flood | N/A | Scoped flood |

The hybrid approach optimizes for both traffic patterns:
- RPL's tree is efficient for the common case (sensor data to cloud)
- LOADng's reactive discovery is efficient for the important case (peer chat)

---

[← Previous: Network Layer](04-network.md) | [Index](README.md) | [Next: Security →](06-security.md)
