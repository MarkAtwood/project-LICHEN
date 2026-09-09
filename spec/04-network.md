<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

<!-- Part of LICHEN Protocol Specification -->

# Network Layer

## 6. Network Layer

### 6.1. IPv6 Addressing

**Design Principles:**
- Isolated meshes (no border router) MUST work
- Multiple border routers MUST be tolerated
- No central address authority required

**Address Types:**

| Type | Prefix | Availability | Purpose |
|------|--------|--------------|---------|
| Link-local | fe80::/10 | After `lichen_link_init()` | Control traffic only (NDP, RPL control, neighbor discovery) |
| Primary (upstream Yggdrasil) | 0200::/8 | Always (upstream `AddrForKey` of Ed25519 pubkey) | All routable traffic (mesh, inter-mesh, BR forwarding). Cryptographically bound to key per 06-security.md §8.5 |

All addresses derive from the Ed25519 public key with no additional secrets: the link-local IID uses the SHA-512 profile of 03-addressing.md, and the primary address equals upstream `AddrForKey` (06-security.md §8.5, `upstream-yggdrasil-addressing` decision in `spec/decisions.jsonl`, pinned oracle `test/vectors/yggdrasil_address.json#upstream_addr_for_key`). This provides cryptographic identity binding: every address is recomputable from the presented key. Link-local restricted to post-`lichen_link_init()` per AGENTS.md initialization graph. Single-primary model eliminates ULA/GUA layering, scope selection bugs, and prefix advertisement complexity while preserving isolated-mesh and multi-BR behavior via Yggdrasil.

**Isolated Meshes (No BR):**

Mesh self-organizes without infrastructure. Nodes derive primary 02xx address independently from their Ed25519 key (no prefix advertisement needed). Root election (lowest EUI-64) establishes RPL DODAG for control and routing using primary addresses. Full peer-to-peer, announce, LOADng, and application functionality works offline.

**Root Election, Failure, Demotion:**

Unchanged mechanics (lowest EUI-64 deterministic election, DIO monitoring, >50% vote demotion with Schnorr-signed DEMOTION_REQUEST). Root no longer generates/advertises ULA prefix. Demotion limitations and protocol remain as documented above (EUI-64 gaming requires hardware compromise; Byzantine threshold applies).

**Multiple Border Routers & Yggdrasil:**

BRs attach LICHEN meshes to Yggdrasil overlay using nodes' upstream-derived 02xx addresses. 

- Local traffic stays on LoRa (RPL/gradient/LOADng on primary addresses)
- Off-mesh 02xx traffic forwards to BR Yggdrasil TUN
- Yggdrasil provides global routing tree connecting meshes without coordination between BRs
- Multi-BR redundancy via Yggdrasil anycast/failover

**LICHEN-on-Yggdrasil Tree Metaphor (P4):**

```
               Yggdrasil Global Backbone (trunk)
                       /          |          \
               LICHEN-MeshA     LICHEN-MeshB    Internet
                 (BR1)            (BR2)
                       \          /
                        LICHEN-MeshC (multi-BR)
```

Each LICHEN LoRa mesh is a leaf cluster. Primary 02xx addresses enable seamless end-to-end IPv6 across the tree. See parent epic project-LICHEN-zt3c for full diagram.

### 6.2. Interface Identifier (IID) Derivation

IID and primary 02xx address are both derived from the Ed25519 public key, but by different functions: the IID uses the LICHEN SHA-512 profile below (link-local use only), while the routable address MUST equal upstream Yggdrasil `AddrForKey(pubkey)` per 06-security.md §8.5 and the `upstream-yggdrasil-addressing` decision in `spec/decisions.jsonl` (MUST match the pinned upstream test vectors byte-for-byte; see also 03-addressing.md:12-18, draft-lichen-schnorr-00, rust/lichen-core/src/addr.rs:86-117 (`iid_from_pubkey_bytes` for the IID; `ygg_addr_from_pubkey` and Python `yggdrasil_address` are the legacy native profile pending migration, not the upstream oracle), python/src/lichen/crypto/identity.py):

```
// IID (8 bytes, link-local fe80::/10 address only)
hash512 = SHA-512(pubkey)
IID = hash512[0:8]
IID[0] &= 0b11111101                      // clear U/L bit (RFC 4291)

// Primary 02xx address (16 bytes, all routable traffic)
// Upstream yggdrasil-go AddrForKey (src/address/address.go @ 422836ee):
key_inv = ~pubkey                         // bit-invert the 32-byte public key
addr[0] = 0x02                            // 0200::/8 node /128 prefix
addr[1] = count_leading_1_bits(key_inv)   // no hashing anywhere
addr[2..16] = next 112 bits of key_inv after dropping the
              leading 1s and the first 0 bit (zero-padded tail)
```

The upstream algorithm bit-packs the inverted public key and involves no hashing, so the SHA-512 IID does NOT appear in the routable address; implementations MUST NOT substitute the IID into its lower 64 bits. Routed `/64` subnets, when used, MUST equal upstream `SubnetForKey` in `0300::/8`; `0200::/7` is the aggregate covering both. The independent conformance oracle is the pinned `upstream_addr_for_key` vector in `test/vectors/yggdrasil_address.json`; LICHEN-native fixtures do not authorize divergence.

**Stable cryptographic IIDs only.** The IID binds the IPv6 address to the Ed25519 keypair used for signatures and OSCORE (no new key material). Temporary (RFC 4941) and opaque (RFC 7217) IIDs MUST NOT be used. See 06-security.md §8.7 for full analysis and privacy considerations. Short address derivation for 6LoWPAN remains compatible but defers to the key-derived IID for identity.

### 6.3. Multicast and Broadcast

#### 6.3.1. Multicast Scopes

IPv6 multicast addresses encode scope in bits 8-11:

| Scope | Value | Address Prefix | Meaning |
|-------|-------|----------------|---------|
| Interface-local | 1 | ff01:: | Loopback only |
| Link-local | 2 | ff02:: | Single hop (direct neighbors) |
| Mesh-local | 3 | ff03:: | Within DODAG (LICHEN extension) |
| Site-local | 5 | ff05:: | Administrative domain |
| Global | 14 | ff0e:: | Internet-wide |

**Standard multicast groups:**

| Address | Scope | Usage |
|---------|-------|-------|
| ff02::1 | Link-local | All nodes (1 hop) |
| ff02::1a | Link-local | All RPL nodes (1 hop) |
| ff02::2 | Link-local | All routers (1 hop) |
| ff03::1 | Mesh-local | All nodes (entire mesh) |
| ff03::fc | Mesh-local | All LICHEN nodes |

#### 6.3.2. Hop-Limited Broadcast

For scoped flooding without full multicast routing, use **Hop Limit**:

| Hop Limit | Reach | Use Case |
|-----------|-------|----------|
| 1 | Direct neighbors | Discovery, link probing |
| 2 | 2 hops | Local announcement |
| 3-4 | Small cluster | Team coordination |
| 5-7 | Mesh diameter | Mesh-wide alert |
| 255 | Unlimited | Flood (bounded by topology) |

**How it works:**

1. Sender sets Hop Limit (e.g., 4)
2. Sender broadcasts to ff03::1 (mesh-local all nodes)
3. Each relay:
   - Receives packet
   - MUST preserve the original IPv6 source address end-to-end (required by §6.3.3 relay accounting)
   - Decrements Hop Limit
   - If Hop Limit > 0: rebroadcast
   - If Hop Limit = 0: consume locally, don't relay

No routing table consulted. Purely local decision at each hop.

#### 6.3.3. Broadcast Rate Limiting

Broadcasts are expensive -- each packet is relayed by every node in range.
Without limits, a single node can flood the network.

**Distributed rate limiting (no central authority):**

Each node tracks broadcasts it relays, per sender:

```
Broadcast Relay State:
  sender_addr: <full 16-byte primary 0200::/8 /128 of original sender>
  hop_bucket[1-7]: <count in rolling 1-hour window>
  last_seen: <timestamp>
```

The relay key is the full primary source address, not the IID: the routable
/128 is upstream `AddrForKey` and embeds no IID (§6.2), and relays MUST
preserve the original IPv6 source end-to-end (§6.3.2), so the key is present
at every hop. Keying on 128 bits strengthens collision resistance over the
64-bit IID; the key is not authenticated end-to-end for broadcast traffic
(link-layer signatures are per-hop), so spoofed-source budget exhaustion
remains a radio-adversary ceiling.

**Hop-aware budgets:**

Higher Hop Limit = larger blast radius = stricter limit:

| Hop Limit | Budget (per sender per hour) | Rationale |
|-----------|------------------------------|-----------|
| 1 | 200 | Neighbors only, low impact |
| 2 | 100 | Small radius |
| 3-4 | 30 | Medium radius |
| 5-7 | 10 | Mesh-wide, expensive |
| SOS (any) | 3 | Emergency, always relay once |

**Relay decision:**

```
on_receive_broadcast(packet):
  sender = packet.source_addr  # full primary /128, preserved end-to-end
  hl = packet.hop_limit

  if sender not in relay_state:
    relay_state[sender] = new_entry()

  budget = get_budget(hl)
  count = relay_state[sender].hop_bucket[hl]

  if count >= budget:
    drop(packet)  # sender exceeded budget
    return

  if count >= budget * 0.5:
    # Probabilistic relay in yellow zone
    if random() > 0.5:
      drop(packet)
      return

  relay_state[sender].hop_bucket[hl] += 1
  decrement_hop_limit(packet)

  if packet.hop_limit > 0:
    rebroadcast(packet)
```

**Properties:**

- **No coordination:** Each node enforces independently
- **No network map:** Only local state per sender
- **Spammers isolated:** Immediate neighbors stop relaying
- **Graceful degradation:** Probabilistic relay in yellow zone
- **Memory bounded:** Expire old entries after 2 hours idle

**State size:**

Per-sender entry: ~27 bytes (16-byte address + 7 bucket counters + timestamp)
At 100 active senders: ~2.7 KB

#### 6.3.4. Border Router Multicast Filtering

Border routers MUST NOT forward mesh multicasts to the internet:

| Direction | Unicast | Multicast |
|-----------|---------|-----------|
| Mesh → Internet | Forward (route normally) | **Drop** |
| Internet → Mesh | Forward (route normally) | **Drop** (unless explicit config) |

Rationale:
- Mesh broadcasts are not meaningful globally
- Prevents accidental flood amplification
- Protects mesh from external multicast storms

**Exception:** Explicitly configured multicast peering between meshes
(future work -- requires multicast routing protocol like PIM).

#### 6.3.5. Forwarding-Plane Endpoint Policy (Martian Filtering)

Rule 255 reception (Adaptation profile, Section 5.5) is byte-preserving: a
structurally valid packet is accepted at link intake even when its endpoint
addresses violate the emission policy, so the two implementation families
stay interoperable. Endpoint address policy therefore attaches to packet
origination (an emission constraint, enforced at encode time) and to the
forwarding decision, which every router MUST apply before relaying a packet
whose destination is not this node:

| Endpoint | Policy-invalid values |
|----------|----------------------|
| Source | Unspecified (`::`), loopback (`::1`), multicast (`ff00::/8`), IPv4-mapped (`::ffff:0:0/96`) |
| Destination | Unspecified (`::`), loopback (`::1`), IPv4-mapped (`::ffff:0:0/96`), multicast with scope outside 2-14 |

A router MUST NOT forward a packet whose source or destination is
policy-invalid under this table. The packet is dropped at the forwarding
decision and reported locally (log/counter); a router MUST NOT transmit a
protocol error (ICMPv6 or otherwise) about the rejection onto the mesh,
because the packet never entered the local stack and echoing policy
failures would amplify the traffic the filter exists to contain.

Structural validation keeps precedence over policy, mirroring the
error-precedence rule of the Adaptation profile: a packet that fails
header, length, or checksum validation is dropped as malformed at intake
regardless of its endpoint addresses; the policy check above applies only
to packets that are structurally valid. Policy-invalid packets destined to
this node are delivered to the local stack, which reports them locally and
MUST NOT re-transmit them, so an originator can learn its own
emission-policy violations without the mesh amplifying them.

### 6.4. ICMPv6

Standard ICMPv6 (RFC 4443) for:
- Echo Request/Reply (ping)
- Destination Unreachable
- Packet Too Big
- RPL control messages (see Section 7)

---

## 12. Addressing

### 12.1. Address Structure

See Section 6.1 for single-primary model (Ed25519 derivation per 06-security.md §8.5 and the `upstream-yggdrasil-addressing` decision in `spec/decisions.jsonl`). Summary:

```
Link-local:  fe80::<IID>                                  (control only)
Primary:     AddrForKey(pubkey)                           (upstream 0200::/8 /128, all routable traffic)
```

IID (SHA-512 profile) and the primary 02xx address derive from the same Ed25519 pubkey but are independent byte strings: the upstream address bit-packs the inverted key and does NOT embed the IID. Routed /64 subnets, when used, equal upstream `SubnetForKey` in `0300::/8`. No ULA or layered GUA model (see 06-security.md).

### 12.2. Example Addresses

| Type | Example | Routable To |
|------|---------|-------------|
| Link-local | fe80::c02:a502:25b4:baaa | Direct neighbors (control) |
| Primary (02xx) | 200:848a:604f:bb7e:4384:65db:8db6:6895 | Mesh, inter-mesh via Yggdrasil, internet |

The link-local example uses the canonical `rfc8032_test_public_key` vector from
`test/vectors/ipv6-addresses.json`: IID = `SHA-512(pubkey)[0:8]` with the U/L
bit cleared (`0c02a50225b4baaa`), link-local = `fe80::` + IID. The primary
example is the pinned upstream Go `AddrForKey` reference vector from
`test/vectors/yggdrasil_address.json` (`upstream_addr_for_key`, public key
`bdbacfd82240de3dcd123924cbb55256fb8dab08aa98e305528ab84f419e6efb`); its bytes
bit-pack the inverted key and contain no IID. The two rows derive from
different keys and illustrate each address form; they are not one node's
address pair. Node uses link-local for control
+ single primary 02xx for everything else. Consistent with updated
05-routing.md and 06-security.md. Matches the pinned upstream test vectors.

### 12.3. Short Address Assignment

16-bit short addresses optimise link-layer addressing and SCHC rule targets
(2 bytes vs 8). The addressing mode field of the link-layer frame selects
16-bit mode via `Addr Mode` value `1` (see `02-physical-link.md:215`).

Assignment methods (no central authority required):
1. **Derived from IID (Ed25519-derived):** `crc32_ieee(EUI-64, key=0x4c494348454e)` truncated to 16 bits (CRC32-IEEE with initial value derived from ASCII "LICHEN"); DAD retry uses seed mixing per `02-physical-link.md:172`
2. **Self-assigned + DAD:** Pick random, verify uniqueness via DAD
3. **DODAG root assignment:** Root allocates from pool (optional optimisation)

Collision resolution: If DAD detects duplicate, regenerate and retry.

Short addresses are mesh-local; they compress the IID for link-layer
forwarding efficiency but the full key-derived IID remains the stable
link-local identifier for security (key binding per 06-security). Because the
routable /128 is upstream `AddrForKey` and embeds no IID (§6.2), a short
address can stand in only for the link-local IID, never for the primary
address.

---

[← Previous: Adaptation Layer](03-adaptation.md) | [Index](README.md) | [Next: Routing →](05-routing.md)
