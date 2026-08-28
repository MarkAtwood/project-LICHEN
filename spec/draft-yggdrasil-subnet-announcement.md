# Yggdrasil Subnet Announcement Extension (DRAFT)

**Status:** Sketch for discussion  
**Author:** LICHEN project  
**Problem:** Gateways serving mesh networks need to announce reachability for nodes behind them without holding their private keys.

## 1. Problem Statement

Standard Yggdrasil: each node has one /128 derived from its Ed25519 key. No mechanism exists for a gateway to announce "I can reach these N addresses."

Attack surface:
- Route hijacking: attacker claims to be gateway for victim's address
- Black hole: malicious gateway announces but drops traffic
- Replay: old announcements used after gateway goes offline

## 2. Design Goals

1. **Cryptographic authorization**: Gateway proves it's authorized to announce
2. **Delegation from address owners**: Only the key owner can authorize a gateway
3. **Revocable**: Delegations expire or can be revoked
4. **Multi-gateway**: Multiple gateways can serve same subnet (redundancy)
5. **Minimal state**: Verifiers don't need per-address state

## 3. Proposed Mechanism

### 3.1 Delegation Certificate

A mesh node delegates routing authority to a gateway by signing:

```
DelegationCert {
    version:        u8 = 1
    delegator:      [u8; 32]      // mesh node's Ed25519 pubkey (address owner)
    delegate:       [u8; 32]      // gateway's Ed25519 pubkey
    valid_from:     u64           // Unix timestamp
    valid_until:    u64           // Unix timestamp (max 30 days recommended)
    flags:          u8            // 0x01 = revocable, 0x02 = re-delegatable
    signature:      [u8; 64]      // Ed25519 signature by delegator
}
```

**Signature covers:** `version || delegator || delegate || valid_from || valid_until || flags`

### 3.2 Subnet Announcement Message

Gateway announces reachability by broadcasting:

```
SubnetAnnouncement {
    version:        u8 = 1
    gateway:        [u8; 32]      // gateway's Ed25519 pubkey
    timestamp:      u64           // current time (replay protection)
    ttl:            u16           // seconds until re-announcement required
    cert_count:     u16           // number of delegation certs
    certs:          [DelegationCert; N]  // bundled delegations
    gateway_sig:    [u8; 64]      // gateway signs the announcement
}
```

**Verification:**
1. Check `gateway_sig` valid for announcement body
2. For each cert: verify `delegator` signed delegation to `gateway`
3. Check `valid_from <= now <= valid_until`
4. Derive address from each `delegator` pubkey
5. Install routes: those addresses reachable via `gateway`

### 3.3 Aggregation (Scalability)

For large meshes (1000+ nodes), individual certs are expensive. Two options:

**Option A: Merkle tree**
```
AggregatedAnnouncement {
    gateway:        [u8; 32]
    merkle_root:    [u8; 32]      // root of tree of delegator pubkeys
    tree_size:      u32           // total delegators
    proof_sample:   [MerkleProof; K]  // K random inclusion proofs
    gateway_sig:    [u8; 64]
}
```
Verifiers check K random proofs. Probabilistic but scales to millions.

**Option B: Subnet key (LICHEN-specific)**

LICHEN meshes could have a "mesh root key" that delegates to all nodes:
```
MeshDelegation {
    mesh_root:      [u8; 32]      // mesh root pubkey (well-known)
    gateway:        [u8; 32]
    prefix:         [u8; 16]      // e.g., 0200:1234::/32
    prefix_len:     u8
    valid_until:    u64
    root_sig:       [u8; 64]      // signed by mesh_root
}
```
Single signature covers entire prefix. Mesh root key is governance decision.

## 4. Revocation

### 4.1 Explicit Revocation

Delegator broadcasts:
```
Revocation {
    delegator:      [u8; 32]
    delegate:       [u8; 32]      // gateway being revoked
    revoked_at:     u64
    signature:      [u8; 64]
}
```

### 4.2 Implicit Expiry

Delegations have `valid_until`. Gateway must refresh announcements with fresh certs. Nodes should re-delegate periodically (e.g., weekly).

### 4.3 Revocation Distribution

Problem: how do verifiers learn of revocations?

Options:
- Gossip revocations through Yggdrasil network
- Short cert lifetimes (hours) so revocation = don't re-delegate
- CRL at well-known endpoint (centralization concern)

**Recommended:** Short lifetimes (24-48 hours) + don't re-delegate = implicit revoke.

## 5. Routing Integration

### 5.1 Route Installation

On valid announcement, Yggdrasil node installs:
```
for cert in announcement.certs:
    addr = ygg_addr_from_pubkey(cert.delegator)
    install_route(addr, via=announcement.gateway, ttl=announcement.ttl)
```

### 5.2 Route Selection (Multiple Gateways)

If multiple gateways announce same address:
1. Prefer gateway with lower tree distance
2. Prefer gateway with longer-lived cert
3. Tie-break on gateway pubkey (deterministic)

### 5.3 Announcement Propagation

Announcements flood through spanning tree like standard Yggdrasil routing updates. Nodes cache and re-broadcast. TTL limits propagation scope if needed.

## 6. Security Analysis

| Attack | Mitigation |
|--------|------------|
| Forge delegation | Requires delegator's private key |
| Replay old announcement | Timestamp + TTL; verifiers reject expired |
| Claim unauthorized address | Must have valid cert signed by address owner |
| Black hole (announce but drop) | Out of scope (same as standard Ygg); use multiple gateways |
| Flood network with announcements | Rate limit per gateway pubkey |
| Steal traffic during cert validity | Short cert lifetimes; monitor for competing announcements |

## 7. Open Questions

1. **Yggdrasil upstream acceptance?** This requires protocol changes.
2. **Prefix-based vs individual?** Merkle aggregation vs mesh root key.
3. **Cert distribution:** How do mesh nodes get certs to gateway? LCI protocol? Out of band?
4. **Partial verification:** Can lightweight nodes trust gateway without verifying all certs?

## 8. Implementation Sketch

```
// Gateway announces its mesh
fn announce_subnet(gateway_key: &Ed25519Key, certs: &[DelegationCert]) {
    let ann = SubnetAnnouncement {
        version: 1,
        gateway: gateway_key.public(),
        timestamp: now(),
        ttl: 3600,
        cert_count: certs.len(),
        certs: certs.to_vec(),
        gateway_sig: [0; 64], // filled below
    };
    ann.gateway_sig = gateway_key.sign(&ann.to_bytes_unsigned());
    ygg_broadcast(ann);
}

// Mesh node delegates to gateway
fn delegate_to_gateway(node_key: &Ed25519Key, gateway_pub: &[u8; 32]) -> DelegationCert {
    let cert = DelegationCert {
        version: 1,
        delegator: node_key.public(),
        delegate: *gateway_pub,
        valid_from: now(),
        valid_until: now() + 86400, // 24 hours
        flags: 0x01, // revocable
        signature: [0; 64],
    };
    cert.signature = node_key.sign(&cert.to_bytes_unsigned());
    cert
}
```

## 9. Comparison to Alternatives

| Approach | Pros | Cons |
|----------|------|------|
| This proposal | Cryptographic auth, no central trust | Cert distribution overhead |
| Gateway proxies all keys | Simple routing | Gateway has all private keys (!) |
| Application-layer proxy | No protocol change | No direct addressability |
| DHT-based registry | Decentralized lookup | Separate infrastructure |

## 10. Next Steps

1. Socialize with Yggdrasil maintainers
2. Prototype in LICHEN gateway
3. Measure cert distribution overhead
4. Decide aggregation strategy (Merkle vs mesh root)
