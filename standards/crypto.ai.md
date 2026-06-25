<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# LICHEN Crypto Quick Reference

Target: **128-bit security** throughout.

## Signatures

| Algo       | Pub Key | Sig Size | Notes |
|------------|---------|----------|-------|
| Ed25519    | 32B     | 64B      | RFC 8032 |
| Schnorr-48 | 32B     | 48B      | LICHEN link layer |

### Schnorr-48 Format
```
| e (16B) | s (32B) |  = 48 bytes total
```
- Curve: Curve25519 (same as Ed25519)
- Challenge `e`: truncated to 16 bytes (128-bit)
- Response `s`: 32 bytes
- 25% smaller than Ed25519, same security

## Encryption (AES-CCM)

| Context    | Key  | Nonce | Tag | Algorithm Name |
|------------|------|-------|-----|----------------|
| Link layer | 16B  | 13B   | 8B  | AES-128-CCM |
| OSCORE     | 16B  | 13B   | 8B  | AES-CCM-16-64-128 |

CCM parameters:
- L = 2 (length field size)
- M = 8 (tag length)
- Nonce = 13 bytes

## Key Exchange

| Algo   | Public | Shared Secret |
|--------|--------|---------------|
| X25519 | 32B    | 32B           |

## Hashing

| Algo    | Output | Used By |
|---------|--------|---------|
| SHA-256 | 32B    | HKDF, OSCORE |
| SHA-512 | 64B    | Ed25519, Schnorr nonce |

## Key Derivation

HKDF (RFC 5869) with SHA-256.

## Ed25519 / X25519 Key Relationship

Same 32-byte seed, different derivation:
```
seed = random(32B)
hash = SHA512(seed)

# Ed25519
ed_priv = hash[0:32]
ed_pub  = ed_basepoint * ed_priv

# X25519
x_priv  = clamp(hash[0:32])
x_pub   = x_basepoint * x_priv
```

Clamp operation (X25519):
```
priv[0]  &= 0xF8   # clear bottom 3 bits
priv[31] &= 0x7F   # clear top bit
priv[31] |= 0x40   # set bit 254
```

## Deterministic Nonces

Both Ed25519 and Schnorr-48:
```
nonce = SHA512(prefix || private_key || message)
```
Prevents catastrophic nonce reuse.

## OSCORE Specifics

- AEAD: AES-CCM-16-64-128
- Key size: 16 bytes
- Nonce: 13 bytes (common IV XOR partial IV)
- Tag: 8 bytes
- KDF: HKDF-SHA-256

## Size Summary

| Item | Bytes |
|------|-------|
| Ed25519 public key | 32 |
| Ed25519 signature | 64 |
| Schnorr-48 signature | 48 |
| X25519 public key | 32 |
| X25519 shared secret | 32 |
| AES-128 key | 16 |
| CCM nonce | 13 |
| CCM tag | 8 |
| SHA-256 digest | 32 |
| SHA-512 digest | 64 |
