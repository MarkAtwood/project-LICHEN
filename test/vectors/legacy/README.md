<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: The contributors to the LICHEN project -->

# QUARANTINED: rejected SHA-512 native address profile fixtures

The files in this directory encode the **rejected** LICHEN-native SHA-512
address derivation profile (`addr = [0x02] || SHA-512(pubkey)[0:7] || IID`,
`IID = SHA-512(pubkey)[0:8]` with U/L bit cleared).

That profile is **not** the LICHEN addressing standard. The settled decision
`upstream-yggdrasil-addressing` in `spec/decisions.jsonl` requires every
node's routable IPv6 identity to equal upstream Yggdrasil
`AddrForKey(Ed25519PublicKey)` — which bit-packs the inverted pubkey with **no
hashing**. The two schemes agree only on the leading `0x02` byte.

**These files are historical reference only**, kept to support the in-flight
upstream-migration work (see `bd` epic around
`project-LICHEN-worker6-q6ko`). Per `AGENTS.md`:

- They MUST NOT be cited as conformance oracles by spec prose, tests, or new
  code.
- The independent conformance oracle is the pinned upstream byte-equality
  vector (`upstream_addr_for_key` in `test/vectors/yggdrasil_address.json`,
  verbatim from yggdrasil-go `address_test.go`).
- Existing implementations still derive the legacy profile below; that is a
  known, tracked migration gap, not a license to treat these vectors as the
  target.

Files:

| File | Contents |
|------|----------|
| `yggdrasil.json` | Two legacy-profile spot vectors (`ygg_addr_from_pubkey` shape) |
| `yggdrasil-derivation.json` | Legacy-profile derivation corpus: U/L-bit cases, IID binding invariant, substitution-attack negative entry |
| `yggdrasil_address_native_sha512.json` | The ten `lichen_native_sha512` vectors moved verbatim out of `test/vectors/yggdrasil_address.json`, which now holds only the pinned upstream anchor and the length-rejection cases |
