# LICHEN Contributors Coordination

## Current Status

**Prototype:** Python sim complete, 840+ tests passing
**Crypto:** Schnorr48 implemented and vectorized — ready for cross-impl validation

## What's Unblocked

| Issue | Description | Status |
|-------|-------------|--------|
| 9a9 | Schnorr48 signature implementation | ✅ Done — vectors in `test/vectors/schnorr48.json` |
| muq | Link TX/RX with signatures | Ready to start |
| l1r/8rd | Announce routing | Blocked on muq |
| aj0 | Hybrid routing (RPL + LOADng) | Blocked on l1r |
| q0p | Full node integration | Blocked on aj0 |
| ijj | "Prototype validates design" gate | Blocked on q0p |

## Key Files

| File | What it is |
|------|------------|
| `spec/drafts/draft-lichen-schnorr-00.md` | Schnorr48 spec with test vectors in Appendix A |
| `test/vectors/schnorr48.json` | Machine-readable vectors (5 valid, 6 invalid) |
| `python/src/lichen/crypto/schnorr48.py` | Reference implementation (pynacl) |
| `AGENTS.md` | AI agent instructions + project overview |

## For New Contributors

1. Read `AGENTS.md` for architecture overview
2. Run `bd prime` for issue tracking workflow
3. Check `bd ready` for available work
4. Test vectors in `test/vectors/` are canonical — all implementations must match bit-for-bit

## Communication

- GitHub Issues: Use `bd` (beads) for tracking
- PRs welcome — fork and submit against `main`

## Recent Changes

**2026-06-22:**
- Merged fr0sty1's protocol stack (SCHC, RPL, LOADng, CoAP, IPv6)
- Added Schnorr48 reference impl + test vectors
- Fixed spec bug (truncated challenge scalar)

---

*Update this file when project status changes significantly.*
