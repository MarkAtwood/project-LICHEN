<!-- Part of LICHEN Protocol Specification -->

# Appendix B: RPL Configuration

RPL is used for border router traffic only. See Section 8 for details.
For peer-to-peer traffic, see Appendix B2 (LOADng).

## B.1. Objective Function

**MRHOF (Minimum Rank with Hysteresis Objective Function):**

```
ETX(link) = transmissions / successes
PathETX = sum(ETX(link)) for all links to root
Rank = (PathETX * 128) + MinHopRankIncrease
```

## B.2. Configuration Option Values

| Parameter | Value |
|-----------|-------|
| RPLInstanceID | 0 (default instance) |
| Mode of Operation | Non-Storing (MOP=1) |
| MinHopRankIncrease | 256 |
| MaxRankIncrease | 2048 |
| Default Lifetime | 30 minutes |
| Lifetime Unit | 60 seconds |

## B.3. Trickle Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Imin | 4096 ms | ~4 seconds |
| Imax | 20 | 2^20 ms = ~17 minutes |
| k | 10 | Redundancy constant |

---

[← Previous: Appendix A](appendix-schc.md) | [Index](README.md) | [Next: Appendix B2 →](appendix-loadng.md)
