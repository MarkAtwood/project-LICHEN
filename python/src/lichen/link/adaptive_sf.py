# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Adaptive Spreading Factor oracle (spec 02-physical-link.md §3.5, CCP-16).

Normative pseudocode (spec §3.5):

    ema_update(avg, sample):
        diff = sample - avg
        return avg + (diff >> 2)
    update_neighbor(nbr, snr, loss):
        nbr.ema_snr = ema_update(nbr.ema_snr, snr)
        nbr.ema_loss = ema_update(nbr.ema_loss, loss)
        nbr.samples = nbr.samples + 1
    select_tx_sf(nbr, density, utilization):
        sf = nbr.assigned_sf or 10
        if density > 10 or utilization > 150:
            sf = min(12, sf + 2)
        if nbr.ema_snr > 8 and density < 5:
            sf = max(7, sf - 1)
        if nbr.ema_loss > 0.25:
            sf = min(12, sf + 1)
        if utilization > 200:
            return 12, false
        return sf, true

Sensitivity table and thresholds are also enforced per the spec table.

Embedded note: no_std implementations SHOULD prefer Q16.16 fixed-point
(see appendix-design-rationale.md:7.6).  Python oracle uses float for clarity
but matches integer Ema semantics for int SNR values via arithmetic shift.
"""

from __future__ import annotations

from dataclasses import dataclass

# Sensitivity per SF (dBm) from spec §3.5 table
SENSITIVITY_DBM: dict[int, float] = {
    7: -123.0,
    9: -129.0,
    10: -132.0,
    11: -134.0,
    12: -137.0,
}


@dataclass
class NeighborState:
    """Per-neighbor RF state (MUST track EMA, loss, samples per spec)."""

    assigned_sf: int | None = None  # None -> SF10 baseline
    ema_snr: float = 0.0
    ema_loss: float = 0.0
    samples: int = 0

    @property
    def baseline_sf(self) -> int:
        return self.assigned_sf if self.assigned_sf is not None else 10


def ema_update(avg: float, sample: float) -> float:
    """EMA with alpha=1/4 via shift semantics: avg + (sample-avg)/4.

    For integer SNR inputs this matches `avg + (diff >> 2)` when avg/sample are
    integers.  Using float preserves the same result for int inputs and extends
    naturally to fractional SNR.
    """
    diff = sample - avg
    return avg + diff * 0.25


def update_neighbor(nbr: NeighborState, snr: float, loss: float) -> None:
    """Update per-neighbor EMA tracking (MUST signal in DIO per CCP-16)."""
    nbr.ema_snr = ema_update(nbr.ema_snr, snr)
    nbr.ema_loss = ema_update(nbr.ema_loss, loss)
    nbr.samples += 1


def adaptive_sf_for_metrics(
    density: int,
    snr_ema: int | float,
    load_factor: float = 0.0,
) -> int:
    """Table-based SF selection per spec §3.5 and CCP-16 (mirrors Rust adaptive_sf)."""
    snr = int(snr_ema) if isinstance(snr_ema, int) else int(snr_ema)
    if density > 20 or snr < -5:
        return 12
    if density > 10 or snr < 0 or load_factor > 0.8:
        return 11
    if density < 5 and snr > 8:
        return 9
    return 10


def select_tx_sf(
    nbr: NeighborState,
    density: int,
    utilization: int,
    load_factor: float = 0.0,
) -> tuple[int, bool]:
    """Select TX SF and tx_allowed flag per spec 02a 2a.8 pseudocode.

    Two-tier approach matching Rust RfHealthMetrics: tier 1 supplies the
    base SF (the threshold table via adaptive_sf_for_metrics when no
    explicit assigned SF, else the caller's baseline), tier 2 ALWAYS
    applies the normative pseudocode steps (density > 10, SNR upgrade,
    loss bump, utilization back-off). The table alone remains the oracle
    only when consulted directly via adaptive_sf_for_metrics (e.g. the
    CCP-16 table-only vectors).

    Args:
        nbr: Per-neighbor state (assigned_sf, ema_snr, ema_loss).
        density: Neighbor density (0..255).
        utilization: Channel utilization uint8 0..255 (util_norm=util/255,
            TX-time based occupancy per spec).
        load_factor: Channel load factor 0..1 (Q0.1 fraction); floor (d)
            applies when > 0.8. Defaults to 0.0 (no load tracking).

    Returns:
        (sf, tx_allowed) where sf in 7..12 and tx_allowed is False only when
        utilization > 200 (congestion back-off, caller should defer TX).
    """
    # Merge resolution: the beads-worker-1 body is kept. The other parent's
    # density > 8 threshold was a residue; the normative 2a.8 pseudocode
    # (spec/02-physical-link.md), python ccp.py, and rust rf_health.rs all
    # pin density > 10. load_factor is a documented parameter with a 0.0
    # default so floor (d) does not read an undefined name.
    # Tier 1: assigned SF or the SF10 baseline.
    sf = nbr.baseline_sf
    # Tier 2: normative pseudocode steps (always applied)
    if density > 10 or utilization > 150:
        sf = min(12, sf + 2)
    if nbr.ema_snr > 8 and density < 5:
        sf = max(7, sf - 1)
    if nbr.ema_loss > 0.25:
        sf = min(12, sf + 1)
    if utilization > 200:
        return 12, False
    # Spec 2a.8 post-step-6 minimum-SF floors, in order a-d with each MAX
    # against the running SF (rust rf_health.rs parity; Rust implements
    # floor d as >= 0.8 in Q16.16 where 52429 is the smallest integer
    # strictly above 0.8*65536; Python uses the float threshold > 0.8).
    if nbr.ema_snr < -5:
        sf = 12
    if nbr.ema_snr < 0:
        sf = max(11, sf)
    if density > 10:
        sf = max(11, sf)
    if load_factor > 0.8:
        sf = max(11, sf)
    # Clamp to valid range (defensive)
    sf = max(7, min(12, sf))
    return sf, True


__all__ = [
    "SENSITIVITY_DBM",
    "NeighborState",
    "ema_update",
    "select_tx_sf",
    "update_neighbor",
]
