# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project

"""CCP-15 constants per spec/02a-coordinated-capacity.md 2a.10.6."""

from lichen.constants import INTERFERENCE_ESCAPE_TENTHS, RF_METRICS_WINDOW_SF


def test_constants_match_spec():
    assert RF_METRICS_WINDOW_SF == 32
    assert INTERFERENCE_ESCAPE_TENTHS == 1000
