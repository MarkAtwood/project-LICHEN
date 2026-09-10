# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""Hardware-gated MeshCore wrong-mode smoke checks.

Set ``LICHEN_MESHCORE_SMOKE_CMD`` to a client wrapper accepting ``--transport``
and ``--frame``.  The wrapper should return nonzero and report the rejection.
"""

import os
import shlex
import subprocess

import pytest


@pytest.mark.parametrize(
    ("transport", "frame"),
    (("ble", "3c01000a"), ("ble", "3e01000a"), ("native", ""), ("meshtastic", "")),
)
def test_meshcore_mode_rejects_wrong_transport(transport: str, frame: str) -> None:
    command = os.environ.get("LICHEN_MESHCORE_SMOKE_CMD")
    if not command:
        pytest.skip("set LICHEN_MESHCORE_SMOKE_CMD for hardware smoke testing")

    result = subprocess.run(
        [*shlex.split(command.format(transport=transport, frame=frame)),
         "--transport", transport, "--frame", frame],
        check=False,
        capture_output=True,
        text=True,
    )
    output = f"{result.stdout}\n{result.stderr}".lower()
    assert result.returncode != 0
    assert any(word in output for word in ("reject", "wrong-mode", "incompatible", "unsupported"))
