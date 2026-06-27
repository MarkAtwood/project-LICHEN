# SPDX-License-Identifier: GPL-3.0-or-later
# SPDX-FileCopyrightText: The contributors to the LICHEN project
"""LICHEN cryptographic primitives.

- schnorr48: Link-layer signatures (Ed25519-based, 48-byte)
- identity: Node identity management
- edhoc: EDHOC RFC 9528 Suite 0 for OSCORE key establishment
"""

from .edhoc import EdhocInitiator, EdhocResponder, OscoreContext
from .identity import Identity, PeerIdentity

__all__ = [
    "EdhocInitiator",
    "EdhocResponder",
    "Identity",
    "OscoreContext",
    "PeerIdentity",
]
