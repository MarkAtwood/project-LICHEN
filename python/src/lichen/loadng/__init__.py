"""LICHEN LOADng routing (spec section 10, appendix B2).

LOADng is the reactive peer-to-peer fallback used when no gradient route
exists. This package currently provides the control-message codecs (RREQ,
RREP, RERR).
"""

from lichen.loadng.messages import (
    INITIAL_HOP_LIMIT,
    MAX_HOP_LIMIT,
    RERR,
    RREP,
    RREQ,
    SIGNATURE_LENGTH,
    LoadngCode,
    LoadngError,
    LoadngMessage,
    from_icmpv6,
    to_icmpv6,
)

__all__ = [
    "INITIAL_HOP_LIMIT",
    "MAX_HOP_LIMIT",
    "RERR",
    "RREP",
    "RREQ",
    "SIGNATURE_LENGTH",
    "LoadngCode",
    "LoadngError",
    "LoadngMessage",
    "from_icmpv6",
    "to_icmpv6",
]
