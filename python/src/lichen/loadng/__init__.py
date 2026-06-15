"""LICHEN LOADng routing (spec section 10, appendix B2).

LOADng is the reactive peer-to-peer fallback used when no gradient route
exists. This package currently provides the control-message codecs (RREQ,
RREP, RERR).
"""

from lichen.loadng.cache import (
    ROUTE_CACHE_SIZE,
    ROUTE_REFRESH_MS,
    ROUTE_TIMEOUT_MS,
    RouteCache,
    RouteEntry,
)
from lichen.loadng.discovery import (
    SUPPRESS_WINDOW_MS,
    LoadngRouter,
    RrepResult,
    RreqResult,
)
from lichen.loadng.error import RerrAction, RouteErrorManager
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
    "ROUTE_CACHE_SIZE",
    "ROUTE_REFRESH_MS",
    "ROUTE_TIMEOUT_MS",
    "SUPPRESS_WINDOW_MS",
    "RERR",
    "RREP",
    "RREQ",
    "SIGNATURE_LENGTH",
    "LoadngCode",
    "LoadngError",
    "LoadngMessage",
    "LoadngRouter",
    "RerrAction",
    "RouteCache",
    "RouteEntry",
    "RouteErrorManager",
    "RreqResult",
    "RrepResult",
    "from_icmpv6",
    "to_icmpv6",
]
