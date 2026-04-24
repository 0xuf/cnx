"""
Async DNS resolver with full CNAME-chain following and NXDOMAIN detection.
Uses ``aiodns`` so every lookup is non-blocking.
"""

from __future__ import annotations

from typing import List, Tuple

import aiodns


# aiodns NXDOMAIN / no-answer error codes
_NXDOMAIN_CODES = frozenset(
    [
        aiodns.error.ARES_ENOTFOUND,   # 4 – name not found
        aiodns.error.ARES_ENODATA,     # 11 – no data record
    ]
)

_MAX_CNAME_DEPTH = 15   # guard against infinite loops


class DNSResolver:
    """
    Thin async wrapper around ``aiodns.DNSResolver``.

    Notes
    -----
    A single instance **must** be reused across all workers so they share the
    same underlying c-ares context.  Create it inside the running event loop
    (i.e. inside an ``async`` function) rather than at import time.
    """

    def __init__(self, timeout: int = 8) -> None:
        self._timeout = timeout
        self._resolver: aiodns.DNSResolver | None = None

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    def _get(self) -> aiodns.DNSResolver:
        """Lazily create the resolver (must be called from the event loop)."""
        if self._resolver is None:
            self._resolver = aiodns.DNSResolver(
                nameservers=["8.8.8.8", "1.1.1.1", "8.8.4.4"],
                timeout=self._timeout,
            )
        return self._resolver

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def resolve(self, domain: str) -> Tuple[List[str], bool]:
        """
        Follow the CNAME chain for *domain* and attempt a final A lookup.

        Returns
        -------
        cname_chain:
            Ordered list of CNAME targets encountered (may be empty).
        nxdomain:
            ``True`` when the domain (or its CNAME target) does not exist.
        """
        resolver = self._get()
        cname_chain: List[str] = []
        current = domain
        nxdomain = False

        # --- Walk CNAME chain ---
        for _ in range(_MAX_CNAME_DEPTH):
            try:
                result = await resolver.query(current, "CNAME")
                target = result.cname.rstrip(".")
                cname_chain.append(target)
                current = target
            except aiodns.error.DNSError:
                # No more CNAMEs (or real error) — stop following
                break

        # --- Confirm the final name resolves ---
        try:
            await resolver.query(current, "A")
        except aiodns.error.DNSError as exc:
            code = exc.args[0] if exc.args else None
            if code in _NXDOMAIN_CODES:
                nxdomain = True
        except Exception:
            nxdomain = True

        return cname_chain, nxdomain
