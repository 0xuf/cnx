"""
Per-domain scan logic.
The ``Scanner`` class owns a shared aiohttp session and handles:
  - DNS resolution  (via DNSResolver)
  - HTTP probing    (https → http fallback)
  - Fingerprinting  (via FingerprintMatcher)
"""

from __future__ import annotations

from typing import Optional, Tuple

import aiohttp

from core.matcher import FingerprintMatcher
from core.resolver import DNSResolver
from utils.limiter import RateLimiter
from utils.models import ScanResult, Verdict
from utils.logger import get_logger

logger = get_logger(__name__)

_USER_AGENT = (
    "Mozilla/5.0 (compatible; cnx-scanner/2.0; "
    "+https://github.com/cnx-scanner)"
)
_MAX_BODY_BYTES = 512 * 1024   # 512 KB — more than enough for fingerprinting


class Scanner:
    """
    Stateless per-domain scanner.

    Parameters
    ----------
    session:
        A shared ``aiohttp.ClientSession`` managed by the engine.
    resolver:
        A shared ``DNSResolver`` instance.
    matcher:
        A shared ``FingerprintMatcher`` instance.
    limiter:
        A shared ``RateLimiter`` (may be a no-op instance).
    timeout:
        Per-request HTTP timeout in seconds.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        resolver: DNSResolver,
        matcher: FingerprintMatcher,
        limiter: RateLimiter,
        timeout: int = 10,
    ) -> None:
        self._session = session
        self._resolver = resolver
        self._matcher = matcher
        self._limiter = limiter
        self._timeout = aiohttp.ClientTimeout(total=timeout)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def scan(self, domain: str) -> ScanResult:
        """
        Run a full scan for *domain* and return a populated ``ScanResult``.
        This method never raises; all exceptions are captured in
        ``result.error``.
        """
        result = ScanResult(domain=domain)

        try:
            await self._limiter.acquire()

            # ── 1. DNS ────────────────────────────────────────────────
            cname_chain, nxdomain = await self._resolver.resolve(domain)
            result.cname_chain = cname_chain
            result.nxdomain = nxdomain

            # ── 2. HTTP (skip when NXDOMAIN) ──────────────────────────
            http_body: Optional[str] = None
            if not nxdomain:
                http_body, result.http_status = await self._http_probe(domain)

            # ── 3. Fingerprint match ───────────────────────────────────
            self._matcher.match(result, http_body)

        except Exception as exc:
            result.error = str(exc)
            result.verdict = Verdict.ERROR
            logger.debug("Error scanning %s: %s", domain, exc)

        return result

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    async def _http_probe(
        self, domain: str
    ) -> Tuple[Optional[str], Optional[int]]:
        """
        Try HTTPS first, then HTTP.
        Returns ``(body, status_code)`` or ``(None, None)`` on complete
        failure.
        """
        for scheme in ("https", "http"):
            url = f"{scheme}://{domain}"
            try:
                async with self._session.get(
                    url,
                    timeout=self._timeout,
                    allow_redirects=True,
                    max_redirects=10,
                    ssl=False,
                ) as response:
                    raw = await response.content.read(_MAX_BODY_BYTES)
                    body = raw.decode("utf-8", errors="replace")
                    return body, response.status
            except Exception:
                continue   # try the other scheme

        return None, None
