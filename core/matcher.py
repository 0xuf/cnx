"""
Fingerprint matching engine.

Fetches fingerprints live from the canonical upstream URL (EdOverflow/can-i-take-over-xyz)
so the scanner always uses the latest data without requiring a local copy.
Falls back to a local ``fingerprints.json`` if the network is unreachable.

Exposes a single ``match()`` method that decides whether a DNS / HTTP
response indicates a takeover opportunity.
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path
from typing import List, Optional

from utils.models import ScanResult, Verdict

_UPSTREAM_URL = (
    "https://github.com/EdOverflow/can-i-take-over-xyz"
    "/raw/refs/heads/master/fingerprints.json"
)


def _load_fingerprints(fingerprints_path: str) -> list:
    """
    Try to fetch fingerprints from the upstream GitHub URL.
    On any network failure, fall back to *fingerprints_path* on disk.
    Returns the raw list parsed from JSON.
    """
    try:
        with urllib.request.urlopen(_UPSTREAM_URL, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        pass  # network unavailable — fall back to local file

    local = Path(fingerprints_path)
    if local.exists():
        with local.open(encoding="utf-8") as fh:
            return json.load(fh)

    raise FileNotFoundError(
        f"Could not fetch fingerprints from upstream and no local file "
        f"found at '{fingerprints_path}'."
    )


class FingerprintMatcher:
    """
    Match a ``ScanResult`` against the known takeover fingerprints.

    Parameters
    ----------
    fingerprints_path:
        Path to a local ``fingerprints.json`` used as a fallback when the
        upstream URL is unreachable.  Can be an empty string if you are
        confident the network is always available.
    """

    def __init__(self, fingerprints_path: str) -> None:
        raw: list = _load_fingerprints(fingerprints_path)

        # Keep only entries that have at least a service name
        self._fingerprints: List[dict] = [
            fp for fp in raw if fp.get("service")
        ]

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    def match(
        self,
        result: ScanResult,
        http_body: Optional[str],
    ) -> None:
        """
        Populate *result* in-place with verdict, service, and matched
        fingerprint string.  Called after DNS + HTTP probing is done.
        """
        for fp in self._fingerprints:
            if self._fp_matches(fp, result, result.domain, http_body):
                result.service = fp.get("service")
                result.status_label = fp.get("status", "Unknown")
                result.fingerprint_matched = fp.get("fingerprint") or None
                result.vulnerable = bool(fp.get("vulnerable", False))
                result.verdict = self._to_verdict(fp)
                return

        # No fingerprint matched — domain appears clean
        result.verdict = Verdict.UNKNOWN

    # ------------------------------------------------------------------ #
    # Private helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _to_verdict(fp: dict) -> Verdict:
        status = (fp.get("status") or "").lower()
        if fp.get("vulnerable"):
            return Verdict.VULNERABLE
        if "edge" in status:
            return Verdict.EDGE_CASE
        if "not" in status:
            return Verdict.NOT_VULNERABLE
        return Verdict.UNKNOWN

    def _fp_matches(
        self,
        fp: dict,
        result: ScanResult,
        domain: str,
        http_body: Optional[str],
    ) -> bool:
        """Return True if *fp* matches the scan evidence."""

        # Build an extended chain that also includes the domain itself so
        # that direct subdomains (e.g. foo.azurewebsites.net) match CNAME
        # fingerprints even when no CNAME record was returned.
        extended_chain = result.cname_chain + [domain]

        # 1. NXDOMAIN fingerprints ─────────────────────────────────────
        if fp.get("nxdomain") and result.nxdomain:
            if self._cname_matches(fp.get("cname", []), extended_chain):
                return True

        # 2. Body fingerprint ──────────────────────────────────────────
        fp_str: str = fp.get("fingerprint", "")
        if fp_str and http_body:
            if self._body_matches(fp_str, http_body):
                fp_cnames = fp.get("cname", [])
                if not fp_cnames or self._cname_matches(
                    fp_cnames, extended_chain
                ):
                    return True

        # 3. HTTP-status-only fingerprints ─────────────────────────────
        fp_status = fp.get("http_status")
        if fp_status and result.http_status and fp_status == result.http_status:
            if self._cname_matches(fp.get("cname", []), extended_chain):
                return True

        return False

    # ------------------------------------------------------------------ #
    # Static utilities
    # ------------------------------------------------------------------ #

    @staticmethod
    def _cname_matches(fp_cnames: List[str], extended_chain: List[str]) -> bool:
        """
        True when:
        - the fingerprint has no CNAME requirement (wildcard), OR
        - for any (fp_cname, chain_entry) pair one of these holds:
            a) fp_cname is a substring of chain_entry  (foo.surge.sh ⊇ surge.sh)
            b) chain_entry is a substring of fp_cname  (reverse case)
            c) they share a common registered domain suffix, e.g.
               ``nonexistent.surge.sh`` and ``na-west1.surge.sh`` both end
               with ``surge.sh`` — extracted as the last two labels.
        """
        if not fp_cnames:
            return True

        def _apex(host: str) -> str:
            """Return the last two dot-separated labels of a hostname."""
            parts = host.rstrip(".").lower().split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()

        for fp_cname in fp_cnames:
            fp_lower  = fp_cname.lower()
            fp_apex   = _apex(fp_cname)
            for entry in extended_chain:
                entry_lower = entry.lower()
                entry_apex  = _apex(entry)
                if (
                    fp_lower in entry_lower          # a) fp inside chain entry
                    or entry_lower in fp_lower       # b) chain entry inside fp
                    or (fp_apex and fp_apex == entry_apex)  # c) shared apex
                ):
                    return True
        return False

    @staticmethod
    def _body_matches(pattern: str, body: str) -> bool:
        """
        Try regex first; fall back to case-insensitive substring match.
        HTML entities in patterns (e.g. ``&#124;`` → ``|``) are decoded
        before matching so fingerprints from fingerprints.json work as-is.
        """
        import html
        pattern = html.unescape(pattern)
        try:
            return bool(re.search(pattern, body, re.IGNORECASE | re.DOTALL))
        except re.error:
            return pattern.lower() in body.lower()
