"""
Data models for CNX scanner.
All domain scan state is represented here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Verdict(str, Enum):
    """Final verdict for a scanned domain."""

    VULNERABLE = "VULNERABLE"
    EDGE_CASE = "EDGE_CASE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    ERROR = "ERROR"
    UNKNOWN = "UNKNOWN"


@dataclass
class ScanResult:
    """
    Holds every piece of information produced while scanning one domain.
    Immutable after the scan worker populates it.
    """

    domain: str

    # DNS
    cname_chain: List[str] = field(default_factory=list)
    nxdomain: bool = False

    # HTTP
    http_status: Optional[int] = None

    # Matched fingerprint fields
    service: Optional[str] = None
    verdict: Verdict = Verdict.UNKNOWN
    status_label: Optional[str] = None   # raw "status" from fingerprint
    fingerprint_matched: Optional[str] = None
    vulnerable: bool = False

    # Diagnostics
    error: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict:
        """Serialise to a plain dict (JSON-safe)."""
        return {
            "domain": self.domain,
            "vulnerable": self.vulnerable,
            "verdict": self.verdict.value,
            "service": self.service,
            "status": self.status_label,
            "fingerprint_matched": self.fingerprint_matched,
            "cname_chain": self.cname_chain,
            "nxdomain": self.nxdomain,
            "http_status": self.http_status,
            "error": self.error,
        }
