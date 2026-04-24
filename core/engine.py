"""
Queue-based async scan engine.

Architecture
------------
  Producer  → fills asyncio.Queue with domain strings
  Workers   → N concurrent coroutines each pull from the queue,
              call Scanner.scan(), and push results to result_queue
  Collector → drains result_queue and accumulates ScanResult objects

This design decouples I/O from result handling and makes the pipeline
scale to any number of domains without holding them all in memory.
"""

from __future__ import annotations

import asyncio
from typing import Callable, List, Optional

import aiohttp

from core.matcher import FingerprintMatcher
from core.resolver import DNSResolver
from core.scanner import Scanner
from output.dashboard import LiveDashboard
from utils.limiter import RateLimiter
from utils.logger import get_logger
from utils.models import ScanResult

logger = get_logger(__name__)

_SENTINEL = None   # signals workers to stop


class Engine:
    """
    High-throughput scan engine.

    Parameters
    ----------
    fingerprints_path:
        Path to ``fingerprints.json``.
    concurrency:
        Number of concurrent scan workers.
    timeout:
        Per-domain HTTP timeout in seconds.
    rate_limit:
        Max requests per second (``0`` = unlimited).
    on_result:
        Optional callback invoked immediately after each domain is scanned.
        Signature: ``(result: ScanResult) -> None``.
    """

    def __init__(
        self,
        fingerprints_path: str,
        concurrency: int = 150,
        timeout: int = 10,
        rate_limit: int = 0,
        on_result: Optional[Callable[[ScanResult], None]] = None,
        silent: bool = False,
    ) -> None:
        self._fingerprints_path = fingerprints_path
        self._concurrency = concurrency
        self._timeout = timeout
        self._rate_limit = rate_limit
        self._on_result = on_result
        self._silent = silent

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def run(self, domains: List[str]) -> List[ScanResult]:
        """
        Scan every domain in *domains* and return all ``ScanResult``s.
        """
        total = len(domains)
        work_queue: asyncio.Queue[Optional[str]] = asyncio.Queue(
            maxsize=self._concurrency * 4
        )
        result_queue: asyncio.Queue[ScanResult] = asyncio.Queue()

        matcher = FingerprintMatcher(self._fingerprints_path)
        resolver = DNSResolver(timeout=self._timeout)
        limiter = RateLimiter(self._rate_limit)

        connector = aiohttp.TCPConnector(
            limit=self._concurrency,
            ssl=False,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
        )

        async with aiohttp.ClientSession(
            connector=connector,
            headers={"User-Agent": (
                "Mozilla/5.0 (compatible; cnx-scanner/2.0)"
            )},
        ) as session:

            scanner = Scanner(
                session=session,
                resolver=resolver,
                matcher=matcher,
                limiter=limiter,
                timeout=self._timeout,
            )

            dashboard = LiveDashboard(total=total, silent=self._silent)

            # ── Launch components concurrently ────────────────────────
            try:
                async with asyncio.TaskGroup() as tg:
                    tg.create_task(
                        self._producer(domains, work_queue)
                    )
                    for _ in range(self._concurrency):
                        tg.create_task(
                            self._worker(scanner, work_queue, result_queue, dashboard)
                        )
                    collector_task = tg.create_task(
                        self._collector(result_queue, total)
                    )
            finally:
                dashboard.stop()

        return collector_task.result()

    # ------------------------------------------------------------------ #
    # Pipeline stages
    # ------------------------------------------------------------------ #

    async def _producer(
        self,
        domains: List[str],
        queue: asyncio.Queue,
    ) -> None:
        """Push all domains into the work queue, then send sentinels."""
        for domain in domains:
            await queue.put(domain)

        # One sentinel per worker so every worker exits cleanly
        for _ in range(self._concurrency):
            await queue.put(_SENTINEL)

    async def _worker(
        self,
        scanner: Scanner,
        work_queue: asyncio.Queue,
        result_queue: asyncio.Queue,
        dashboard: LiveDashboard,
    ) -> None:
        """Pull domains from the queue, scan them, push results."""
        while True:
            domain = await work_queue.get()

            if domain is _SENTINEL:
                work_queue.task_done()
                break

            try:
                result = await scanner.scan(domain)
                await result_queue.put(result)

                if self._on_result:
                    self._on_result(result)

                dashboard.update(result)

            finally:
                work_queue.task_done()

        # Signal collector that one worker has finished
        await result_queue.put(_SENTINEL)

    async def _collector(
        self,
        result_queue: asyncio.Queue,
        total: int,
    ) -> List[ScanResult]:
        """Drain the result queue until all workers have sent their sentinel."""
        results: List[ScanResult] = []
        finished_workers = 0

        while finished_workers < self._concurrency:
            item = await result_queue.get()
            if item is _SENTINEL:
                finished_workers += 1
            else:
                results.append(item)

        return results
