"""
Token-bucket rate limiter for async code.
``RateLimiter(0)`` is a no-op (unlimited).
"""

import asyncio
import time


class RateLimiter:
    """
    Async token-bucket limiter.

    Parameters
    ----------
    rate:
        Maximum number of acquisitions per second.
        Pass ``0`` (or any falsy value) to disable rate-limiting.
    """

    __slots__ = ("_rate", "_tokens", "_last_refill", "_lock")

    def __init__(self, rate: int) -> None:
        self._rate: int = rate
        self._tokens: float = float(rate)
        self._last_refill: float = time.monotonic()
        self._lock: asyncio.Lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return self._rate > 0

    async def acquire(self) -> None:
        """Block until a token is available."""
        if not self.enabled:
            return

        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(self._rate),
                self._tokens + elapsed * self._rate,
            )
            self._last_refill = now

            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self._rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
            else:
                self._tokens -= 1.0
