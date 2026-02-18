"""Rate limiting utilities for CTF Toolkit."""

import asyncio
import time
from typing import Optional


class RateLimiter:
    """
    Token bucket rate limiter for controlling request rate.
    Supports both sync and async usage.
    """

    def __init__(self, rate: float = 10.0, burst: Optional[int] = None):
        """
        Initialize rate limiter.

        Args:
            rate: Requests per second
            burst: Maximum burst size (defaults to rate)
        """
        self.rate = rate
        self.burst = burst or int(rate)
        self.tokens = float(self.burst)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
        self._sync_lock = False

    def _add_tokens(self) -> None:
        """Add tokens based on elapsed time."""
        now = time.monotonic()
        elapsed = now - self.last_update
        self.tokens = min(self.burst, self.tokens + elapsed * self.rate)
        self.last_update = now

    def acquire_sync(self) -> None:
        """
        Acquire a token synchronously (blocking).
        """
        while True:
            self._add_tokens()
            if self.tokens >= 1:
                self.tokens -= 1
                return
            # Calculate sleep time until next token
            sleep_time = (1 - self.tokens) / self.rate
            time.sleep(sleep_time)

    async def acquire(self) -> None:
        """
        Acquire a token asynchronously.
        """
        async with self._lock:
            while True:
                self._add_tokens()
                if self.tokens >= 1:
                    self.tokens -= 1
                    return
                # Calculate sleep time until next token
                sleep_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(sleep_time)

    def try_acquire(self) -> bool:
        """
        Try to acquire a token without blocking.

        Returns:
            True if token was acquired, False otherwise
        """
        self._add_tokens()
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False

    @property
    def available_tokens(self) -> float:
        """Get current number of available tokens."""
        self._add_tokens()
        return self.tokens


class AdaptiveRateLimiter(RateLimiter):
    """
    Rate limiter that adapts based on response times or errors.
    """

    def __init__(
        self,
        initial_rate: float = 10.0,
        min_rate: float = 1.0,
        max_rate: float = 50.0,
        adjustment_factor: float = 0.5
    ):
        """
        Initialize adaptive rate limiter.

        Args:
            initial_rate: Starting requests per second
            min_rate: Minimum rate limit
            max_rate: Maximum rate limit
            adjustment_factor: Factor to increase/decrease rate
        """
        super().__init__(rate=initial_rate)
        self.min_rate = min_rate
        self.max_rate = max_rate
        self.adjustment_factor = adjustment_factor
        self.error_count = 0
        self.success_count = 0

    def report_success(self) -> None:
        """Report a successful request."""
        self.success_count += 1
        # Increase rate after consecutive successes
        if self.success_count >= 10:
            self._increase_rate()
            self.success_count = 0
            self.error_count = 0

    def report_error(self) -> None:
        """Report a failed request (e.g., timeout, rate limit response)."""
        self.error_count += 1
        self.success_count = 0
        # Decrease rate after errors
        if self.error_count >= 3:
            self._decrease_rate()
            self.error_count = 0

    def _increase_rate(self) -> None:
        """Increase the rate limit."""
        new_rate = self.rate * (1 + self.adjustment_factor)
        self.rate = min(new_rate, self.max_rate)
        self.burst = int(self.rate)

    def _decrease_rate(self) -> None:
        """Decrease the rate limit."""
        new_rate = self.rate * (1 - self.adjustment_factor)
        self.rate = max(new_rate, self.min_rate)
        self.burst = int(self.rate)


class Semaphore:
    """
    Simple semaphore for limiting concurrent operations.
    """

    def __init__(self, max_concurrent: int = 5):
        """
        Initialize semaphore.

        Args:
            max_concurrent: Maximum concurrent operations
        """
        self._semaphore = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self):
        await self._semaphore.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self._semaphore.release()
