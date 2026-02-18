"""HTTP client with proxy support for CTF Toolkit."""

import asyncio
import time
from typing import Optional, Any
from dataclasses import dataclass
import httpx
import aiohttp

from .context import AttackContext
from .rate_limiter import RateLimiter


@dataclass
class Response:
    """Wrapper for HTTP response data."""
    status_code: int
    text: str
    content: bytes
    headers: dict[str, str]
    elapsed: float  # seconds
    url: str

    @property
    def content_length(self) -> int:
        """Get content length."""
        return len(self.content)

    def __str__(self) -> str:
        return f"Response(status={self.status_code}, length={self.content_length}, time={self.elapsed:.3f}s)"


class HttpClient:
    """
    HTTP client with proxy, cookie, and rate limiting support.
    Supports both sync and async operations.
    """

    def __init__(self, ctx: AttackContext):
        """
        Initialize HTTP client.

        Args:
            ctx: Attack context with configuration
        """
        self.ctx = ctx
        self.rate_limiter = RateLimiter(rate=ctx.rate_limit)
        self._sync_client: Optional[httpx.Client] = None
        self._async_client: Optional[aiohttp.ClientSession] = None

    def _get_sync_client(self) -> httpx.Client:
        """Get or create sync HTTP client."""
        if self._sync_client is None:
            self._sync_client = httpx.Client(
                timeout=self.ctx.timeout,
                verify=self.ctx.verify_ssl,
                follow_redirects=True,
                proxy=self.ctx.proxy,
            )
        return self._sync_client

    async def _get_async_client(self) -> aiohttp.ClientSession:
        """Get or create async HTTP client."""
        if self._async_client is None:
            timeout = aiohttp.ClientTimeout(total=self.ctx.timeout)
            connector = aiohttp.TCPConnector(ssl=self.ctx.verify_ssl)
            self._async_client = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
            )
        return self._async_client

    def request_sync(
        self,
        url: Optional[str] = None,
        method: Optional[str] = None,
        data: Optional[dict] = None,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ) -> Response:
        """
        Make a synchronous HTTP request.

        Args:
            url: Target URL (defaults to context URL)
            method: HTTP method (defaults to context method)
            data: POST data
            params: Query parameters
            headers: Additional headers
            cookies: Additional cookies

        Returns:
            Response object
        """
        self.rate_limiter.acquire_sync()

        client = self._get_sync_client()

        # Merge with context defaults
        url = url or self.ctx.target_url
        method = method or self.ctx.method
        all_headers = self.ctx.get_headers()
        if headers:
            all_headers.update(headers)
        all_cookies = self.ctx.cookies.copy()
        if cookies:
            all_cookies.update(cookies)

        start_time = time.monotonic()

        response = client.request(
            method=method.upper(),
            url=url,
            data=data or self.ctx.data or None,
            params=params or self.ctx.params or None,
            headers=all_headers,
            cookies=all_cookies,
        )

        elapsed = time.monotonic() - start_time

        return Response(
            status_code=response.status_code,
            text=response.text,
            content=response.content,
            headers=dict(response.headers),
            elapsed=elapsed,
            url=str(response.url),
        )

    async def request(
        self,
        url: Optional[str] = None,
        method: Optional[str] = None,
        data: Optional[dict] = None,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        cookies: Optional[dict] = None,
    ) -> Response:
        """
        Make an asynchronous HTTP request.

        Args:
            url: Target URL (defaults to context URL)
            method: HTTP method (defaults to context method)
            data: POST data
            params: Query parameters
            headers: Additional headers
            cookies: Additional cookies

        Returns:
            Response object
        """
        await self.rate_limiter.acquire()

        # Merge with context defaults
        url = url or self.ctx.target_url
        method = method or self.ctx.method
        all_headers = self.ctx.get_headers()
        if headers:
            all_headers.update(headers)
        all_cookies = self.ctx.cookies.copy()
        if cookies:
            all_cookies.update(cookies)

        start_time = time.monotonic()

        # Use aiohttp with proxy if configured
        proxy = self.ctx.proxy
        session = await self._get_async_client()

        async with session.request(
            method=method.upper(),
            url=url,
            data=data or self.ctx.data or None,
            params=params or self.ctx.params or None,
            headers=all_headers,
            cookies=all_cookies,
            proxy=proxy,
            ssl=self.ctx.verify_ssl,
        ) as response:
            content = await response.read()
            text = content.decode("utf-8", errors="ignore")
            elapsed = time.monotonic() - start_time

            return Response(
                status_code=response.status,
                text=text,
                content=content,
                headers=dict(response.headers),
                elapsed=elapsed,
                url=str(response.url),
            )

    async def request_with_payload(
        self,
        payload: str,
        inject_in: str = "auto",  # "url", "data", or "auto"
    ) -> Response:
        """
        Make request with payload injected.

        Args:
            payload: Payload to inject
            inject_in: Where to inject ("url" for GET params, "data" for POST)

        Returns:
            Response object
        """
        if inject_in == "auto":
            inject_in = "data" if self.ctx.method.upper() == "POST" else "url"

        if inject_in == "url":
            url = self.ctx.build_url_with_payload(payload)
            return await self.request(url=url)
        else:
            data = self.ctx.build_data_with_payload(payload)
            return await self.request(data=data)

    def request_with_payload_sync(
        self,
        payload: str,
        inject_in: str = "auto",
    ) -> Response:
        """Synchronous version of request_with_payload."""
        if inject_in == "auto":
            inject_in = "data" if self.ctx.method.upper() == "POST" else "url"

        if inject_in == "url":
            url = self.ctx.build_url_with_payload(payload)
            return self.request_sync(url=url)
        else:
            data = self.ctx.build_data_with_payload(payload)
            return self.request_sync(data=data)

    async def close(self) -> None:
        """Close HTTP client connections."""
        if self._async_client:
            await self._async_client.close()
            self._async_client = None
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None

    def close_sync(self) -> None:
        """Close sync HTTP client."""
        if self._sync_client:
            self._sync_client.close()
            self._sync_client = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close_sync()
