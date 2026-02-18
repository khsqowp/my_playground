"""Target fingerprinting module."""

from typing import Optional
import asyncio

from ..core.context import AttackContext
from ..core.http_client import HttpClient, Response
from ..utils.logger import console, log_info, log_success, print_section
from .tech_detector import TechDetector, TechFingerprint


class Fingerprinter:
    """Orchestrates target fingerprinting."""

    def __init__(self, ctx: AttackContext):
        """
        Initialize fingerprinter.

        Args:
            ctx: Attack context
        """
        self.ctx = ctx
        self.client = HttpClient(ctx)
        self.detector = TechDetector()
        self.fingerprint: Optional[TechFingerprint] = None

    async def fingerprint(self) -> TechFingerprint:
        """
        Perform full fingerprinting of target.

        Returns:
            TechFingerprint with detected technologies
        """
        log_info(f"Fingerprinting target: {self.ctx.target_url}")

        # Get initial response
        response = await self.client.request()

        # Detect from headers
        self.detector.detect_from_headers(response.headers)

        # Detect from body
        self.detector.detect_from_body(response.text)

        # Detect from cookies if present
        if "set-cookie" in {k.lower() for k in response.headers.keys()}:
            cookies = self._parse_cookies(response.headers)
            self.detector.detect_from_cookies(cookies)

        # Additional probes
        await self._probe_common_paths()

        self.fingerprint = self.detector.fingerprint

        # Update context with findings
        self.ctx.server_type = self.fingerprint.web_server
        self.ctx.db_type = self.fingerprint.database
        self.ctx.os_type = self.fingerprint.os

        await self.client.close()

        return self.fingerprint

    def fingerprint_sync(self) -> TechFingerprint:
        """Synchronous fingerprinting."""
        log_info(f"Fingerprinting target: {self.ctx.target_url}")

        response = self.client.request_sync()

        self.detector.detect_from_headers(response.headers)
        self.detector.detect_from_body(response.text)

        if "set-cookie" in {k.lower() for k in response.headers.keys()}:
            cookies = self._parse_cookies(response.headers)
            self.detector.detect_from_cookies(cookies)

        self.fingerprint = self.detector.fingerprint

        self.ctx.server_type = self.fingerprint.web_server
        self.ctx.db_type = self.fingerprint.database
        self.ctx.os_type = self.fingerprint.os

        self.client.close_sync()

        return self.fingerprint

    async def _probe_common_paths(self) -> None:
        """Probe common paths for additional fingerprinting."""
        probe_paths = [
            "/robots.txt",
            "/sitemap.xml",
            "/.git/HEAD",
            "/wp-admin/",
            "/administrator/",
            "/phpmyadmin/",
            "/server-status",
            "/.env",
        ]

        tasks = []
        for path in probe_paths:
            url = self.ctx.target_url.rstrip("/") + path
            tasks.append(self._probe_path(url))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _probe_path(self, url: str) -> None:
        """Probe a single path."""
        try:
            response = await self.client.request(url=url)

            if response.status_code == 200:
                # Analyze response
                self.detector.detect_from_body(response.text)

                # Specific detections
                if "/.git/HEAD" in url and "ref:" in response.text:
                    self.detector.fingerprint.other.append("git_exposed")

                if "/.env" in url and ("DB_" in response.text or "APP_" in response.text):
                    self.detector.fingerprint.other.append("env_exposed")

        except Exception:
            pass  # Ignore probe failures

    def _parse_cookies(self, headers: dict[str, str]) -> dict[str, str]:
        """Parse Set-Cookie headers into dict."""
        cookies = {}
        for key, value in headers.items():
            if key.lower() == "set-cookie":
                # Simple parsing - just get cookie name
                if "=" in value:
                    name = value.split("=")[0]
                    cookies[name] = value
        return cookies

    def print_results(self) -> None:
        """Print fingerprinting results in a nice format."""
        if not self.fingerprint:
            console.print("[yellow]No fingerprint data available[/yellow]")
            return

        print_section("FINGERPRINT RESULTS")

        fp = self.fingerprint

        results = [
            ("Web Server", fp.web_server, fp.web_server_version),
            ("Operating System", fp.os, None),
            ("Language", fp.language, None),
            ("Framework", fp.framework, None),
            ("Database", fp.database, None),
            ("CMS", fp.cms, None),
            ("CDN", fp.cdn, None),
            ("WAF", fp.waf, None),
        ]

        for name, value, version in results:
            if value:
                if version:
                    console.print(f"  [cyan]{name}:[/cyan] {value} ({version})")
                else:
                    console.print(f"  [cyan]{name}:[/cyan] {value}")

        if fp.other:
            console.print(f"  [cyan]Other:[/cyan] {', '.join(fp.other)}")

        # Warnings
        if fp.waf:
            console.print(f"\n[yellow][!] WAF Detected: {fp.waf}[/yellow]")
            console.print("[yellow]    Consider using WAF bypass techniques[/yellow]")

        if "git_exposed" in fp.other:
            console.print("\n[red][!] Git repository exposed![/red]")

        if "env_exposed" in fp.other:
            console.print("\n[red][!] Environment file exposed![/red]")


async def quick_fingerprint(url: str) -> TechFingerprint:
    """
    Quick fingerprinting utility function.

    Args:
        url: Target URL

    Returns:
        TechFingerprint
    """
    ctx = AttackContext(target_url=url)
    fingerprinter = Fingerprinter(ctx)
    return await fingerprinter.fingerprint()
