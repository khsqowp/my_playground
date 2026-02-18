"""WAF (Web Application Firewall) detection module."""

import re
import asyncio
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

from ..core.http_client import HttpClient, Response
from ..core.context import AttackContext


class WafType(Enum):
    """Known WAF types."""
    CLOUDFLARE = "cloudflare"
    MODSECURITY = "modsecurity"
    AWS_WAF = "aws_waf"
    AKAMAI = "akamai"
    IMPERVA = "imperva"
    F5_BIG_IP = "f5_big_ip"
    BARRACUDA = "barracuda"
    SUCURI = "sucuri"
    WORDFENCE = "wordfence"
    FORTINET = "fortinet"
    CITRIX = "citrix"
    PALO_ALTO = "palo_alto"
    RADWARE = "radware"
    AZURE_WAF = "azure_waf"
    GOOGLE_CLOUD_ARMOR = "google_cloud_armor"
    ALIBABA_CLOUD = "alibaba_cloud"
    TENCENT_CLOUD = "tencent_cloud"
    WALLARM = "wallarm"
    REBLAZE = "reblaze"
    SQREEN = "sqreen"
    COMODO = "comodo"
    UNKNOWN = "unknown"
    NONE = "none"


@dataclass
class WafSignature:
    """WAF detection signature."""
    name: str
    waf_type: WafType
    headers: dict[str, str] = field(default_factory=dict)  # header: regex pattern
    cookies: list[str] = field(default_factory=list)
    body_patterns: list[str] = field(default_factory=list)
    status_codes: list[int] = field(default_factory=list)
    server_header: Optional[str] = None


@dataclass
class WafResult:
    """Result of WAF detection."""
    detected: bool
    waf_type: WafType
    waf_name: str
    confidence: float  # 0.0 - 1.0
    evidence: list[str]
    blocked_patterns: list[str] = field(default_factory=list)
    bypass_suggestions: list[str] = field(default_factory=list)


class WafDetector:
    """
    Detects WAF presence and type.

    Supports 20+ common WAF signatures including:
    - Cloud WAFs: Cloudflare, AWS WAF, Azure WAF, GCP Cloud Armor
    - Commercial: Akamai, Imperva, F5, Fortinet, Palo Alto
    - Open Source: ModSecurity
    - WordPress: Wordfence, Sucuri
    """

    WAF_SIGNATURES: list[WafSignature] = [
        # Cloudflare
        WafSignature(
            name="Cloudflare",
            waf_type=WafType.CLOUDFLARE,
            headers={
                "cf-ray": r".*",
                "cf-cache-status": r".*",
                "server": r"cloudflare",
                "cf-request-id": r".*",
            },
            cookies=["__cfduid", "__cf_bm", "cf_clearance"],
            body_patterns=[
                r"attention\s*required.*cloudflare",
                r"ray\s*id:",
                r"cloudflare",
                r"error\s*code:\s*1",
            ],
            status_codes=[403, 503],
        ),
        # ModSecurity
        WafSignature(
            name="ModSecurity",
            waf_type=WafType.MODSECURITY,
            headers={
                "server": r"mod_security|modsecurity",
            },
            body_patterns=[
                r"mod_security",
                r"modsecurity",
                r"this\s*error\s*was\s*generated\s*by\s*mod_security",
                r"not\s*acceptable.*security\s*module",
                r"owasp.*modsecurity.*core\s*rule\s*set",
            ],
            status_codes=[403, 406],
        ),
        # AWS WAF
        WafSignature(
            name="AWS WAF",
            waf_type=WafType.AWS_WAF,
            headers={
                "x-amzn-requestid": r".*",
                "x-amz-cf-id": r".*",
            },
            body_patterns=[
                r"aws\s*waf",
                r"request\s*blocked",
                r"<title>403\s*Forbidden</title>.*amazon",
            ],
            status_codes=[403],
        ),
        # Akamai
        WafSignature(
            name="Akamai Kona",
            waf_type=WafType.AKAMAI,
            headers={
                "server": r"akamai.*ghost|akamaighost",
                "x-akamai-transformed": r".*",
            },
            body_patterns=[
                r"akamai",
                r"reference\s*#\d+\.\w+\.\d+",
                r"access\s*denied.*akamai",
            ],
            status_codes=[403],
        ),
        # Imperva/Incapsula
        WafSignature(
            name="Imperva Incapsula",
            waf_type=WafType.IMPERVA,
            headers={
                "x-iinfo": r".*",
                "x-cdn": r"incapsula",
            },
            cookies=["incap_ses_", "visid_incap_", "nlbi_"],
            body_patterns=[
                r"incapsula",
                r"powered\s*by\s*incapsula",
                r"request\s*unsuccessful.*incapsula",
            ],
            status_codes=[403],
        ),
        # F5 BIG-IP ASM
        WafSignature(
            name="F5 BIG-IP ASM",
            waf_type=WafType.F5_BIG_IP,
            headers={
                "server": r"big-?ip|bigip",
                "x-cnection": r".*",
            },
            cookies=["TS", "BIGipServer", "F5_"],
            body_patterns=[
                r"the\s*requested\s*url\s*was\s*rejected",
                r"please\s*consult\s*with\s*your\s*administrator",
                r"support\s*id:\s*\d+",
            ],
            status_codes=[403],
        ),
        # Barracuda
        WafSignature(
            name="Barracuda WAF",
            waf_type=WafType.BARRACUDA,
            headers={
                "server": r"barracuda",
            },
            cookies=["barra_counter_session"],
            body_patterns=[
                r"barracuda",
                r"you\s*are\s*blocked",
                r"barracuda\s*networks",
            ],
            status_codes=[403],
        ),
        # Sucuri
        WafSignature(
            name="Sucuri CloudProxy",
            waf_type=WafType.SUCURI,
            headers={
                "server": r"sucuri",
                "x-sucuri-id": r".*",
                "x-sucuri-cache": r".*",
            },
            body_patterns=[
                r"sucuri",
                r"cloudproxy",
                r"access\s*denied.*sucuri",
            ],
            status_codes=[403],
        ),
        # Wordfence
        WafSignature(
            name="Wordfence",
            waf_type=WafType.WORDFENCE,
            body_patterns=[
                r"wordfence",
                r"generated\s*by\s*wordfence",
                r"your\s*access\s*to\s*this\s*site\s*has\s*been\s*limited",
                r"block\s*reason:",
            ],
            status_codes=[403],
        ),
        # Fortinet FortiWeb
        WafSignature(
            name="Fortinet FortiWeb",
            waf_type=WafType.FORTINET,
            headers={
                "server": r"fortiweb",
            },
            cookies=["FORTIWAFSID"],
            body_patterns=[
                r"fortinet|fortiweb",
                r"fortigate",
                r".fgd_icon",
            ],
            status_codes=[403],
        ),
        # Citrix NetScaler
        WafSignature(
            name="Citrix NetScaler",
            waf_type=WafType.CITRIX,
            headers={
                "cneonction": r".*",
                "nncoection": r".*",
                "via": r"ns-cache",
            },
            cookies=["citrix_ns_id", "NSC_"],
            body_patterns=[
                r"citrix",
                r"netscaler",
                r"appfw\s*session",
            ],
            status_codes=[403],
        ),
        # Palo Alto
        WafSignature(
            name="Palo Alto Networks",
            waf_type=WafType.PALO_ALTO,
            body_patterns=[
                r"palo\s*alto\s*networks",
                r"has\s*been\s*blocked\s*in\s*accordance",
                r"url\s*filtering\s*profile",
            ],
            status_codes=[403],
        ),
        # Radware AppWall
        WafSignature(
            name="Radware AppWall",
            waf_type=WafType.RADWARE,
            headers={
                "x-sl-compstate": r".*",
            },
            body_patterns=[
                r"radware",
                r"unauthorized\s*activity\s*has\s*been\s*detected",
            ],
            status_codes=[403],
        ),
        # Azure WAF
        WafSignature(
            name="Azure Web Application Firewall",
            waf_type=WafType.AZURE_WAF,
            headers={
                "x-azure-ref": r".*",
                "x-ms-request-id": r".*",
            },
            body_patterns=[
                r"azure",
                r"microsoft",
                r"<title>403.*azure</title>",
            ],
            status_codes=[403],
        ),
        # Google Cloud Armor
        WafSignature(
            name="Google Cloud Armor",
            waf_type=WafType.GOOGLE_CLOUD_ARMOR,
            headers={
                "x-goog-": r".*",
                "via": r"google",
            },
            body_patterns=[
                r"google\s*cloud\s*armor",
                r"access\s*denied\s*by\s*security\s*policy",
            ],
            status_codes=[403],
        ),
        # Alibaba Cloud WAF
        WafSignature(
            name="Alibaba Cloud WAF",
            waf_type=WafType.ALIBABA_CLOUD,
            headers={
                "server": r"aliyun",
            },
            cookies=["aliyungf_tc"],
            body_patterns=[
                r"aliyun",
                r"alibaba\s*cloud",
                r"anti-bot\s*verification",
            ],
            status_codes=[403, 405],
        ),
        # Tencent Cloud WAF
        WafSignature(
            name="Tencent Cloud WAF",
            waf_type=WafType.TENCENT_CLOUD,
            headers={
                "server": r"tencent",
            },
            body_patterns=[
                r"tencent",
                r"waf.*tencent",
            ],
            status_codes=[403],
        ),
        # Wallarm
        WafSignature(
            name="Wallarm",
            waf_type=WafType.WALLARM,
            headers={
                "server": r"nginx.*wallarm",
            },
            body_patterns=[
                r"wallarm",
            ],
            status_codes=[403],
        ),
        # Reblaze
        WafSignature(
            name="Reblaze",
            waf_type=WafType.REBLAZE,
            cookies=["rbzid"],
            body_patterns=[
                r"reblaze",
                r"www\.reblaze\.com",
            ],
            status_codes=[403],
        ),
        # Comodo WAF
        WafSignature(
            name="Comodo WAF",
            waf_type=WafType.COMODO,
            headers={
                "server": r"comodo",
            },
            body_patterns=[
                r"comodo",
                r"protected\s*by\s*comodo",
            ],
            status_codes=[403],
        ),
    ]

    # Attack probes to trigger WAF
    PROBE_PAYLOADS = [
        # SQL Injection probes
        "' OR '1'='1",
        "1' AND '1'='1' --",
        "UNION SELECT NULL--",
        "1'; WAITFOR DELAY '0:0:5'--",

        # XSS probes
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",

        # Command injection probes
        "; ls -la",
        "| cat /etc/passwd",
        "$(whoami)",

        # Path traversal probes
        "../../../etc/passwd",
        "....//....//....//etc/passwd",

        # General malicious patterns
        "/admin' --",
        "<?php system($_GET['cmd']); ?>",
    ]

    def __init__(self, ctx: AttackContext):
        """
        Initialize WAF detector.

        Args:
            ctx: Attack context
        """
        self.ctx = ctx
        self.client = HttpClient(ctx)
        self._compiled_signatures: list[tuple[WafSignature, dict]] = []
        self._compile_signatures()

    def _compile_signatures(self) -> None:
        """Pre-compile signature patterns."""
        for sig in self.WAF_SIGNATURES:
            compiled = {
                "headers": {h: re.compile(p, re.IGNORECASE) for h, p in sig.headers.items()},
                "body": [re.compile(p, re.IGNORECASE) for p in sig.body_patterns],
            }
            self._compiled_signatures.append((sig, compiled))

    async def detect(
        self,
        probe: bool = True,
        num_probes: int = 5
    ) -> WafResult:
        """
        Detect WAF presence and type.

        Args:
            probe: Whether to send attack probes
            num_probes: Number of probes to send

        Returns:
            WafResult with detection details
        """
        # First, check baseline response
        baseline = await self.client.request()
        result = self._analyze_response(baseline, is_probe=False)

        if result.detected:
            await self.client.close()
            return result

        # If not detected in baseline, try with probes
        if probe:
            blocked_patterns = []

            for payload in self.PROBE_PAYLOADS[:num_probes]:
                try:
                    resp = await self.client.request_with_payload(payload)
                    probe_result = self._analyze_response(resp, is_probe=True)

                    if probe_result.detected:
                        blocked_patterns.append(payload)

                        # If we found a WAF, return it
                        if probe_result.waf_type != WafType.UNKNOWN:
                            probe_result.blocked_patterns = blocked_patterns
                            probe_result.bypass_suggestions = self._get_bypass_suggestions(probe_result.waf_type)
                            await self.client.close()
                            return probe_result

                except Exception:
                    # Connection reset might indicate WAF
                    blocked_patterns.append(payload)

            # If probes were blocked but WAF type unknown
            if blocked_patterns:
                await self.client.close()
                return WafResult(
                    detected=True,
                    waf_type=WafType.UNKNOWN,
                    waf_name="Unknown WAF",
                    confidence=0.7,
                    evidence=[f"Blocked {len(blocked_patterns)} attack probes"],
                    blocked_patterns=blocked_patterns,
                    bypass_suggestions=self._get_bypass_suggestions(WafType.UNKNOWN),
                )

        await self.client.close()
        return WafResult(
            detected=False,
            waf_type=WafType.NONE,
            waf_name="No WAF Detected",
            confidence=0.8,
            evidence=["No WAF signatures found"],
        )

    def _analyze_response(self, response: Response, is_probe: bool = False) -> WafResult:
        """
        Analyze response for WAF signatures.

        Args:
            response: HTTP response to analyze
            is_probe: Whether this is a probe response

        Returns:
            WafResult with detection details
        """
        evidence = []
        best_match: Optional[WafSignature] = None
        best_score = 0.0

        for sig, compiled in self._compiled_signatures:
            score = 0.0
            sig_evidence = []

            # Check headers
            for header_name, pattern in compiled["headers"].items():
                header_val = response.headers.get(header_name, "")
                if pattern.search(header_val):
                    score += 0.4
                    sig_evidence.append(f"header:{header_name}={header_val[:50]}")

            # Check cookies
            set_cookie = response.headers.get("set-cookie", "")
            for cookie in sig.cookies:
                if cookie.lower() in set_cookie.lower():
                    score += 0.3
                    sig_evidence.append(f"cookie:{cookie}")

            # Check body patterns
            for pattern in compiled["body"]:
                if pattern.search(response.text):
                    score += 0.5
                    sig_evidence.append(f"body_pattern:{pattern.pattern[:30]}")
                    break  # One body match is enough

            # Check status code
            if response.status_code in sig.status_codes:
                if is_probe:
                    score += 0.3
                    sig_evidence.append(f"status:{response.status_code}")

            # Check server header specifically
            if sig.server_header:
                server = response.headers.get("server", "")
                if re.search(sig.server_header, server, re.IGNORECASE):
                    score += 0.3
                    sig_evidence.append(f"server:{server}")

            if score > best_score:
                best_score = score
                best_match = sig
                evidence = sig_evidence

        # Determine if WAF detected
        threshold = 0.5
        if best_match and best_score >= threshold:
            return WafResult(
                detected=True,
                waf_type=best_match.waf_type,
                waf_name=best_match.name,
                confidence=min(best_score, 1.0),
                evidence=evidence,
                bypass_suggestions=self._get_bypass_suggestions(best_match.waf_type),
            )

        # Check for generic WAF indicators
        generic_indicators = []
        if response.status_code in [403, 406, 429]:
            generic_indicators.append(f"status:{response.status_code}")

        blocked_patterns = [
            r"access\s*denied",
            r"request\s*blocked",
            r"forbidden",
            r"security\s*violation",
            r"not\s*acceptable",
        ]
        for pattern in blocked_patterns:
            if re.search(pattern, response.text, re.IGNORECASE):
                generic_indicators.append(f"body:{pattern}")

        if generic_indicators and is_probe:
            return WafResult(
                detected=True,
                waf_type=WafType.UNKNOWN,
                waf_name="Unknown WAF",
                confidence=0.5,
                evidence=generic_indicators,
            )

        return WafResult(
            detected=False,
            waf_type=WafType.NONE,
            waf_name="No WAF",
            confidence=0.0,
            evidence=[],
        )

    async def probe_sensitivity(
        self,
        probe_types: Optional[list[str]] = None
    ) -> dict[str, bool]:
        """
        Test which attack patterns are blocked.

        Args:
            probe_types: Types of probes to test (sqli, xss, cmdi, lfi)

        Returns:
            Dict mapping payload to blocked status
        """
        results = {}

        # Get baseline
        baseline = await self.client.request()

        # Categorized probes
        probes = {
            "sqli": [
                "' OR '1'='1",
                "1 AND 1=1",
                "UNION SELECT NULL",
                "'; DROP TABLE--",
            ],
            "xss": [
                "<script>alert(1)</script>",
                "<img src=x onerror=alert(1)>",
                "'-alert(1)-'",
            ],
            "cmdi": [
                "; ls",
                "| cat /etc/passwd",
                "$(whoami)",
            ],
            "lfi": [
                "../../../etc/passwd",
                "/etc/passwd",
                "php://filter",
            ],
        }

        test_probes = []
        if probe_types:
            for pt in probe_types:
                if pt in probes:
                    test_probes.extend(probes[pt])
        else:
            for payloads in probes.values():
                test_probes.extend(payloads)

        for payload in test_probes:
            try:
                resp = await self.client.request_with_payload(payload)
                # Consider blocked if status is error or response changed significantly
                is_blocked = (
                    resp.status_code in [403, 406, 429, 503]
                    or abs(resp.content_length - baseline.content_length) > 500
                    or resp.status_code != baseline.status_code
                )
                results[payload] = is_blocked
            except Exception:
                results[payload] = True  # Connection error = blocked

            await asyncio.sleep(0.5)  # Rate limit

        await self.client.close()
        return results

    def _get_bypass_suggestions(self, waf_type: WafType) -> list[str]:
        """Get bypass suggestions for specific WAF."""
        common_bypasses = [
            "Try case variation: sElEcT, ScRiPt",
            "Use URL encoding: %27 for '",
            "Try double URL encoding: %2527",
            "Use Unicode encoding: \\u0027",
            "Try comment injection: SEL/**/ECT",
            "Use whitespace alternatives: SELECT%09*",
        ]

        waf_specific = {
            WafType.CLOUDFLARE: [
                "Try chunked transfer encoding",
                "Use HTTP/2 specific bypasses",
                "Test with different User-Agents",
            ],
            WafType.MODSECURITY: [
                "Check ModSec paranoia level (CRS)",
                "Try HPP (HTTP Parameter Pollution)",
                "Use multipart form-data encoding",
            ],
            WafType.AWS_WAF: [
                "Check for rule-specific bypasses",
                "Try Origin header manipulation",
                "Test with different Content-Types",
            ],
            WafType.IMPERVA: [
                "Try path normalization bypass",
                "Use JSON encoding for payloads",
                "Test session-based bypass",
            ],
        }

        suggestions = common_bypasses.copy()
        if waf_type in waf_specific:
            suggestions.extend(waf_specific[waf_type])

        return suggestions

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.close()
