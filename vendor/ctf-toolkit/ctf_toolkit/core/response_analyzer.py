"""Response analysis for vulnerability detection."""

import re
from typing import Optional
from dataclasses import dataclass

from .http_client import Response
from .context import AttackContext


@dataclass
class AnalysisResult:
    """Result of response analysis."""
    is_vulnerable: bool
    detection_method: str
    confidence: str  # "high", "medium", "low"
    evidence: str
    details: dict


class ResponseAnalyzer:
    """
    Analyzes HTTP responses for signs of successful injection.
    """

    def __init__(self, ctx: AttackContext, baseline: Optional[Response] = None):
        """
        Initialize analyzer.

        Args:
            ctx: Attack context with detection patterns
            baseline: Baseline response for comparison
        """
        self.ctx = ctx
        self.baseline = baseline
        self.baseline_length = baseline.content_length if baseline else 0
        self.baseline_time = baseline.elapsed if baseline else 0

    def set_baseline(self, response: Response) -> None:
        """Set baseline response for comparison."""
        self.baseline = response
        self.baseline_length = response.content_length
        self.baseline_time = response.elapsed

    def analyze(self, response: Response, payload: str) -> AnalysisResult:
        """
        Analyze response for vulnerability indicators.

        Args:
            response: Response to analyze
            payload: Payload that was sent

        Returns:
            AnalysisResult with findings
        """
        # Check each detection method
        methods = [
            self._check_error_based,
            self._check_success_pattern,
            self._check_length_diff,
            self._check_time_based,
            self._check_status_code,
        ]

        for check_method in methods:
            result = check_method(response, payload)
            if result.is_vulnerable:
                return result

        return AnalysisResult(
            is_vulnerable=False,
            detection_method="none",
            confidence="none",
            evidence="No vulnerability detected",
            details={}
        )

    def _check_error_based(self, response: Response, payload: str) -> AnalysisResult:
        """Check for SQL error messages in response."""
        for pattern in self.ctx.error_patterns:
            match = re.search(pattern, response.text, re.IGNORECASE)
            if match:
                # Determine database type from error
                db_type = self._detect_db_from_error(match.group())

                return AnalysisResult(
                    is_vulnerable=True,
                    detection_method="error_based",
                    confidence="high",
                    evidence=match.group()[:200],
                    details={
                        "db_type": db_type,
                        "pattern_matched": pattern,
                    }
                )

        return AnalysisResult(
            is_vulnerable=False,
            detection_method="error_based",
            confidence="none",
            evidence="",
            details={}
        )

    def _check_success_pattern(self, response: Response, payload: str) -> AnalysisResult:
        """Check for user-defined success pattern."""
        if not self.ctx.success_pattern:
            return AnalysisResult(
                is_vulnerable=False,
                detection_method="success_pattern",
                confidence="none",
                evidence="",
                details={}
            )

        if re.search(self.ctx.success_pattern, response.text, re.IGNORECASE):
            return AnalysisResult(
                is_vulnerable=True,
                detection_method="success_pattern",
                confidence="high",
                evidence=f"Pattern '{self.ctx.success_pattern}' found",
                details={"pattern": self.ctx.success_pattern}
            )

        return AnalysisResult(
            is_vulnerable=False,
            detection_method="success_pattern",
            confidence="none",
            evidence="",
            details={}
        )

    def _check_length_diff(self, response: Response, payload: str) -> AnalysisResult:
        """Check for significant content length difference."""
        if not self.baseline:
            return AnalysisResult(
                is_vulnerable=False,
                detection_method="length_diff",
                confidence="none",
                evidence="No baseline set",
                details={}
            )

        diff = abs(response.content_length - self.baseline_length)

        if diff > self.ctx.length_threshold:
            return AnalysisResult(
                is_vulnerable=True,
                detection_method="length_diff",
                confidence="medium",
                evidence=f"Length diff: {diff} bytes (baseline: {self.baseline_length}, current: {response.content_length})",
                details={
                    "baseline_length": self.baseline_length,
                    "response_length": response.content_length,
                    "difference": diff,
                }
            )

        return AnalysisResult(
            is_vulnerable=False,
            detection_method="length_diff",
            confidence="none",
            evidence="",
            details={"difference": diff}
        )

    def _check_time_based(self, response: Response, payload: str) -> AnalysisResult:
        """Check for time-based blind injection (response delay)."""
        # Check if payload contains time-based indicators
        time_indicators = ["SLEEP", "WAITFOR", "DELAY", "BENCHMARK", "PG_SLEEP"]
        is_time_payload = any(ind.lower() in payload.lower() for ind in time_indicators)

        if not is_time_payload:
            return AnalysisResult(
                is_vulnerable=False,
                detection_method="time_based",
                confidence="none",
                evidence="Not a time-based payload",
                details={}
            )

        if response.elapsed > self.ctx.time_threshold:
            return AnalysisResult(
                is_vulnerable=True,
                detection_method="time_based",
                confidence="high",
                evidence=f"Response time: {response.elapsed:.2f}s (threshold: {self.ctx.time_threshold}s)",
                details={
                    "response_time": response.elapsed,
                    "threshold": self.ctx.time_threshold,
                }
            )

        return AnalysisResult(
            is_vulnerable=False,
            detection_method="time_based",
            confidence="none",
            evidence="",
            details={"response_time": response.elapsed}
        )

    def _check_status_code(self, response: Response, payload: str) -> AnalysisResult:
        """Check for suspicious status code changes."""
        if not self.baseline:
            return AnalysisResult(
                is_vulnerable=False,
                detection_method="status_code",
                confidence="none",
                evidence="",
                details={}
            )

        # 500 errors might indicate SQL errors being suppressed
        if response.status_code == 500 and self.baseline.status_code == 200:
            return AnalysisResult(
                is_vulnerable=True,
                detection_method="status_code",
                confidence="low",
                evidence=f"Status changed from {self.baseline.status_code} to {response.status_code}",
                details={
                    "baseline_status": self.baseline.status_code,
                    "response_status": response.status_code,
                }
            )

        return AnalysisResult(
            is_vulnerable=False,
            detection_method="status_code",
            confidence="none",
            evidence="",
            details={}
        )

    def _detect_db_from_error(self, error_text: str) -> Optional[str]:
        """Detect database type from error message."""
        error_lower = error_text.lower()

        if "mysql" in error_lower:
            return "mysql"
        elif "postgresql" in error_lower or "pg::" in error_lower:
            return "postgresql"
        elif "ora-" in error_lower or "oracle" in error_lower:
            return "oracle"
        elif "sql server" in error_lower or "mssql" in error_lower:
            return "mssql"
        elif "sqlite" in error_lower:
            return "sqlite"

        return None

    def compare_responses(self, resp1: Response, resp2: Response) -> dict:
        """
        Compare two responses and return differences.

        Useful for boolean-based blind SQLi detection.
        """
        return {
            "length_diff": abs(resp1.content_length - resp2.content_length),
            "time_diff": abs(resp1.elapsed - resp2.elapsed),
            "status_diff": resp1.status_code != resp2.status_code,
            "resp1_length": resp1.content_length,
            "resp2_length": resp2.content_length,
            "resp1_time": resp1.elapsed,
            "resp2_time": resp2.elapsed,
        }

    def is_boolean_diff(self, true_response: Response, false_response: Response) -> bool:
        """
        Check if there's a detectable difference between true/false responses.

        Used for boolean-based blind SQLi.
        """
        comparison = self.compare_responses(true_response, false_response)
        return (
            comparison["length_diff"] > self.ctx.length_threshold
            or comparison["status_diff"]
        )
