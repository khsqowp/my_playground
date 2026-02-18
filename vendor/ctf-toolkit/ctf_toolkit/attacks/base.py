"""Base class for attack modules."""

from abc import ABC, abstractmethod
from typing import Any, Optional
import asyncio

from ..core.context import AttackContext
from ..core.http_client import HttpClient, Response
from ..core.response_analyzer import ResponseAnalyzer, AnalysisResult


class AttackModule(ABC):
    """Abstract base class for attack modules."""

    def __init__(self, ctx: AttackContext):
        """
        Initialize attack module.

        Args:
            ctx: Attack context with configuration
        """
        self.ctx = ctx
        self.client = HttpClient(ctx)
        self.analyzer: Optional[ResponseAnalyzer] = None
        self.results: list[dict] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Module name."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Module description."""
        pass

    async def setup(self) -> None:
        """
        Setup before scanning (e.g., get baseline response).
        Override in subclass if needed.
        """
        # Get baseline response
        baseline = await self.client.request()
        self.analyzer = ResponseAnalyzer(self.ctx, baseline)

    def setup_sync(self) -> None:
        """Synchronous setup."""
        baseline = self.client.request_sync()
        self.analyzer = ResponseAnalyzer(self.ctx, baseline)

    @abstractmethod
    async def scan(self, payloads: list[str]) -> list[dict]:
        """
        Scan target with payloads.

        Args:
            payloads: List of payloads to test

        Returns:
            List of findings
        """
        pass

    @abstractmethod
    def scan_sync(self, payloads: list[str]) -> list[dict]:
        """Synchronous scan."""
        pass

    async def test_payload(self, payload: str) -> tuple[Response, AnalysisResult]:
        """
        Test a single payload.

        Args:
            payload: Payload to test

        Returns:
            Tuple of (response, analysis_result)
        """
        response = await self.client.request_with_payload(payload)
        if self.analyzer:
            result = self.analyzer.analyze(response, payload)
        else:
            result = AnalysisResult(
                is_vulnerable=False,
                detection_method="none",
                confidence="none",
                evidence="Analyzer not initialized",
                details={}
            )
        return response, result

    def test_payload_sync(self, payload: str) -> tuple[Response, AnalysisResult]:
        """Synchronous payload test."""
        response = self.client.request_with_payload_sync(payload)
        if self.analyzer:
            result = self.analyzer.analyze(response, payload)
        else:
            result = AnalysisResult(
                is_vulnerable=False,
                detection_method="none",
                confidence="none",
                evidence="Analyzer not initialized",
                details={}
            )
        return response, result

    def add_finding(
        self,
        vuln_type: str,
        payload: str,
        evidence: str,
        confidence: str = "high",
        details: Optional[dict] = None
    ) -> None:
        """Record a vulnerability finding."""
        finding = {
            "type": vuln_type,
            "url": self.ctx.target_url,
            "parameter": self.ctx.inject_param,
            "payload": payload,
            "evidence": evidence,
            "confidence": confidence,
            "details": details or {},
        }
        self.results.append(finding)
        self.ctx.add_vulnerability(vuln_type, payload, evidence, confidence)

    def get_results(self) -> list[dict]:
        """Get all findings."""
        return self.results

    async def cleanup(self) -> None:
        """Cleanup after scanning."""
        await self.client.close()

    def cleanup_sync(self) -> None:
        """Synchronous cleanup."""
        self.client.close_sync()

    async def __aenter__(self):
        await self.setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.cleanup()

    def __enter__(self):
        self.setup_sync()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup_sync()
