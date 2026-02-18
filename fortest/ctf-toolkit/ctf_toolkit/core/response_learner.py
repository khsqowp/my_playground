"""Response pattern learning for intelligent vulnerability detection."""

import hashlib
import re
import statistics
from dataclasses import dataclass, field
from typing import Optional
from collections import Counter

from .http_client import Response


@dataclass
class ResponseFeatures:
    """Extracted features from an HTTP response."""
    content_length: int
    response_time: float
    status_code: int
    content_hash: str
    structure_hash: str  # HTML structure without text
    error_keywords: list[str] = field(default_factory=list)
    has_forms: bool = False
    has_scripts: bool = False
    header_signature: str = ""
    word_count: int = 0
    line_count: int = 0


@dataclass
class BaselineStats:
    """Statistical baseline from learned responses."""
    length_mean: float
    length_std: float
    time_mean: float
    time_std: float
    common_status: int
    structure_hashes: set[str]
    error_frequency: Counter
    sample_count: int


class ResponseLearner:
    """
    Learns response patterns to distinguish normal vs anomalous responses.

    Used to:
    - Detect successful injections by identifying anomalies
    - Reduce false positives by understanding normal behavior
    - Identify error messages and patterns
    """

    # Common error keywords by category
    ERROR_PATTERNS = {
        "sql": [
            r"sql\s*syntax", r"mysql", r"sqlite", r"postgresql", r"ora-\d+",
            r"sql\s*server", r"mssql", r"syntax\s*error", r"unclosed\s*quotation",
            r"quoted\s*string", r"SQLSTATE", r"database\s*error", r"query\s*failed",
        ],
        "php": [
            r"fatal\s*error", r"parse\s*error", r"warning:", r"notice:",
            r"undefined\s*variable", r"undefined\s*index", r"call\s*to\s*undefined",
        ],
        "python": [
            r"traceback", r"exception", r"error:", r"syntaxerror",
            r"typeerror", r"valueerror", r"keyerror",
        ],
        "java": [
            r"java\.lang\.", r"exception", r"at\s+\w+\.\w+\(", r"stacktrace",
            r"nullpointerexception", r"classnotfoundexception",
        ],
        "general": [
            r"error", r"exception", r"failed", r"invalid", r"denied",
            r"forbidden", r"unauthorized", r"internal\s*server",
        ],
    }

    # WAF/Security filter indicators
    BLOCKED_PATTERNS = [
        r"access\s*denied", r"request\s*blocked", r"security\s*violation",
        r"waf", r"firewall", r"forbidden", r"suspicious\s*activity",
        r"attack\s*detected", r"malicious", r"not\s*allowed",
    ]

    def __init__(self, sensitivity: float = 2.0):
        """
        Initialize ResponseLearner.

        Args:
            sensitivity: Number of standard deviations for anomaly detection
        """
        self.sensitivity = sensitivity
        self.responses: list[Response] = []
        self.features: list[ResponseFeatures] = []
        self.baseline: Optional[BaselineStats] = None
        self._compiled_patterns: dict[str, list[re.Pattern]] = {}
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for category, patterns in self.ERROR_PATTERNS.items():
            self._compiled_patterns[category] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]
        self._compiled_patterns["blocked"] = [
            re.compile(p, re.IGNORECASE) for p in self.BLOCKED_PATTERNS
        ]

    def extract_features(self, response: Response) -> ResponseFeatures:
        """
        Extract features from a response for comparison.

        Args:
            response: HTTP response to analyze

        Returns:
            ResponseFeatures with extracted data
        """
        text = response.text

        # Content hash
        content_hash = hashlib.md5(response.content).hexdigest()[:16]

        # Structure hash - remove text content, keep HTML structure
        structure = re.sub(r'>([^<]+)<', '><', text)
        structure = re.sub(r'\s+', '', structure)
        structure_hash = hashlib.md5(structure.encode()).hexdigest()[:16]

        # Find error keywords
        error_keywords = []
        for category, patterns in self._compiled_patterns.items():
            if category == "blocked":
                continue
            for pattern in patterns:
                if pattern.search(text):
                    error_keywords.append(f"{category}:{pattern.pattern}")

        # Check for forms and scripts
        has_forms = bool(re.search(r'<form[^>]*>', text, re.IGNORECASE))
        has_scripts = bool(re.search(r'<script[^>]*>', text, re.IGNORECASE))

        # Header signature
        important_headers = ["content-type", "x-powered-by", "server"]
        header_parts = []
        for h in important_headers:
            if h in response.headers:
                header_parts.append(f"{h}:{response.headers[h]}")
        header_signature = "|".join(sorted(header_parts))

        # Text stats
        word_count = len(text.split())
        line_count = len(text.splitlines())

        return ResponseFeatures(
            content_length=response.content_length,
            response_time=response.elapsed,
            status_code=response.status_code,
            content_hash=content_hash,
            structure_hash=structure_hash,
            error_keywords=error_keywords,
            has_forms=has_forms,
            has_scripts=has_scripts,
            header_signature=header_signature,
            word_count=word_count,
            line_count=line_count,
        )

    def learn_baseline(self, responses: list[Response]) -> None:
        """
        Learn baseline patterns from a set of responses.

        Args:
            responses: List of normal responses to learn from
        """
        if not responses:
            return

        self.responses = responses
        self.features = [self.extract_features(r) for r in responses]

        lengths = [f.content_length for f in self.features]
        times = [f.response_time for f in self.features]
        statuses = [f.status_code for f in self.features]

        # Calculate statistics
        length_mean = statistics.mean(lengths)
        length_std = statistics.stdev(lengths) if len(lengths) > 1 else 0
        time_mean = statistics.mean(times)
        time_std = statistics.stdev(times) if len(times) > 1 else 0

        # Most common status code
        status_counter = Counter(statuses)
        common_status = status_counter.most_common(1)[0][0]

        # Unique structure hashes (normal page variations)
        structure_hashes = {f.structure_hash for f in self.features}

        # Error frequency
        error_frequency: Counter = Counter()
        for f in self.features:
            error_frequency.update(f.error_keywords)

        self.baseline = BaselineStats(
            length_mean=length_mean,
            length_std=length_std,
            time_mean=time_mean,
            time_std=time_std,
            common_status=common_status,
            structure_hashes=structure_hashes,
            error_frequency=error_frequency,
            sample_count=len(responses),
        )

    def add_sample(self, response: Response) -> None:
        """
        Add a single sample to the baseline.

        Args:
            response: Response to add
        """
        self.responses.append(response)
        self.features.append(self.extract_features(response))
        # Recalculate baseline
        self.learn_baseline(self.responses)

    def is_anomaly(
        self,
        response: Response,
        check_length: bool = True,
        check_time: bool = True,
        check_status: bool = True,
        check_structure: bool = True,
        check_errors: bool = True,
    ) -> tuple[bool, float, str]:
        """
        Check if a response is anomalous compared to baseline.

        Args:
            response: Response to check
            check_length: Check content length anomaly
            check_time: Check response time anomaly
            check_status: Check status code changes
            check_structure: Check HTML structure changes
            check_errors: Check for new error patterns

        Returns:
            Tuple of (is_anomaly, confidence, reason)
        """
        if not self.baseline:
            return False, 0.0, "No baseline established"

        features = self.extract_features(response)
        reasons = []
        scores = []

        # Length anomaly
        if check_length and self.baseline.length_std > 0:
            z_score = abs(features.content_length - self.baseline.length_mean) / self.baseline.length_std
            if z_score > self.sensitivity:
                reasons.append(f"length_diff:{features.content_length - int(self.baseline.length_mean)}")
                scores.append(min(z_score / self.sensitivity, 2.0))

        # Time anomaly (especially for time-based injection)
        if check_time and self.baseline.time_std > 0:
            z_score = (features.response_time - self.baseline.time_mean) / self.baseline.time_std
            if z_score > self.sensitivity:
                reasons.append(f"time_delay:{features.response_time - self.baseline.time_mean:.2f}s")
                scores.append(min(z_score / self.sensitivity, 2.0))

        # Status code change
        if check_status and features.status_code != self.baseline.common_status:
            reasons.append(f"status_change:{self.baseline.common_status}->{features.status_code}")
            # 500 errors are highly suspicious
            if features.status_code == 500:
                scores.append(1.5)
            else:
                scores.append(0.8)

        # Structure change (new page layout)
        if check_structure and features.structure_hash not in self.baseline.structure_hashes:
            reasons.append("structure_changed")
            scores.append(1.0)

        # New error patterns
        if check_errors:
            new_errors = [e for e in features.error_keywords if e not in self.baseline.error_frequency]
            if new_errors:
                reasons.append(f"new_errors:{','.join(new_errors[:3])}")
                # SQL errors are highly indicative
                sql_errors = [e for e in new_errors if e.startswith("sql:")]
                if sql_errors:
                    scores.append(2.0)
                else:
                    scores.append(1.2)

        if not reasons:
            return False, 0.0, "Normal response"

        # Calculate overall confidence
        confidence = min(sum(scores) / len(scores), 1.0)
        reason = "; ".join(reasons)

        return True, confidence, reason

    def is_blocked(self, response: Response) -> tuple[bool, str]:
        """
        Check if response indicates WAF/security block.

        Args:
            response: Response to check

        Returns:
            Tuple of (is_blocked, indicator)
        """
        text = response.text.lower()

        # Status code indicators
        if response.status_code in [403, 406, 429, 503]:
            return True, f"status_code:{response.status_code}"

        # Pattern matching
        for pattern in self._compiled_patterns.get("blocked", []):
            match = pattern.search(text)
            if match:
                return True, f"pattern:{match.group()}"

        return False, ""

    def get_baseline_summary(self) -> dict:
        """Get summary of learned baseline."""
        if not self.baseline:
            return {"status": "no_baseline"}

        return {
            "sample_count": self.baseline.sample_count,
            "length_mean": round(self.baseline.length_mean, 2),
            "length_std": round(self.baseline.length_std, 2),
            "time_mean": round(self.baseline.time_mean, 4),
            "time_std": round(self.baseline.time_std, 4),
            "common_status": self.baseline.common_status,
            "structure_variations": len(self.baseline.structure_hashes),
            "known_errors": list(self.baseline.error_frequency.keys()),
        }

    def compare_responses(
        self,
        resp1: Response,
        resp2: Response
    ) -> dict:
        """
        Compare two responses and return detailed differences.

        Useful for boolean-based blind injection detection.

        Args:
            resp1: First response
            resp2: Second response

        Returns:
            Dictionary with comparison results
        """
        f1 = self.extract_features(resp1)
        f2 = self.extract_features(resp2)

        return {
            "length_diff": abs(f1.content_length - f2.content_length),
            "time_diff": abs(f1.response_time - f2.response_time),
            "status_same": f1.status_code == f2.status_code,
            "structure_same": f1.structure_hash == f2.structure_hash,
            "content_same": f1.content_hash == f2.content_hash,
            "resp1": {
                "length": f1.content_length,
                "time": f1.response_time,
                "status": f1.status_code,
                "errors": f1.error_keywords,
            },
            "resp2": {
                "length": f2.content_length,
                "time": f2.response_time,
                "status": f2.status_code,
                "errors": f2.error_keywords,
            },
        }

    def detect_boolean_difference(
        self,
        true_resp: Response,
        false_resp: Response,
        min_length_diff: int = 50
    ) -> bool:
        """
        Detect if there's a usable difference for boolean-based injection.

        Args:
            true_resp: Response for TRUE condition
            false_resp: Response for FALSE condition
            min_length_diff: Minimum length difference to be usable

        Returns:
            True if responses are distinguishable
        """
        comparison = self.compare_responses(true_resp, false_resp)

        # Clear content difference
        if comparison["length_diff"] > min_length_diff:
            return True

        # Different status codes
        if not comparison["status_same"]:
            return True

        # Different page structure
        if not comparison["structure_same"]:
            return True

        return False
