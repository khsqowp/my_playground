"""Flag extraction utilities for CTF challenges."""

import re
from typing import Optional


class FlagExtractor:
    """Extract CTF flags from text using regex patterns."""

    # Common CTF flag formats
    DEFAULT_PATTERNS = [
        r"CTF\{[^}]+\}",
        r"FLAG\{[^}]+\}",
        r"flag\{[^}]+\}",
        r"ctf\{[^}]+\}",
        r"HTB\{[^}]+\}",          # HackTheBox
        r"THM\{[^}]+\}",          # TryHackMe
        r"picoCTF\{[^}]+\}",      # picoCTF
        r"PCTF\{[^}]+\}",
        r"DUCTF\{[^}]+\}",        # DownUnderCTF
        r"bcactf\{[^}]+\}",
        r"uiuctf\{[^}]+\}",
        r"lactf\{[^}]+\}",
        r"justctf\{[^}]+\}",
        r"corctf\{[^}]+\}",
        r"dicectf\{[^}]+\}",
        r"googlectf\{[^}]+\}",
        r"hkcert\d*\{[^}]+\}",
        r"[A-Za-z0-9_]+\{[A-Za-z0-9_!@#$%^&*()-+=]+\}",  # Generic format
    ]

    def __init__(self, custom_patterns: Optional[list[str]] = None):
        """
        Initialize flag extractor.

        Args:
            custom_patterns: Additional regex patterns to use
        """
        self.patterns = self.DEFAULT_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

    def extract(self, text: str) -> list[str]:
        """
        Extract all flags from text.

        Args:
            text: Text to search for flags

        Returns:
            List of found flags
        """
        flags = []
        for pattern in self.patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            flags.extend(matches)

        # Remove duplicates while preserving order
        seen = set()
        unique_flags = []
        for flag in flags:
            if flag not in seen:
                seen.add(flag)
                unique_flags.append(flag)

        return unique_flags

    def extract_with_context(self, text: str, context_chars: int = 50) -> list[dict]:
        """
        Extract flags with surrounding context.

        Args:
            text: Text to search
            context_chars: Number of characters to include before/after

        Returns:
            List of dicts with flag and context
        """
        results = []
        for pattern in self.patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                start = max(0, match.start() - context_chars)
                end = min(len(text), match.end() + context_chars)
                results.append({
                    "flag": match.group(),
                    "context": text[start:end],
                    "start": match.start(),
                    "end": match.end(),
                })

        return results

    def highlight_flags(self, text: str, highlight_start: str = "\033[92m", highlight_end: str = "\033[0m") -> str:
        """
        Return text with flags highlighted.

        Args:
            text: Text to process
            highlight_start: ANSI code or string to start highlight
            highlight_end: ANSI code or string to end highlight

        Returns:
            Text with flags highlighted
        """
        result = text
        for pattern in self.patterns:
            result = re.sub(
                pattern,
                lambda m: f"{highlight_start}{m.group()}{highlight_end}",
                result,
                flags=re.IGNORECASE
            )
        return result

    def add_pattern(self, pattern: str) -> None:
        """Add a custom pattern."""
        self.patterns.append(pattern)

    def set_ctf_format(self, prefix: str) -> None:
        """
        Set pattern for specific CTF format.

        Args:
            prefix: CTF prefix (e.g., "DEFCON", "SECCON")
        """
        pattern = f"{prefix}\\{{[^}}]+\\}}"
        if pattern not in self.patterns:
            self.patterns.insert(0, pattern)

    @staticmethod
    def is_likely_flag(text: str) -> bool:
        """
        Check if text looks like a flag.

        Args:
            text: Text to check

        Returns:
            True if text matches flag format
        """
        # Basic heuristics for flag detection
        if not text:
            return False

        # Check for common flag structure
        if re.match(r"^[A-Za-z0-9_]+\{.+\}$", text):
            return True

        # Check for hex-like content that might be encoded flag
        if re.match(r"^[A-Fa-f0-9]{32,}$", text):
            return True

        # Check for base64-like content
        if re.match(r"^[A-Za-z0-9+/]+=*$", text) and len(text) > 20:
            return True

        return False


def extract_flags(text: str, pattern: Optional[str] = None) -> list[str]:
    """
    Convenience function to extract flags.

    Args:
        text: Text to search
        pattern: Optional custom pattern

    Returns:
        List of found flags
    """
    extractor = FlagExtractor()
    if pattern:
        extractor.add_pattern(pattern)
    return extractor.extract(text)
