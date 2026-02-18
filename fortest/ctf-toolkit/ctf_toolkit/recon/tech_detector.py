"""Technology stack detection for target fingerprinting."""

import re
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class TechFingerprint:
    """Detected technology fingerprint."""
    web_server: Optional[str] = None
    web_server_version: Optional[str] = None
    os: Optional[str] = None
    language: Optional[str] = None
    framework: Optional[str] = None
    database: Optional[str] = None
    cms: Optional[str] = None
    cdn: Optional[str] = None
    waf: Optional[str] = None
    other: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "web_server": self.web_server,
            "web_server_version": self.web_server_version,
            "os": self.os,
            "language": self.language,
            "framework": self.framework,
            "database": self.database,
            "cms": self.cms,
            "cdn": self.cdn,
            "waf": self.waf,
            "other": self.other,
        }


class TechDetector:
    """Detect technology stack from HTTP responses."""

    # Web Server signatures
    WEB_SERVERS = {
        "nginx": [r"nginx/?(\d+\.[\d\.]+)?", r"nginx"],
        "apache": [r"Apache/?(\d+\.[\d\.]+)?", r"Apache"],
        "iis": [r"Microsoft-IIS/?(\d+\.[\d\.]+)?", r"IIS"],
        "tomcat": [r"Apache-Coyote/?(\d+\.[\d\.]+)?", r"Tomcat"],
        "lighttpd": [r"lighttpd/?(\d+\.[\d\.]+)?"],
        "cloudflare": [r"cloudflare"],
        "gunicorn": [r"gunicorn/?(\d+\.[\d\.]+)?"],
        "uvicorn": [r"uvicorn"],
        "werkzeug": [r"Werkzeug/?(\d+\.[\d\.]+)?"],
    }

    # OS detection patterns
    OS_PATTERNS = {
        "windows": [
            r"Win64",
            r"Windows",
            r"Microsoft-IIS",
            r"ASP\.NET",
            r"win32",
        ],
        "linux": [
            r"Ubuntu",
            r"Debian",
            r"CentOS",
            r"Red Hat",
            r"Fedora",
            r"Linux",
        ],
        "unix": [
            r"Unix",
            r"FreeBSD",
            r"OpenBSD",
        ],
    }

    # Programming language/framework patterns
    LANGUAGE_PATTERNS = {
        "php": [
            r"X-Powered-By:\s*PHP/?(\d+\.[\d\.]+)?",
            r"\.php",
            r"PHPSESSID",
        ],
        "asp.net": [
            r"X-Powered-By:\s*ASP\.NET",
            r"X-AspNet-Version",
            r"\.aspx?",
            r"ASP\.NET_SessionId",
        ],
        "java": [
            r"JSESSIONID",
            r"X-Powered-By:\s*Servlet",
            r"\.jsp",
            r"\.do",
        ],
        "python": [
            r"X-Powered-By:\s*Python",
            r"Werkzeug",
            r"gunicorn",
            r"uvicorn",
        ],
        "ruby": [
            r"X-Powered-By:\s*Phusion Passenger",
            r"X-Runtime",
            r"_rails_session",
        ],
        "node.js": [
            r"X-Powered-By:\s*Express",
            r"connect\.sid",
        ],
    }

    # Framework patterns
    FRAMEWORK_PATTERNS = {
        "django": [r"csrftoken", r"django"],
        "flask": [r"Werkzeug", r"session="],
        "rails": [r"_rails_session", r"X-Runtime"],
        "express": [r"X-Powered-By:\s*Express"],
        "spring": [r"JSESSIONID", r"org\.springframework"],
        "laravel": [r"laravel_session", r"XSRF-TOKEN"],
        "wordpress": [r"wp-content", r"wp-includes", r"WordPress"],
        "drupal": [r"Drupal", r"sites/default/files"],
        "joomla": [r"Joomla", r"/administrator/"],
    }

    # Database error patterns
    DATABASE_PATTERNS = {
        "mysql": [
            r"mysql",
            r"MySQL",
            r"mysqli",
            r"SQLSTATE\[HY000\]",
            r"mysql_",
        ],
        "postgresql": [
            r"PostgreSQL",
            r"pg_",
            r"Npgsql",
            r"PG::",
        ],
        "mssql": [
            r"Microsoft SQL Server",
            r"ODBC SQL Server Driver",
            r"SqlClient",
            r"\[SQL Server\]",
        ],
        "oracle": [
            r"ORA-\d{5}",
            r"Oracle",
            r"oci_",
        ],
        "sqlite": [
            r"SQLite",
            r"sqlite3",
        ],
        "mongodb": [
            r"MongoDB",
            r"MongoError",
        ],
    }

    # WAF detection patterns
    WAF_PATTERNS = {
        "cloudflare": [r"cloudflare", r"cf-ray", r"__cfduid"],
        "akamai": [r"akamai", r"AkamaiGHost"],
        "incapsula": [r"incap_ses", r"visid_incap"],
        "sucuri": [r"sucuri", r"x-sucuri"],
        "modsecurity": [r"mod_security", r"NOYB"],
        "aws_waf": [r"awswaf", r"x-amzn-waf"],
        "f5_big_ip": [r"BigIP", r"F5"],
    }

    # CDN patterns
    CDN_PATTERNS = {
        "cloudflare": [r"cloudflare", r"cf-ray"],
        "akamai": [r"akamai", r"x-akamai"],
        "fastly": [r"fastly", r"x-served-by.*cache"],
        "cloudfront": [r"cloudfront", r"x-amz-cf"],
        "maxcdn": [r"maxcdn", r"netdna"],
    }

    def __init__(self):
        self.fingerprint = TechFingerprint()

    def detect_from_headers(self, headers: dict[str, str]) -> TechFingerprint:
        """
        Detect technologies from HTTP headers.

        Args:
            headers: HTTP response headers

        Returns:
            TechFingerprint with detected technologies
        """
        headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())
        headers_lower = {k.lower(): v for k, v in headers.items()}

        # Detect web server
        server = headers_lower.get("server", "")
        self._detect_web_server(server)

        # Detect from X-Powered-By
        powered_by = headers_lower.get("x-powered-by", "")
        self._detect_language(powered_by)

        # Detect WAF
        self._detect_waf(headers_str)

        # Detect CDN
        self._detect_cdn(headers_str)

        # OS hints from headers
        self._detect_os(headers_str)

        return self.fingerprint

    def detect_from_body(self, body: str) -> TechFingerprint:
        """
        Detect technologies from response body.

        Args:
            body: HTTP response body

        Returns:
            TechFingerprint with detected technologies
        """
        # Detect CMS
        self._detect_cms(body)

        # Detect framework hints
        self._detect_framework(body)

        # Detect database from errors
        self._detect_database(body)

        return self.fingerprint

    def detect_from_cookies(self, cookies: dict[str, str]) -> TechFingerprint:
        """
        Detect technologies from cookies.

        Args:
            cookies: Cookie dictionary

        Returns:
            TechFingerprint with detected technologies
        """
        cookies_str = " ".join(cookies.keys())

        # Check for session cookie patterns
        if "PHPSESSID" in cookies:
            self.fingerprint.language = "php"
        elif "JSESSIONID" in cookies:
            self.fingerprint.language = "java"
        elif "ASP.NET_SessionId" in cookies:
            self.fingerprint.language = "asp.net"
        elif "connect.sid" in cookies:
            self.fingerprint.language = "node.js"
        elif "_rails_session" in cookies:
            self.fingerprint.framework = "rails"
            self.fingerprint.language = "ruby"
        elif "laravel_session" in cookies:
            self.fingerprint.framework = "laravel"
            self.fingerprint.language = "php"
        elif "csrftoken" in cookies:
            self.fingerprint.framework = "django"
            self.fingerprint.language = "python"

        return self.fingerprint

    def _detect_web_server(self, server_header: str) -> None:
        """Detect web server from Server header."""
        server_lower = server_header.lower()

        for server_name, patterns in self.WEB_SERVERS.items():
            for pattern in patterns:
                match = re.search(pattern, server_header, re.IGNORECASE)
                if match:
                    self.fingerprint.web_server = server_name
                    if match.groups():
                        self.fingerprint.web_server_version = match.group(1)
                    return

    def _detect_os(self, text: str) -> None:
        """Detect OS from text."""
        for os_name, patterns in self.OS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    self.fingerprint.os = os_name
                    return

    def _detect_language(self, text: str) -> None:
        """Detect programming language."""
        for lang, patterns in self.LANGUAGE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    self.fingerprint.language = lang
                    return

    def _detect_framework(self, text: str) -> None:
        """Detect framework from text."""
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    self.fingerprint.framework = framework
                    return

    def _detect_database(self, text: str) -> None:
        """Detect database from error messages."""
        for db, patterns in self.DATABASE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    self.fingerprint.database = db
                    return

    def _detect_cms(self, text: str) -> None:
        """Detect CMS from response body."""
        cms_patterns = {
            "wordpress": [r"wp-content", r"wp-includes", r"/wp-json/"],
            "drupal": [r'Drupal\.settings', r"sites/default/files"],
            "joomla": [r"/media/jui/", r"/administrator/"],
            "magento": [r"Mage\.Cookies", r"/skin/frontend/"],
            "shopify": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        }

        for cms, patterns in cms_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    self.fingerprint.cms = cms
                    return

    def _detect_waf(self, text: str) -> None:
        """Detect WAF from headers."""
        for waf, patterns in self.WAF_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    self.fingerprint.waf = waf
                    return

    def _detect_cdn(self, text: str) -> None:
        """Detect CDN from headers."""
        for cdn, patterns in self.CDN_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    self.fingerprint.cdn = cdn
                    return
