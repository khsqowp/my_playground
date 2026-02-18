"""Attack context for maintaining session state."""

from dataclasses import dataclass, field
from typing import Optional, Any
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


@dataclass
class AttackContext:
    """
    Stores session state and configuration for attacks.
    """
    # Target configuration
    target_url: str
    method: str = "GET"
    inject_param: Optional[str] = None

    # Request configuration
    params: dict[str, str] = field(default_factory=dict)
    data: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    # Connection configuration
    proxy: Optional[str] = None
    timeout: int = 10
    verify_ssl: bool = False

    # Rate limiting
    rate_limit: float = 10.0  # requests per second
    threads: int = 5

    # Detection configuration
    success_pattern: Optional[str] = None
    failure_pattern: Optional[str] = None
    error_patterns: list[str] = field(default_factory=list)
    time_threshold: float = 3.0  # seconds for time-based detection
    length_threshold: int = 100  # bytes for content-length diff

    # Detected information
    server_type: Optional[str] = None
    db_type: Optional[str] = None
    os_type: Optional[str] = None

    # Results storage
    vulnerabilities: list[dict] = field(default_factory=list)
    extracted_data: list[str] = field(default_factory=list)
    flags_found: list[str] = field(default_factory=list)

    # Verbose mode
    verbose: bool = False

    def __post_init__(self):
        """Initialize default error patterns if not provided."""
        if not self.error_patterns:
            self.error_patterns = [
                # MySQL
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_",
                r"MySQLSyntaxErrorException",
                r"valid MySQL result",
                r"check the manual that corresponds to your MySQL server version",
                # PostgreSQL
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"PG::SyntaxError",
                # MSSQL
                r"Driver.* SQL[\-\_\ ]*Server",
                r"OLE DB.* SQL Server",
                r"SQLServer JDBC Driver",
                r"SqlException",
                r"Unclosed quotation mark",
                # Oracle
                r"ORA-[0-9]{5}",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*oci_",
                # SQLite
                r"SQLite/JDBCDriver",
                r"SQLite\.Exception",
                r"System\.Data\.SQLite\.SQLiteException",
                r"sqlite3\.OperationalError",
                # Generic
                r"syntax error",
                r"SQL error",
                r"unterminated string",
            ]

    def get_proxy_dict(self) -> Optional[dict[str, str]]:
        """Get proxy configuration as dict for requests library."""
        if self.proxy:
            return {
                "http": self.proxy,
                "https": self.proxy,
            }
        return None

    def get_headers(self) -> dict[str, str]:
        """Get headers including User-Agent if not set."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        headers.update(self.headers)
        return headers

    def parse_cookies_string(self, cookie_string: str) -> None:
        """Parse cookie string and add to cookies dict."""
        for item in cookie_string.split(";"):
            if "=" in item:
                key, value = item.split("=", 1)
                self.cookies[key.strip()] = value.strip()

    def parse_data_string(self, data_string: str) -> None:
        """Parse POST data string and add to data dict."""
        for item in data_string.split("&"):
            if "=" in item:
                key, value = item.split("=", 1)
                self.data[key.strip()] = value.strip()

    def build_url_with_payload(self, payload: str) -> str:
        """Build URL with payload injected into the target parameter."""
        if not self.inject_param:
            return self.target_url

        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        # Inject payload into target parameter
        if self.inject_param in params:
            params[self.inject_param] = [payload]
        else:
            params[self.inject_param] = [payload]

        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        return new_url

    def build_data_with_payload(self, payload: str) -> dict[str, str]:
        """Build POST data with payload injected into the target parameter."""
        data = self.data.copy()
        if self.inject_param and self.inject_param in data:
            data[self.inject_param] = payload
        return data

    def add_vulnerability(
        self,
        vuln_type: str,
        payload: str,
        evidence: str,
        confidence: str = "high"
    ) -> None:
        """Record a found vulnerability."""
        self.vulnerabilities.append({
            "type": vuln_type,
            "url": self.target_url,
            "parameter": self.inject_param,
            "payload": payload,
            "evidence": evidence,
            "confidence": confidence,
        })

    def add_flag(self, flag: str) -> None:
        """Record a found flag."""
        if flag not in self.flags_found:
            self.flags_found.append(flag)

    def to_dict(self) -> dict[str, Any]:
        """Convert context to dictionary for serialization."""
        return {
            "target_url": self.target_url,
            "method": self.method,
            "inject_param": self.inject_param,
            "server_type": self.server_type,
            "db_type": self.db_type,
            "os_type": self.os_type,
            "vulnerabilities": self.vulnerabilities,
            "extracted_data": self.extracted_data,
            "flags_found": self.flags_found,
        }
