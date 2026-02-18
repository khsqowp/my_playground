"""Brute Force scanner module for CTF challenges.

This module provides directory enumeration, login brute forcing, and parameter fuzzing
capabilities for authorized security testing and CTF competitions.
"""

import asyncio
import re
from typing import Optional, Callable
from urllib.parse import urljoin, urlparse

from ..base import AttackModule
from ...core.context import AttackContext
from ...core.http_client import Response
from ...utils.logger import log_info, log_warning, log_vulnerable, create_progress
from ...utils.flag_extractor import FlagExtractor


# Common directories for enumeration
COMMON_DIRECTORIES = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "dashboard", "panel", "console", "manager", "phpmyadmin",
    "backup", "backups", "bak", "old", "temp", "tmp",
    "api", "api/v1", "api/v2", "rest", "graphql",
    "upload", "uploads", "files", "images", "static", "assets",
    "include", "includes", "inc", "lib", "libs",
    "config", "conf", "cfg", "settings",
    "test", "testing", "dev", "development", "staging",
    "private", "secret", "hidden", ".hidden",
    "flag", "flag.txt", "flag.php", "flags",
    "robots.txt", "sitemap.xml", ".htaccess", ".git", ".svn",
    ".env", ".env.bak", ".env.local", ".env.production",
    "web.config", "config.php", "config.inc.php", "wp-config.php",
    "debug", "debug.log", "error.log", "access.log",
    "shell", "cmd", "command", "exec",
    "user", "users", "member", "members", "account", "accounts",
    "cgi-bin", "scripts", "bin",
    "db", "database", "sql", "mysql", "data",
    "readme", "README", "README.md", "readme.txt",
    "changelog", "CHANGELOG", "version", "VERSION",
    "install", "setup", "init",
    "server-status", "server-info", "status", "info", "phpinfo.php",
]

# Common file extensions
COMMON_EXTENSIONS = [
    "", ".php", ".html", ".htm", ".txt", ".bak", ".old",
    ".asp", ".aspx", ".jsp", ".json", ".xml", ".yml", ".yaml",
    ".log", ".sql", ".db", ".sqlite", ".zip", ".tar.gz",
    ".inc", ".conf", ".config", ".ini",
]

# Common backup file patterns
BACKUP_PATTERNS = [
    "{name}.bak", "{name}.old", "{name}.backup", "{name}~",
    "{name}.save", "{name}.orig", "{name}.copy",
    "{name}.1", "{name}.2",
    "backup_{name}", "old_{name}", "copy_{name}",
    "{name}_backup", "{name}_old", "{name}_copy",
]

# Common usernames for login brute force
COMMON_USERNAMES = [
    "admin", "administrator", "root", "user", "test",
    "guest", "demo", "manager", "webmaster", "support",
    "info", "contact", "sales", "admin1", "user1",
]

# Common weak passwords (top 100)
COMMON_PASSWORDS = [
    "admin", "password", "123456", "12345678", "password1",
    "admin123", "root", "toor", "test", "guest",
    "letmein", "welcome", "monkey", "dragon", "master",
    "qwerty", "login", "passwd", "abc123", "111111",
    "123123", "admin@123", "admin1234", "password123", "p@ssw0rd",
    "passw0rd", "1234567890", "0987654321", "qwerty123", "1q2w3e4r",
    "superman", "iloveyou", "trustno1", "sunshine", "princess",
    "football", "baseball", "soccer", "hockey", "batman",
    "cheese", "pepper", "secret", "access", "shadow",
    "123456789", "654321", "7777777", "1234567", "123321",
    "666666", "121212", "000000", "696969", "112233",
    "default", "changeme", "server", "database", "mysql",
    "oracle", "postgres", "ftp", "ssh", "web",
    "cisco", "juniper", "router", "switch", "firewall",
]

# Hidden parameter names
COMMON_PARAMETERS = [
    "debug", "test", "admin", "id", "user", "username",
    "pass", "password", "passwd", "pwd", "token", "key",
    "api_key", "apikey", "api-key", "secret", "auth",
    "callback", "redirect", "url", "next", "return", "goto",
    "page", "file", "path", "dir", "folder", "include",
    "template", "view", "action", "cmd", "command", "exec",
    "q", "query", "search", "s", "keyword", "filter",
    "sort", "order", "limit", "offset", "count",
    "format", "type", "mode", "method", "func", "function",
    "role", "access", "level", "permission", "grant",
    "email", "mail", "phone", "name", "first", "last",
    "lang", "language", "locale", "country", "region",
    "v", "version", "ver", "rev", "revision",
    "flag", "hidden", "internal", "private", "system",
]


class BruteforceScanner(AttackModule):
    """Brute force vulnerability scanner for CTF challenges."""

    @property
    def name(self) -> str:
        return "Brute Force Scanner"

    @property
    def description(self) -> str:
        return "Directory enumeration, login brute force, and parameter fuzzing"

    def __init__(self, ctx: AttackContext):
        """
        Initialize brute force scanner.

        Args:
            ctx: Attack context
        """
        super().__init__(ctx)
        self.flag_extractor = FlagExtractor()
        self.found_paths: list[dict] = []
        self.found_credentials: list[dict] = []
        self.found_parameters: list[dict] = []
        self.baseline_length: int = 0
        self.baseline_status: int = 0

    async def scan(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
    ) -> list[dict]:
        """
        Generic scan method - uses directory enumeration by default.

        Args:
            payloads: Custom wordlist (if None, uses built-in)
            on_finding: Callback function when finding discovered

        Returns:
            List of findings
        """
        return await self.enumerate_directories(
            wordlist=payloads,
            on_finding=on_finding,
        )

    def scan_sync(
        self,
        payloads: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
    ) -> list[dict]:
        """Synchronous scan."""
        return self.enumerate_directories_sync(
            wordlist=payloads,
            on_finding=on_finding,
        )

    # ==================== Directory Enumeration ====================

    async def enumerate_directories(
        self,
        wordlist: Optional[list[str]] = None,
        extensions: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        filter_status: Optional[list[int]] = None,
        filter_length: Optional[int] = None,
    ) -> list[dict]:
        """
        Enumerate directories and files.

        Args:
            wordlist: Custom wordlist (if None, uses COMMON_DIRECTORIES)
            extensions: File extensions to try (if None, uses COMMON_EXTENSIONS)
            on_finding: Callback when path found
            filter_status: Status codes to filter out (e.g., [404])
            filter_length: Response length to filter out (for custom 404)

        Returns:
            List of found paths
        """
        if wordlist is None:
            wordlist = COMMON_DIRECTORIES
        if extensions is None:
            extensions = [""]  # No extension by default for speed
        if filter_status is None:
            filter_status = [404]

        # Generate all paths to test
        paths = self._generate_paths(wordlist, extensions)

        if self.ctx.verbose:
            log_info(f"Testing {len(paths)} paths against {self.ctx.target_url}")

        # Get baseline 404 response
        await self._get_baseline()

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Enumerating directories...", total=len(paths))

            semaphore = asyncio.Semaphore(self.ctx.threads)

            async def test_with_semaphore(path: str):
                async with semaphore:
                    return await self._test_path(path, filter_status, filter_length)

            tasks = [test_with_semaphore(p) for p in paths]

            for coro in asyncio.as_completed(tasks):
                result = await coro
                progress.update(task, advance=1)

                if result:
                    findings.append(result)
                    self.found_paths.append(result)
                    if on_finding:
                        on_finding(result)

                    if self.ctx.verbose:
                        log_vulnerable(
                            result["url"],
                            "directory",
                            f"[{result['status']}] {result['path']}"
                        )

        await self.cleanup()
        self.results.extend(findings)
        return findings

    def enumerate_directories_sync(
        self,
        wordlist: Optional[list[str]] = None,
        extensions: Optional[list[str]] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
        filter_status: Optional[list[int]] = None,
        filter_length: Optional[int] = None,
    ) -> list[dict]:
        """Synchronous directory enumeration."""
        if wordlist is None:
            wordlist = COMMON_DIRECTORIES
        if extensions is None:
            extensions = [""]
        if filter_status is None:
            filter_status = [404]

        paths = self._generate_paths(wordlist, extensions)

        if self.ctx.verbose:
            log_info(f"Testing {len(paths)} paths")

        self._get_baseline_sync()
        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Enumerating directories...", total=len(paths))

            for path in paths:
                result = self._test_path_sync(path, filter_status, filter_length)
                progress.update(task, advance=1)

                if result:
                    findings.append(result)
                    self.found_paths.append(result)
                    if on_finding:
                        on_finding(result)

        self.cleanup_sync()
        self.results.extend(findings)
        return findings

    async def _get_baseline(self) -> None:
        """Get baseline 404 response for comparison."""
        try:
            # Request non-existent path
            test_url = urljoin(self.ctx.target_url, "/ctf_toolkit_nonexistent_path_12345")
            response = await self.client.request(url=test_url)
            self.baseline_length = response.content_length
            self.baseline_status = response.status_code
        except Exception:
            self.baseline_length = 0
            self.baseline_status = 404

    def _get_baseline_sync(self) -> None:
        """Synchronous baseline check."""
        try:
            test_url = urljoin(self.ctx.target_url, "/ctf_toolkit_nonexistent_path_12345")
            response = self.client.request_sync(url=test_url)
            self.baseline_length = response.content_length
            self.baseline_status = response.status_code
        except Exception:
            self.baseline_length = 0
            self.baseline_status = 404

    async def _test_path(
        self,
        path: str,
        filter_status: list[int],
        filter_length: Optional[int],
    ) -> Optional[dict]:
        """Test a single path asynchronously."""
        try:
            url = urljoin(self.ctx.target_url, path)
            response = await self.client.request(url=url)

            # Filter by status code
            if response.status_code in filter_status:
                return None

            # Filter by length (custom 404 detection)
            if filter_length and response.content_length == filter_length:
                return None

            # Filter if same as baseline
            if (response.status_code == self.baseline_status and
                abs(response.content_length - self.baseline_length) < 50):
                return None

            # Check for flags
            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            return {
                "type": "directory_found",
                "url": url,
                "path": path,
                "status": response.status_code,
                "length": response.content_length,
                "flags_found": flags,
                "content_type": response.headers.get("content-type", ""),
            }

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing path {path}: {e}")
            return None

    def _test_path_sync(
        self,
        path: str,
        filter_status: list[int],
        filter_length: Optional[int],
    ) -> Optional[dict]:
        """Synchronous path test."""
        try:
            url = urljoin(self.ctx.target_url, path)
            response = self.client.request_sync(url=url)

            if response.status_code in filter_status:
                return None

            if filter_length and response.content_length == filter_length:
                return None

            if (response.status_code == self.baseline_status and
                abs(response.content_length - self.baseline_length) < 50):
                return None

            flags = self.flag_extractor.extract(response.text)
            for flag in flags:
                self.ctx.add_flag(flag)

            return {
                "type": "directory_found",
                "url": url,
                "path": path,
                "status": response.status_code,
                "length": response.content_length,
                "flags_found": flags,
                "content_type": response.headers.get("content-type", ""),
            }

        except Exception:
            return None

    def _generate_paths(
        self, wordlist: list[str], extensions: list[str]
    ) -> list[str]:
        """Generate paths with extensions."""
        paths = []
        for word in wordlist:
            for ext in extensions:
                if ext and not word.endswith(ext):
                    paths.append(word + ext)
                elif not ext:
                    paths.append(word)
        return list(set(paths))

    # ==================== Login Brute Force ====================

    async def bruteforce_login(
        self,
        usernames: Optional[list[str]] = None,
        passwords: Optional[list[str]] = None,
        username_field: str = "username",
        password_field: str = "password",
        success_indicator: Optional[str] = None,
        failure_indicator: Optional[str] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
    ) -> list[dict]:
        """
        Brute force login form.

        Args:
            usernames: List of usernames to try
            passwords: List of passwords to try
            username_field: Form field name for username
            password_field: Form field name for password
            success_indicator: String that appears on successful login
            failure_indicator: String that appears on failed login
            on_finding: Callback when credentials found

        Returns:
            List of valid credentials
        """
        if usernames is None:
            usernames = COMMON_USERNAMES
        if passwords is None:
            passwords = COMMON_PASSWORDS

        total = len(usernames) * len(passwords)

        if self.ctx.verbose:
            log_info(f"Testing {len(usernames)} usernames x {len(passwords)} passwords = {total} combinations")

        # Get baseline failed login response
        baseline_response = await self._get_login_baseline(
            username_field, password_field
        )

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Brute forcing login...", total=total)

            semaphore = asyncio.Semaphore(self.ctx.threads)

            async def test_with_semaphore(user: str, passwd: str):
                async with semaphore:
                    return await self._test_credentials(
                        user, passwd,
                        username_field, password_field,
                        baseline_response,
                        success_indicator, failure_indicator
                    )

            tasks = []
            for user in usernames:
                for passwd in passwords:
                    tasks.append(test_with_semaphore(user, passwd))

            for coro in asyncio.as_completed(tasks):
                result = await coro
                progress.update(task, advance=1)

                if result:
                    findings.append(result)
                    self.found_credentials.append(result)
                    if on_finding:
                        on_finding(result)

                    if self.ctx.verbose:
                        log_vulnerable(
                            self.ctx.target_url,
                            "login",
                            f"{result['username']}:{result['password']}"
                        )

        await self.cleanup()
        self.results.extend(findings)
        return findings

    def bruteforce_login_sync(
        self,
        usernames: Optional[list[str]] = None,
        passwords: Optional[list[str]] = None,
        username_field: str = "username",
        password_field: str = "password",
        success_indicator: Optional[str] = None,
        failure_indicator: Optional[str] = None,
        on_finding: Optional[Callable[[dict], None]] = None,
    ) -> list[dict]:
        """Synchronous login brute force."""
        if usernames is None:
            usernames = COMMON_USERNAMES
        if passwords is None:
            passwords = COMMON_PASSWORDS

        total = len(usernames) * len(passwords)

        if self.ctx.verbose:
            log_info(f"Testing {total} credential combinations")

        baseline_response = self._get_login_baseline_sync(
            username_field, password_field
        )

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Brute forcing login...", total=total)

            for user in usernames:
                for passwd in passwords:
                    result = self._test_credentials_sync(
                        user, passwd,
                        username_field, password_field,
                        baseline_response,
                        success_indicator, failure_indicator
                    )
                    progress.update(task, advance=1)

                    if result:
                        findings.append(result)
                        self.found_credentials.append(result)
                        if on_finding:
                            on_finding(result)

        self.cleanup_sync()
        self.results.extend(findings)
        return findings

    async def _get_login_baseline(
        self, username_field: str, password_field: str
    ) -> Response:
        """Get baseline failed login response."""
        data = {
            username_field: "ctf_invalid_user_12345",
            password_field: "ctf_invalid_pass_12345",
        }
        return await self.client.request(method="POST", data=data)

    def _get_login_baseline_sync(
        self, username_field: str, password_field: str
    ) -> Response:
        """Synchronous baseline."""
        data = {
            username_field: "ctf_invalid_user_12345",
            password_field: "ctf_invalid_pass_12345",
        }
        return self.client.request_sync(method="POST", data=data)

    async def _test_credentials(
        self,
        username: str,
        password: str,
        username_field: str,
        password_field: str,
        baseline: Response,
        success_indicator: Optional[str],
        failure_indicator: Optional[str],
    ) -> Optional[dict]:
        """Test a single credential pair."""
        try:
            data = {
                username_field: username,
                password_field: password,
            }
            response = await self.client.request(method="POST", data=data)

            is_success = self._check_login_success(
                response, baseline, success_indicator, failure_indicator
            )

            if is_success:
                # Check for flags in response
                flags = self.flag_extractor.extract(response.text)
                for flag in flags:
                    self.ctx.add_flag(flag)

                return {
                    "type": "credentials_found",
                    "url": self.ctx.target_url,
                    "username": username,
                    "password": password,
                    "status": response.status_code,
                    "length": response.content_length,
                    "flags_found": flags,
                }

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing {username}:{password}: {e}")

        return None

    def _test_credentials_sync(
        self,
        username: str,
        password: str,
        username_field: str,
        password_field: str,
        baseline: Response,
        success_indicator: Optional[str],
        failure_indicator: Optional[str],
    ) -> Optional[dict]:
        """Synchronous credential test."""
        try:
            data = {
                username_field: username,
                password_field: password,
            }
            response = self.client.request_sync(method="POST", data=data)

            is_success = self._check_login_success(
                response, baseline, success_indicator, failure_indicator
            )

            if is_success:
                flags = self.flag_extractor.extract(response.text)
                for flag in flags:
                    self.ctx.add_flag(flag)

                return {
                    "type": "credentials_found",
                    "url": self.ctx.target_url,
                    "username": username,
                    "password": password,
                    "status": response.status_code,
                    "length": response.content_length,
                    "flags_found": flags,
                }

        except Exception:
            pass

        return None

    def _check_login_success(
        self,
        response: Response,
        baseline: Response,
        success_indicator: Optional[str],
        failure_indicator: Optional[str],
    ) -> bool:
        """Check if login was successful."""
        # Check custom indicators first
        if success_indicator and success_indicator in response.text:
            return True

        if failure_indicator and failure_indicator in response.text:
            return False

        # Check for redirect (common success pattern)
        if response.status_code in [301, 302, 303, 307, 308]:
            location = response.headers.get("location", "")
            # Avoid redirect to login page
            if "login" not in location.lower() and "error" not in location.lower():
                return True

        # Check for Set-Cookie (session creation)
        if "set-cookie" in response.headers:
            cookie = response.headers.get("set-cookie", "").lower()
            if "session" in cookie or "token" in cookie or "auth" in cookie:
                # Compare with baseline
                if "set-cookie" not in baseline.headers:
                    return True

        # Check for significant length difference
        if abs(response.content_length - baseline.content_length) > 200:
            # Longer response might indicate dashboard/welcome page
            if response.content_length > baseline.content_length:
                return True

        # Check for common success/failure patterns
        success_patterns = [
            r'welcome', r'dashboard', r'logout', r'my account',
            r'logged in', r'success', r'hello,?\s+\w+',
        ]
        failure_patterns = [
            r'invalid', r'incorrect', r'wrong', r'failed',
            r'error', r'denied', r'try again',
        ]

        text_lower = response.text.lower()

        for pattern in failure_patterns:
            if re.search(pattern, text_lower):
                return False

        for pattern in success_patterns:
            if re.search(pattern, text_lower):
                return True

        return False

    # ==================== Parameter Fuzzing ====================

    async def fuzz_parameters(
        self,
        parameters: Optional[list[str]] = None,
        test_value: str = "ctf_test_value",
        on_finding: Optional[Callable[[dict], None]] = None,
    ) -> list[dict]:
        """
        Fuzz for hidden GET parameters.

        Args:
            parameters: List of parameter names to try
            test_value: Value to use for testing
            on_finding: Callback when parameter found

        Returns:
            List of found parameters
        """
        if parameters is None:
            parameters = COMMON_PARAMETERS

        if self.ctx.verbose:
            log_info(f"Fuzzing {len(parameters)} parameters against {self.ctx.target_url}")

        # Get baseline response
        await self.setup()

        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Fuzzing parameters...", total=len(parameters))

            semaphore = asyncio.Semaphore(self.ctx.threads)

            async def test_with_semaphore(param: str):
                async with semaphore:
                    return await self._test_parameter(param, test_value)

            tasks = [test_with_semaphore(p) for p in parameters]

            for coro in asyncio.as_completed(tasks):
                result = await coro
                progress.update(task, advance=1)

                if result:
                    findings.append(result)
                    self.found_parameters.append(result)
                    if on_finding:
                        on_finding(result)

                    if self.ctx.verbose:
                        log_vulnerable(
                            self.ctx.target_url,
                            "parameter",
                            result["parameter"]
                        )

        await self.cleanup()
        self.results.extend(findings)
        return findings

    def fuzz_parameters_sync(
        self,
        parameters: Optional[list[str]] = None,
        test_value: str = "ctf_test_value",
        on_finding: Optional[Callable[[dict], None]] = None,
    ) -> list[dict]:
        """Synchronous parameter fuzzing."""
        if parameters is None:
            parameters = COMMON_PARAMETERS

        if self.ctx.verbose:
            log_info(f"Fuzzing {len(parameters)} parameters")

        self.setup_sync()
        findings = []

        with create_progress() as progress:
            task = progress.add_task("[cyan]Fuzzing parameters...", total=len(parameters))

            for param in parameters:
                result = self._test_parameter_sync(param, test_value)
                progress.update(task, advance=1)

                if result:
                    findings.append(result)
                    self.found_parameters.append(result)
                    if on_finding:
                        on_finding(result)

        self.cleanup_sync()
        self.results.extend(findings)
        return findings

    async def _test_parameter(
        self, param: str, test_value: str
    ) -> Optional[dict]:
        """Test a single parameter."""
        try:
            # Test with GET parameter
            url = self.ctx.target_url
            if "?" in url:
                url = f"{url}&{param}={test_value}"
            else:
                url = f"{url}?{param}={test_value}"

            response = await self.client.request(url=url)

            # Compare with baseline
            if self.analyzer:
                # Check for different response
                baseline_len = self.analyzer.baseline.content_length

                # Significant difference indicates parameter is processed
                if abs(response.content_length - baseline_len) > 50:
                    flags = self.flag_extractor.extract(response.text)
                    for flag in flags:
                        self.ctx.add_flag(flag)

                    return {
                        "type": "parameter_found",
                        "url": url,
                        "parameter": param,
                        "method": "GET",
                        "baseline_length": baseline_len,
                        "response_length": response.content_length,
                        "length_diff": response.content_length - baseline_len,
                        "flags_found": flags,
                    }

                # Check if parameter value is reflected (potential for XSS/injection)
                if test_value in response.text:
                    return {
                        "type": "parameter_reflected",
                        "url": url,
                        "parameter": param,
                        "method": "GET",
                        "note": "Value is reflected in response",
                        "flags_found": [],
                    }

        except Exception as e:
            if self.ctx.verbose:
                log_warning(f"Error testing parameter {param}: {e}")

        return None

    def _test_parameter_sync(
        self, param: str, test_value: str
    ) -> Optional[dict]:
        """Synchronous parameter test."""
        try:
            url = self.ctx.target_url
            if "?" in url:
                url = f"{url}&{param}={test_value}"
            else:
                url = f"{url}?{param}={test_value}"

            response = self.client.request_sync(url=url)

            if self.analyzer:
                baseline_len = self.analyzer.baseline.content_length

                if abs(response.content_length - baseline_len) > 50:
                    flags = self.flag_extractor.extract(response.text)
                    for flag in flags:
                        self.ctx.add_flag(flag)

                    return {
                        "type": "parameter_found",
                        "url": url,
                        "parameter": param,
                        "method": "GET",
                        "baseline_length": baseline_len,
                        "response_length": response.content_length,
                        "length_diff": response.content_length - baseline_len,
                        "flags_found": flags,
                    }

                if test_value in response.text:
                    return {
                        "type": "parameter_reflected",
                        "url": url,
                        "parameter": param,
                        "method": "GET",
                        "note": "Value is reflected in response",
                        "flags_found": [],
                    }

        except Exception:
            pass

        return None

    # ==================== Utility Methods ====================

    def get_summary(self) -> dict:
        """Get summary of all findings."""
        return {
            "total_findings": len(self.results),
            "directories_found": len(self.found_paths),
            "credentials_found": len(self.found_credentials),
            "parameters_found": len(self.found_parameters),
            "paths": self.found_paths,
            "credentials": self.found_credentials,
            "parameters": self.found_parameters,
        }
