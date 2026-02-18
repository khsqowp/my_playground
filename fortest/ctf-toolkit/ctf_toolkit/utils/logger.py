"""Rich-based logging utilities for CTF Toolkit."""

from rich.console import Console
from rich.theme import Theme
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from typing import Optional, Any

# Custom theme for security tools
custom_theme = Theme({
    "info": "cyan",
    "success": "green bold",
    "warning": "yellow",
    "error": "red bold",
    "highlight": "magenta bold",
    "flag": "green on black bold",
    "payload": "yellow italic",
    "url": "blue underline",
})

console = Console(theme=custom_theme)


def log_info(message: str, prefix: str = "[*]") -> None:
    """Log an info message."""
    console.print(f"[info]{prefix}[/info] {message}")


def log_success(message: str, prefix: str = "[+]") -> None:
    """Log a success message."""
    console.print(f"[success]{prefix}[/success] {message}")


def log_error(message: str, prefix: str = "[-]") -> None:
    """Log an error message."""
    console.print(f"[error]{prefix}[/error] {message}")


def log_warning(message: str, prefix: str = "[!]") -> None:
    """Log a warning message."""
    console.print(f"[warning]{prefix}[/warning] {message}")


def log_flag(flag: str) -> None:
    """Log a found flag with highlighting."""
    console.print(Panel(
        f"[flag]{flag}[/flag]",
        title="[success]FLAG FOUND[/success]",
        border_style="green"
    ))


def log_payload(payload: str, status: str = "testing") -> None:
    """Log a payload being tested."""
    console.print(f"  [payload]→ {payload}[/payload] [{status}]")


def log_vulnerable(url: str, param: str, payload: str) -> None:
    """Log a vulnerability finding."""
    console.print(Panel(
        f"[url]URL:[/url] {url}\n"
        f"[info]Parameter:[/info] {param}\n"
        f"[payload]Payload:[/payload] {payload}",
        title="[error]VULNERABILITY FOUND[/error]",
        border_style="red"
    ))


def create_results_table(title: str, columns: list[str]) -> Table:
    """Create a table for displaying results."""
    table = Table(title=title, show_header=True, header_style="bold cyan")
    for col in columns:
        table.add_column(col)
    return table


def create_progress() -> Progress:
    """Create a progress bar for scanning operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console
    )


def print_banner() -> None:
    """Print the CTF Toolkit banner."""
    banner = """
   ____ _____ _____   _____           _ _    _ _
  / ___|_   _|  ___| |_   _|__   ___ | | | _(_) |_
 | |     | | | |_      | |/ _ \\ / _ \\| | |/ / | __|
 | |___  | | |  _|     | | (_) | (_) | |   <| | |_
  \\____| |_| |_|       |_|\\___/ \\___/|_|_|\\_\\_|\\__|

    CTF/Pentest Automation Toolkit v0.1.0
"""
    console.print(f"[cyan]{banner}[/cyan]")


def print_section(title: str) -> None:
    """Print a section header."""
    console.print(f"\n[bold cyan]{'='*50}[/bold cyan]")
    console.print(f"[bold cyan] {title}[/bold cyan]")
    console.print(f"[bold cyan]{'='*50}[/bold cyan]\n")
