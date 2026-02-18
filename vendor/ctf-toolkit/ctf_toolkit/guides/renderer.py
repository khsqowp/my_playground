"""Rich console rendering functions for learning guides."""

import json
import os
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.markdown import Markdown
from rich.columns import Columns
from rich.tree import Tree
from rich import box
from rich.markup import escape as rich_escape

console = Console(emoji=False)

# Severity colors
SEVERITY_COLORS = {
    "critical": "red bold",
    "high": "red",
    "medium": "yellow",
    "low": "green",
}

# Difficulty colors
DIFFICULTY_COLORS = {
    "beginner": "green",
    "intermediate": "yellow",
    "advanced": "red",
}

# Confidence colors
CONFIDENCE_COLORS = {
    "high": "green",
    "medium": "yellow",
    "low": "red",
}

# Checklist state file
CHECKLIST_STATE_DIR = Path.home() / ".ctf-toolkit"
CHECKLIST_STATE_FILE = CHECKLIST_STATE_DIR / "checklist_state.json"


def get_severity_badge(severity: str) -> Text:
    """Create a severity badge."""
    color = SEVERITY_COLORS.get(severity, "white")
    return Text(f"[{severity.upper()}]", style=color)


def get_difficulty_badge(difficulty: str) -> Text:
    """Create a difficulty badge."""
    color = DIFFICULTY_COLORS.get(difficulty, "white")
    return Text(f"({difficulty})", style=color)


def render_overview_list(guides: list[dict]) -> None:
    """Render list of all available guides."""
    console.print()
    console.print(Panel(
        "[bold cyan]CTF-Toolkit Learning Guides[/bold cyan]\n"
        "취약점 유형별 학습 가이드, 체크리스트, 탐지 패턴을 제공합니다.",
        title="Overview",
        border_style="cyan"
    ))
    console.print()

    table = Table(
        title="사용 가능한 가이드",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan"
    )
    table.add_column("Type", style="bold")
    table.add_column("Title")
    table.add_column("Severity", justify="center")
    table.add_column("Difficulty", justify="center")
    table.add_column("Techniques", justify="center")
    table.add_column("Checklist", justify="center")

    for guide in guides:
        severity_color = SEVERITY_COLORS.get(guide["severity"], "white")
        difficulty_color = DIFFICULTY_COLORS.get(guide["difficulty"], "white")

        table.add_row(
            guide["attack_type"].upper(),
            guide["title"],
            f"[{severity_color}]{guide['severity']}[/{severity_color}]",
            f"[{difficulty_color}]{guide['difficulty']}[/{difficulty_color}]",
            str(guide["technique_count"]),
            f"{guide['checklist_steps']} steps",
        )

    console.print(table)
    console.print()

    # Usage hints
    console.print("[dim]사용법:[/dim]")
    console.print("  [cyan]ctf-toolkit learn guide sqli[/cyan]      # SQLi 전체 가이드")
    console.print("  [cyan]ctf-toolkit learn checklist xss[/cyan]   # XSS 체크리스트")
    console.print("  [cyan]ctf-toolkit learn detect sqli[/cyan]     # 탐지 패턴")
    console.print("  [cyan]ctf-toolkit learn quick lfi[/cyan]       # 퀵 레퍼런스")
    console.print()


def render_guide_overview(guide: dict) -> None:
    """Render guide overview section."""
    severity_color = SEVERITY_COLORS.get(guide.get("severity", ""), "white")
    difficulty_color = DIFFICULTY_COLORS.get(guide.get("difficulty", ""), "white")

    # Title panel
    title_text = f"[bold]{guide['title']}[/bold]\n\n"
    title_text += f"[{severity_color}]Severity: {guide['severity'].upper()}[/{severity_color}]  "
    title_text += f"[{difficulty_color}]Difficulty: {guide['difficulty']}[/{difficulty_color}]"

    console.print()
    console.print(Panel(
        title_text,
        title=f"[bold cyan]{guide['attack_type'].upper()} Guide[/bold cyan]",
        border_style="cyan"
    ))
    console.print()

    # Overview
    console.print("[bold yellow]개요 (Overview)[/bold yellow]")
    console.print(guide.get("overview", ""))
    console.print()

    # Impact
    if guide.get("impact"):
        console.print("[bold yellow]영향 (Impact)[/bold yellow]")
        for impact in guide["impact"]:
            console.print(f"  [red]![/red] {impact}")
        console.print()


def render_technique(technique_name: str, technique: dict) -> None:
    """Render a single technique."""
    difficulty_color = DIFFICULTY_COLORS.get(technique.get("difficulty", ""), "white")

    console.print()
    console.print(Panel(
        f"[bold]{technique.get('name', technique_name)}[/bold]\n"
        f"[{difficulty_color}]Difficulty: {technique.get('difficulty', 'unknown')}[/{difficulty_color}]",
        border_style="blue"
    ))

    # How it works
    if technique.get("how_it_works"):
        console.print("[bold cyan]원리 (How it works)[/bold cyan]")
        console.print(technique["how_it_works"])
        console.print()

    # Prerequisites
    if technique.get("prerequisites"):
        console.print("[bold cyan]필수 조건 (Prerequisites)[/bold cyan]")
        for prereq in technique["prerequisites"]:
            console.print(f"  [yellow]>[/yellow] {prereq}")
        console.print()

    # Payloads
    if technique.get("payloads"):
        console.print("[bold cyan]페이로드 (Payloads)[/bold cyan]")
        payload_table = Table(box=box.SIMPLE)
        payload_table.add_column("Payload", style="green")
        payload_table.add_column("Purpose")
        payload_table.add_column("Expected")

        for payload in technique["payloads"]:
            payload_table.add_row(
                payload.get("payload", ""),
                payload.get("purpose", ""),
                payload.get("expected", ""),
            )
        console.print(payload_table)
        console.print()

    # Detection patterns
    if technique.get("detection_patterns"):
        console.print("[bold cyan]탐지 패턴 (Detection)[/bold cyan]")
        for pattern in technique["detection_patterns"]:
            console.print(f"  [green]+[/green] {pattern}")
        console.print()

    # Common mistakes
    if technique.get("common_mistakes"):
        console.print("[bold cyan]흔한 실수 (Common Mistakes)[/bold cyan]")
        for mistake in technique["common_mistakes"]:
            console.print(f"  [red]-[/red] {mistake}")
        console.print()


def render_techniques(techniques: dict, title: str = "Techniques") -> None:
    """Render all techniques."""
    console.print()
    console.print(f"[bold yellow]{title}[/bold yellow]")

    for tech_name, tech_data in techniques.items():
        render_technique(tech_name, tech_data)


def render_checklist(checklist: list[dict], attack_type: str) -> None:
    """Render checklist."""
    console.print()
    console.print(Panel(
        f"[bold]{attack_type.upper()} 취약점 점검 체크리스트[/bold]\n"
        f"총 {len(checklist)}단계의 점검 항목",
        title="Checklist",
        border_style="green"
    ))
    console.print()

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold green"
    )
    table.add_column("#", style="bold", width=3)
    table.add_column("Action", width=30)
    table.add_column("Expected Result", width=25)
    table.add_column("Notes")

    for item in checklist:
        table.add_row(
            str(item.get("step", "")),
            item.get("action", ""),
            item.get("expected_result", ""),
            item.get("notes", ""),
        )

    console.print(table)
    console.print()

    # Command examples
    console.print("[dim]명령어 예시:[/dim]")
    for item in checklist[:3]:
        if item.get("command_example"):
            console.print(f"  [cyan]{item['command_example']}[/cyan]")
    console.print()


def render_detection_patterns(
    patterns: list[dict],
    attack_type: str,
    show_examples: bool = False
) -> None:
    """Render detection patterns."""
    console.print()
    console.print(Panel(
        f"[bold]{attack_type.upper()} 취약점 탐지 패턴[/bold]\n"
        f"총 {len(patterns)}개의 탐지 패턴",
        title="Detection Patterns",
        border_style="magenta"
    ))
    console.print()

    # Group by pattern type
    by_type = {}
    for pattern in patterns:
        ptype = pattern.get("pattern_type", "other")
        if ptype not in by_type:
            by_type[ptype] = []
        by_type[ptype].append(pattern)

    for ptype, type_patterns in by_type.items():
        console.print(f"[bold cyan]{ptype.replace('_', ' ').title()}[/bold cyan]")

        table = Table(box=box.SIMPLE)
        table.add_column("Indicator", style="green")
        table.add_column("Confidence", justify="center")
        if any(p.get("db_specific") for p in type_patterns):
            table.add_column("DB Type")
        if show_examples:
            table.add_column("Example Response")

        for pattern in type_patterns:
            confidence = pattern.get("confidence", "medium")
            conf_color = CONFIDENCE_COLORS.get(confidence, "white")

            # Escape Rich markup in indicator
            indicator = rich_escape(pattern.get("indicator", ""))

            row = [
                indicator,
                f"[{conf_color}]{confidence}[/{conf_color}]",
            ]

            if any(p.get("db_specific") for p in type_patterns):
                row.append(pattern.get("db_specific", "all"))

            if show_examples and pattern.get("example_response"):
                example = rich_escape(pattern["example_response"])
                if len(example) > 50:
                    example = example[:50] + "..."
                row.append(example)

            table.add_row(*row)

        console.print(table)
        console.print()


def render_waf_bypass(bypasses: list[dict], attack_type: str) -> None:
    """Render WAF bypass techniques."""
    console.print()
    console.print(Panel(
        f"[bold]{attack_type.upper()} WAF 우회 기법[/bold]",
        title="WAF Bypass",
        border_style="yellow"
    ))
    console.print()

    table = Table(box=box.ROUNDED)
    table.add_column("Technique", style="bold")
    table.add_column("Example", style="green")
    table.add_column("Effective Against")

    for bypass in bypasses:
        table.add_row(
            bypass.get("technique", ""),
            bypass.get("example", ""),
            bypass.get("effective_against", ""),
        )

    console.print(table)
    console.print()


def render_ctf_tips(tips: list[str], attack_type: str) -> None:
    """Render CTF tips."""
    console.print()
    console.print(Panel(
        f"[bold]{attack_type.upper()} CTF 팁[/bold]",
        title="CTF Tips",
        border_style="cyan"
    ))
    console.print()

    for i, tip in enumerate(tips, 1):
        console.print(f"  [cyan]{i}.[/cyan] {tip}")

    console.print()


def render_quick_reference(quick_ref: dict) -> None:
    """Render quick reference card."""
    attack_type = quick_ref["attack_type"]
    severity_color = SEVERITY_COLORS.get(quick_ref.get("severity", ""), "white")

    console.print()
    console.print(Panel(
        f"[bold]{quick_ref['title']}[/bold] "
        f"[{severity_color}][{quick_ref['severity'].upper()}][/{severity_color}]",
        title=f"Quick Reference - {attack_type.upper()}",
        border_style="cyan"
    ))
    console.print()

    # Create columns layout
    left_content = []
    right_content = []

    # Left: Top Payloads
    left_content.append("[bold yellow]Top Payloads[/bold yellow]")
    for i, payload in enumerate(quick_ref.get("top_payloads", []), 1):
        escaped_payload = rich_escape(payload['payload'])
        escaped_purpose = rich_escape(payload.get('purpose', ''))
        left_content.append(
            f"  [green]{escaped_payload}[/green]\n"
            f"    [dim]{escaped_purpose}[/dim]"
        )

    # Right: Detection Patterns
    right_content.append("[bold yellow]Detection Patterns[/bold yellow]")
    for pattern in quick_ref.get("detection_patterns", []):
        conf = pattern.get("confidence", "medium")
        conf_color = CONFIDENCE_COLORS.get(conf, "white")
        escaped_indicator = rich_escape(pattern.get('indicator', ''))
        right_content.append(
            f"  [{conf_color}]{escaped_indicator}[/{conf_color}]"
        )

    # Print in columns
    console.print(Columns([
        "\n".join(left_content),
        "\n".join(right_content),
    ]))
    console.print()

    # Key techniques
    console.print("[bold yellow]Key Techniques[/bold yellow]")
    techniques = quick_ref.get("key_techniques", [])
    console.print("  " + " | ".join(f"[cyan]{t}[/cyan]" for t in techniques))
    console.print()

    # CTF Tips
    console.print("[bold yellow]CTF Tips[/bold yellow]")
    for tip in quick_ref.get("ctf_tips", [])[:5]:
        escaped_tip = rich_escape(tip)
        console.print(f"  [green]>[/green] {escaped_tip}")
    console.print()


def load_checklist_state() -> dict:
    """Load checklist state from file."""
    if CHECKLIST_STATE_FILE.exists():
        try:
            with open(CHECKLIST_STATE_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {}


def save_checklist_state(state: dict) -> None:
    """Save checklist state to file."""
    CHECKLIST_STATE_DIR.mkdir(parents=True, exist_ok=True)
    with open(CHECKLIST_STATE_FILE, "w") as f:
        json.dump(state, f, indent=2)


def render_interactive_checklist(checklist: list[dict], attack_type: str) -> None:
    """
    Render interactive checklist with state tracking.

    Uses keyboard navigation:
    - Space/Enter: Toggle item
    - j/Down: Move down
    - k/Up: Move up
    - q: Quit
    - r: Reset all
    """
    try:
        from rich.live import Live
        from rich.prompt import Prompt
    except ImportError:
        console.print("[red]Interactive mode requires 'rich' library[/red]")
        render_checklist(checklist, attack_type)
        return

    # Load saved state
    all_state = load_checklist_state()
    state_key = f"{attack_type}_checklist"
    completed = set(all_state.get(state_key, []))

    console.print()
    console.print(Panel(
        f"[bold]{attack_type.upper()} Interactive Checklist[/bold]\n\n"
        "[dim]Commands: [Enter] Toggle | [r] Reset | [s] Save & Exit | [q] Quit[/dim]",
        title="Interactive Mode",
        border_style="green"
    ))
    console.print()

    while True:
        # Render current state
        console.print()
        for i, item in enumerate(checklist):
            step = item.get("step", i + 1)
            check = "[green][X][/green]" if step in completed else "[ ]"
            action = item.get("action", "")

            if step in completed:
                console.print(f"  {check} [dim]{step}. {action}[/dim]")
            else:
                console.print(f"  {check} [bold]{step}.[/bold] {action}")

        console.print()
        progress = len(completed) / len(checklist) * 100
        console.print(f"[cyan]Progress: {len(completed)}/{len(checklist)} ({progress:.0f}%)[/cyan]")
        console.print()

        # Get user input
        try:
            cmd = Prompt.ask(
                "Step number to toggle (or r/s/q)",
                default=""
            )
        except (KeyboardInterrupt, EOFError):
            break

        cmd = cmd.strip().lower()

        if cmd == "q":
            break
        elif cmd == "s":
            # Save and exit
            all_state[state_key] = list(completed)
            save_checklist_state(all_state)
            console.print("[green]Progress saved![/green]")
            break
        elif cmd == "r":
            completed.clear()
            console.print("[yellow]Checklist reset![/yellow]")
        elif cmd.isdigit():
            step_num = int(cmd)
            if any(item.get("step") == step_num for item in checklist):
                if step_num in completed:
                    completed.discard(step_num)
                else:
                    completed.add(step_num)
            else:
                console.print(f"[red]Invalid step: {step_num}[/red]")

        # Clear screen for next iteration
        console.clear()
        console.print(Panel(
            f"[bold]{attack_type.upper()} Interactive Checklist[/bold]\n\n"
            "[dim]Commands: [Enter] Toggle | [r] Reset | [s] Save & Exit | [q] Quit[/dim]",
            title="Interactive Mode",
            border_style="green"
        ))


def export_checklist_markdown(checklist: list[dict], attack_type: str, output_path: str) -> None:
    """Export checklist to markdown file."""
    lines = [
        f"# {attack_type.upper()} Checklist",
        "",
        f"Total steps: {len(checklist)}",
        "",
    ]

    for item in checklist:
        step = item.get("step", "")
        action = item.get("action", "")
        expected = item.get("expected_result", "")
        notes = item.get("notes", "")
        cmd = item.get("command_example", "")

        lines.append(f"## Step {step}: {action}")
        lines.append("")
        if expected:
            lines.append(f"**Expected Result:** {expected}")
            lines.append("")
        if notes:
            lines.append(f"**Notes:** {notes}")
            lines.append("")
        if cmd:
            lines.append(f"**Command Example:**")
            lines.append(f"```bash")
            lines.append(cmd)
            lines.append(f"```")
            lines.append("")

    with open(output_path, "w") as f:
        f.write("\n".join(lines))

    console.print(f"[green]Checklist exported to: {output_path}[/green]")
