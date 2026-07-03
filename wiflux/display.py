"""Rich-based terminal UI."""

from __future__ import annotations

import re
import sys
from typing import Optional

from rich.console import Console
from rich.live import Live
from rich.markup import escape as rich_escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .models import AccessPoint, WPSState, rank_targets

# emoji=False: MAC addresses like 64:FD:96:CD:AF:EB contain :CD: which Rich renders as 💿
console = (
    Console(width=120, soft_wrap=True, emoji=False)
    if not sys.stdout.isatty()
    else Console(emoji=False)
)


_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")


def neutralize_mac_text(value: str) -> str:
    """Break Rich :XX: emoji codes inside MAC addresses (e.g. :CD: → 💿)."""
    if not value or ":" not in value:
        return value
    return _MAC_RE.sub(lambda m: m.group(1).replace(":", ":\u200b"), value)


def safe_markup(value: str) -> str:
    """Escape user-controlled text before embedding in Rich markup strings."""
    return rich_escape(neutralize_mac_text(value))


def safe_text(value: str, style: str = "") -> Text:
    """Render user-controlled text without markup/emoji interpretation."""
    return Text(neutralize_mac_text(value), style=style)


def supports_live() -> bool:
    return sys.stdout.isatty()


def banner(version: str) -> None:
    console.print(Panel.fit(
        f"[bold green]WIFLUX[/] [dim]v{version}[/]\n"
        "[cyan]Modern wireless security auditor[/]",
        border_style="green",
    ))


def _power_style(power: int) -> str:
    if power > 50:
        return "bold green"
    if power > 35:
        return "yellow"
    return "red"


def _wps_label(ap: AccessPoint) -> str:
    labels = {
        WPSState.UNLOCKED: "[green]yes[/]",
        WPSState.LOCKED: "[red]lock[/]",
        WPSState.NONE: "[dim]no[/]",
        WPSState.UNKNOWN: "[dim]n/a[/]",
    }
    return labels.get(ap.wps, "?")


def build_scan_table(
    targets: list[AccessPoint],
    *,
    show_index: bool = True,
    ranked: bool = False,
) -> Table:
    """Build AP table. Row numbers match list indices when ranked=True."""
    table = Table(title="Discovered Networks", expand=True, show_lines=False)
    if show_index:
        table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("ESSID", min_width=20, max_width=28, no_wrap=True, overflow="ellipsis")
    table.add_column("BSSID", style="dim", no_wrap=True)
    table.add_column("CH", justify="center", width=4)
    table.add_column("ENC", width=8)
    table.add_column("PWR", justify="right", width=6)
    table.add_column("WPS", width=5)
    table.add_column("CL", justify="center", width=3)
    table.add_column("SCORE", justify="right", width=6)

    ordered = targets if ranked else rank_targets(targets)
    for i, ap in enumerate(ordered, 1):
        name = ap.display_name
        if ap.decloaked:
            name += "*"
        style = "cyan" if ap.essid_known else "yellow"
        row = []
        if show_index:
            row.append(str(i))
        row.extend([
            safe_text(name, style=style),
            safe_text(ap.bssid, style="dim"),
            str(ap.channel),
            ap.encryption_label,
            f"[{_power_style(ap.power)}]{ap.power}[/]",
            _wps_label(ap),
            str(len(ap.clients)) if ap.clients else "-",
            f"{ap.score():.0f}",
        ])
        table.add_row(*row)
    return table


def print_targets(targets: list[AccessPoint]) -> None:
    if not targets:
        console.print("[yellow]No targets found.[/]")
        return
    # ranked=True: row #N == targets[N-1] for selection
    console.print(build_scan_table(targets, ranked=True))


def live_scan_render(targets: list[AccessPoint], elapsed: int, scan_limit: int) -> Table:
    outer = Table.grid()
    status = f"Scanning... {elapsed}s"
    if scan_limit:
        status += f" / {scan_limit}s"
    status += f" | {len(targets)} APs | {sum(len(t.clients) for t in targets)} clients"
    outer.add_row(Text(status, style="bold cyan"))
    outer.add_row(build_scan_table(targets, show_index=False))
    return outer


def print_attack_status(ap: AccessPoint, attack: str, status: str) -> None:
    console.print(
        f"[bold]+[/] [cyan]{attack}[/] → [white]{safe_markup(ap.display_name)}[/] "
        f"[dim]({safe_markup(ap.bssid)})[/] — {status}"
    )


def print_crack(result) -> None:
    console.print(Panel(
        f"[bold green]CRACKED[/]\n"
        f"ESSID: [cyan]{safe_markup(result.essid)}[/]\n"
        f"BSSID: [dim]{safe_markup(result.bssid)}[/]\n"
        f"Key:   [bold yellow]{safe_markup(result.key)}[/]\n"
        f"Method: {result.method}",
        border_style="green",
    ))


def print_error(msg: str) -> None:
    console.print(f"[bold red]![/] {msg}")


def print_info(msg: str) -> None:
    console.print(f"[bold green]+[/] {msg}")