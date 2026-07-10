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

from .models import AccessPoint, HandshakeCaptureInfo, PMKIDCaptureInfo, WPSState, rank_targets

# emoji=False: MAC addresses like 64:FD:96:CD:AF:EB contain :CD: which Rich renders as 💿
console = (
    Console(width=120, soft_wrap=True, emoji=False, highlight=False)
    if not sys.stdout.isatty()
    else Console(emoji=False, highlight=False)
)


_MAC_RE = re.compile(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})")

# Shared styles so ESSID / BSSID look the same in Selected, ATTACKING, tables, logs.
STYLE_ESSID = "bold cyan"
STYLE_BSSID = "dim"
STYLE_CHANNEL = "cyan"
STYLE_ENC = "yellow"


def neutralize_mac_text(value: str) -> str:
    """Break Rich :XX: emoji codes inside MAC addresses (e.g. :CD: → 💿).

    Only needed when the string will pass through markup parsing. Prefer
    text_bssid() / safe_text() for plain Text rendering.
    """
    if not value or not isinstance(value, str) or ":" not in value:
        return value if isinstance(value, str) else str(value or "")
    return _MAC_RE.sub(lambda m: m.group(1).replace(":", ":\u200b"), value)


def safe_markup(value: str) -> str:
    """Escape user-controlled text before embedding in Rich markup strings."""
    return rich_escape(neutralize_mac_text(str(value or "")))


def safe_text(value: str, style: str = "") -> Text:
    """Render user-controlled text without markup/emoji interpretation."""
    # No ZWSP injection here — Text() is not markup-parsed, and ZWSP can make
    # dim/bold styles look patchy mid-MAC on some terminals.
    return Text(str(value or ""), style=style)


def text_essid(name: str, *, style: str = STYLE_ESSID) -> Text:
    """Network name with consistent colour everywhere in the UI."""
    return Text(str(name or ""), style=style)


def text_bssid(bssid: str, *, style: str = STYLE_BSSID) -> Text:
    """MAC/BSSID with one solid style (no mid-address colour flicker)."""
    return Text((bssid or "").upper(), style=style)


def supports_live() -> bool:
    return sys.stdout.isatty()


def show_handshake_validating(ap: AccessPoint, capfile: str) -> None:
    """On-screen notice while a captured handshake is being checked."""
    import os

    cap_name = os.path.basename(capfile) if capfile else "—"
    console.print(Panel(
        "\n".join([
            "[bold bright_yellow]◆  HANDSHAKE CAPTURED[/]",
            "",
            f"Network: [cyan]{safe_markup(ap.display_name)}[/]  "
            f"[dim]|[/]  [dim]{safe_markup(ap.bssid)}[/]",
            f"File: [dim]{safe_markup(cap_name)}[/]",
            "",
            "[bold white]Checking capture…[/]",
            "[dim]Running hcxpcapngtool validation before cracking[/]",
        ]),
        border_style="bright_yellow",
        padding=(1, 2),
        title="[bold bright_yellow]Validating handshake[/]",
        title_align="center",
    ))


def show_handshake_validated(ap: AccessPoint, message: str, *, bssid: str = "") -> None:
    """Confirm a crackable handshake before the smart-wordlist step."""
    lines = [
        "[bold bright_green]✓  HANDSHAKE VALIDATED[/]",
        "",
        f"Network: [cyan]{safe_markup(ap.display_name)}[/]",
        f"Target BSSID: [dim]{safe_markup(ap.bssid)}[/]",
    ]
    if bssid and bssid.upper() != ap.bssid.upper():
        lines.append(f"Handshake BSSID: [yellow]{safe_markup(bssid)}[/]")
    lines.extend([
        "",
        f"[green]{safe_markup(message)}[/]",
        "",
        "[dim]Proceeding to password recovery…[/]",
    ])
    console.print(Panel(
        "\n".join(lines),
        border_style="bright_green",
        padding=(1, 2),
        title="[bold bright_green]Ready to crack[/]",
        title_align="center",
    ))


def show_handshake_rejected(ap: AccessPoint, reason: str) -> None:
    """Handshake candidate failed full validation."""
    console.print(Panel(
        "\n".join([
            "[bold bright_red]✗  HANDSHAKE NOT VALID[/]",
            "",
            f"Network: [cyan]{safe_markup(ap.display_name)}[/]  "
            f"[dim]|[/]  [dim]{safe_markup(ap.bssid)}[/]",
            "",
            f"[yellow]{safe_markup(reason)}[/]",
            "",
            "[dim]Capture will not be cracked — continue listening or retry.[/]",
        ]),
        border_style="bright_red",
        padding=(1, 2),
        title="[bold bright_red]Validation failed[/]",
        title_align="center",
    ))


def show_pmkid_captured(ap: AccessPoint, info: PMKIDCaptureInfo) -> None:
    """Confirm a captured PMKID hash before the smart-wordlist step."""
    import os

    hash_name = os.path.basename(info.hash_file) if info.hash_file else "—"
    hash_label = {
        "eapol": "EAPOL 4-way (hashcat 22000)",
        "pmkid": "PMKID (hashcat 22000)",
        "wpa2": "EAPOL 4-way (hashcat 22000)",  # legacy labels
        "wpa3": "PMKID (hashcat 22000)",
    }.get(info.hash_type, "hashcat 22000")

    lines = [
        "[bold bright_cyan]✓  PMKID CAPTURED[/]",
        "",
        f"Network: [cyan]{safe_markup(info.essid or ap.display_name)}[/]",
        f"BSSID: [dim]{safe_markup(info.bssid or ap.bssid)}[/]",
        f"Channel: [yellow]{info.channel or ap.channel}[/] ({ap.band_label})",
        "",
        f"[green]{safe_markup(info.summary)}[/]",
        f"Hash type: [dim]{hash_label}[/]",
        f"Saved: [dim]{safe_markup(hash_name)}[/]",
        "",
        "[dim]Proceeding to password recovery…[/]",
    ]
    console.print(Panel(
        "\n".join(lines),
        border_style="bright_cyan",
        padding=(1, 2),
        title="[bold bright_cyan]Ready to crack[/]",
        title_align="center",
    ))


def show_pmkid_captured_banner(ap: AccessPoint, info: PMKIDCaptureInfo) -> None:
    """Prominent banner before the smart-wordlist prompt after PMKID capture."""
    import os

    essid = info.essid or ap.display_name
    channel = info.channel or ap.channel
    hash_name = os.path.basename(info.hash_file) if info.hash_file else "—"
    hash_label = {
        "eapol": "EAPOL / mode 22000",
        "pmkid": "PMKID / mode 22000",
        "wpa2": "EAPOL / mode 22000",
        "wpa3": "PMKID / mode 22000",
    }.get(info.hash_type, "mode 22000")

    lines = [
        "[bold bright_cyan]◆  PMKID RECOVERED[/]",
        "[dim]Clientless capture — no handshake or deauth required[/]",
        "",
        f"Network: [bold cyan]{safe_markup(essid)}[/]  "
        f"[dim]|[/]  ch{channel} ({ap.band_label})  "
        f"[dim]|[/]  {safe_markup(ap.encryption_label)}",
        f"BSSID: [dim]{safe_markup(info.bssid or ap.bssid)}[/]",
        "",
        f"[bold white]How:[/] {safe_markup(info.summary)}",
        f"Hash: [dim]{hash_label}[/]",
        f"Saved: [dim]{safe_markup(hash_name)}[/]",
    ]

    console.print(Panel(
        "\n".join(lines),
        border_style="bright_cyan",
        padding=(1, 2),
        title="[bold bright_cyan]PMKID success[/]",
        title_align="center",
    ))


def show_handshake_captured_banner(
    ap: AccessPoint,
    info: HandshakeCaptureInfo,
) -> None:
    """Prominent banner shown before the smart-wordlist prompt after capture."""
    import os

    essid = info.essid or ap.display_name
    channel = info.channel or ap.channel
    band = ap.band_label
    cap_name = os.path.basename(info.capture_file) if info.capture_file else "—"

    lines = [
        "[bold bright_yellow]!  HANDSHAKE RECOVERED[/]",
        "[dim]Deauth was ineffective — captured during passive listen[/]",
        "",
        f"Network: [bold cyan]{safe_markup(essid)}[/]  "
        f"[dim]|[/]  ch{channel} ({band})  "
        f"[dim]|[/]  {safe_markup(ap.encryption_label)}",
        f"Target BSSID: [dim]{safe_markup(info.target_bssid or ap.bssid)}[/]",
    ]
    if info.hash_bssid and info.hash_bssid.upper() != (info.target_bssid or ap.bssid).upper():
        lines.append(
            f"Handshake BSSID: [yellow]{safe_markup(info.hash_bssid)}[/] "
            f"[dim](same router / shared PSK)[/]"
        )
    lines.extend([
        "",
        f"[bold white]How:[/] {safe_markup(info.summary)}",
    ])
    if info.deauth_rounds > 0:
        detail = f"Deauth rounds: [yellow]{info.deauth_rounds}[/]"
        if info.deauth_tools:
            detail += f"  [dim]|[/]  Tools: [cyan]{safe_markup(info.deauth_tools)}[/]"
        if info.clients > 0:
            detail += f"  [dim]|[/]  Clients: [yellow]{info.clients}[/]"
        lines.append(detail)
    if info.cap_size_kb > 0:
        lines.append(f"Capture size: [dim]{info.cap_size_kb} KB[/]")
    lines.append(f"Saved: [dim]{safe_markup(cap_name)}[/]")

    console.print(Panel(
        "\n".join(lines),
        border_style="bright_green",
        padding=(1, 2),
        title="[bold bright_green]Capture success[/]",
        title_align="center",
    ))


def banner(version: str) -> None:
    console.print(Panel.fit(
        f"[bold green]WIFLUX[/] [dim]v{version}[/]\n"
        "[cyan]Modern wireless security auditor[/]\n"
        "[dim]By Leadrogue AKA PandaFrosty[/]",
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
    table.add_column("BSSID", style=STYLE_BSSID, no_wrap=True)
    table.add_column("GHz", justify="center", width=4, style=STYLE_CHANNEL)
    table.add_column("CH", justify="center", width=4, style=STYLE_CHANNEL)
    table.add_column("ENC", width=8, style=STYLE_ENC)
    table.add_column("PWR", justify="right", width=6)
    table.add_column("WPS", width=5)
    table.add_column("CL", justify="center", width=3)
    table.add_column("SCORE", justify="right", width=6)

    ordered = targets if ranked else rank_targets(targets)
    for i, ap in enumerate(ordered, 1):
        name = ap.display_name
        if ap.decloaked:
            name += "*"
        # Known ESSIDs use shared cyan; hidden stay yellow for visibility.
        essid_style = STYLE_ESSID if ap.essid_known else "yellow"
        ghz = {"2": "2.4", "5": "5", "6": "6"}.get(ap.radio_band, "?")
        row = []
        if show_index:
            row.append(str(i))
        row.extend([
            safe_text(name, style=essid_style),
            text_bssid(ap.bssid),
            ghz,
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