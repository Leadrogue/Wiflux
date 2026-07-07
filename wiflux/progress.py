"""Thread-safe live progress tracking for scan and attack phases."""

from __future__ import annotations

import sys
import threading
import time
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from rich.align import Align
from rich.console import Console, Group
from rich.errors import MarkupError
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from .display import console, neutralize_mac_text, safe_markup, supports_live
from .models import AccessPoint

MODE_LABEL_WIDTH = 10
LOG_TAG_WIDTH = 10


@dataclass
class AttackLine:
    name: str
    phase: str = "init"
    detail: str = ""
    elapsed: float = 0.0
    timeout: float = 0.0
    stats: dict[str, Any] = field(default_factory=dict)


class ProgressTracker:
    """Central hub for real-time status updates."""

    def __init__(self):
        self._lock = threading.RLock()
        self.mode: str = "idle"  # idle | scan | attack
        self.scan_elapsed: float = 0.0
        self.scan_limit: int = 0
        self.decloaking: bool = False
        self.scan_status: str = "Searching"
        self.targets: list[AccessPoint] = []
        self.discovered_targets: list[AccessPoint] = []
        self.target_index: int = 0
        self.target_total: int = 0
        self.current_target: Optional[AccessPoint] = None
        self.attacks: dict[str, AttackLine] = {}
        self.logs: deque[str] = deque(maxlen=12)
        self._live: Optional[Live] = None
        self._fallback: bool = False
        self._last_fallback_print: float = 0.0
        self._started_at: float = 0.0
        self._skip_event = threading.Event()
        self._skip_listener: Optional[Any] = None
        self._show_skip_hint: bool = False
        self._live_suspended: bool = False
        self.wps_scan_caps: dict[str, str] = {}

    def set_wps_scan_cap(self, bssid: str, cap_path: str) -> None:
        with self._lock:
            self.wps_scan_caps[bssid.upper()] = cap_path

    def log(self, msg: str, *, tag: str | None = None) -> None:
        ts = time.strftime("%H:%M:%S")
        msg = neutralize_mac_text(msg)
        with self._lock:
            if tag:
                label = f"{tag:<{LOG_TAG_WIDTH}}"
                self.logs.append(f"[dim]{ts}[/] [cyan]{label}[/] {msg}")
            else:
                self.logs.append(f"[dim]{ts}[/] {msg}")

    def begin_scan(self, scan_limit: int = 0) -> None:
        with self._lock:
            self.mode = "scan"
            self.scan_limit = scan_limit
            self.scan_elapsed = 0.0
            self.scan_status = "Searching"
            self._started_at = time.time()
            self.logs.clear()

    def set_scan_status(self, status: str) -> None:
        with self._lock:
            self.scan_status = status

    def tick_scan(self) -> None:
        with self._lock:
            if self.mode == "scan":
                self.scan_elapsed = time.time() - self._started_at

    def set_discovered_targets(self, targets: list[AccessPoint]) -> None:
        with self._lock:
            self.discovered_targets = list(targets)

    def update_scan(self, targets: list[AccessPoint], *, decloaking: bool = False) -> None:
        with self._lock:
            self.targets = targets
            self.scan_elapsed = time.time() - self._started_at
            self.decloaking = decloaking
            if targets:
                self.scan_status = "Searching"

    def begin_attack(self, index: int, total: int, ap: AccessPoint) -> None:
        with self._lock:
            self.mode = "attack"
            self.target_index = index
            self.target_total = total
            self.current_target = ap
            self.attacks.clear()
            self._started_at = time.time()
            self.clear_skip()
            self.log(
                f"[cyan]{safe_markup(ap.display_name)}[/] [dim]({safe_markup(ap.bssid)})[/]",
                tag="attack",
            )

    def enable_skip_controls(self) -> None:
        from .input import SkipListener, input_available
        self._show_skip_hint = input_available()
        if not self._show_skip_hint:
            return
        if self._skip_listener is None:
            self._skip_listener = SkipListener(self)
        self._skip_listener.start()

    def disable_skip_controls(self) -> None:
        if self._skip_listener:
            self._skip_listener.stop()
            if self._skip_listener._thread:
                self._skip_listener._thread.join(timeout=2.0)
        self._show_skip_hint = False
        self.clear_skip()

    def request_skip(self) -> None:
        with self._lock:
            if self.mode != "attack":
                return
            if self._skip_event.is_set():
                return
            self._skip_event.set()
            self.log("[yellow]Space — skipping to next attack[/]", tag="input")
        self.refresh()

    def clear_skip(self) -> None:
        self._skip_event.clear()

    def skip_requested(self) -> bool:
        return self._skip_event.is_set()

    def update_attack(
        self,
        name: str,
        phase: str,
        detail: str = "",
        *,
        timeout: float = 0.0,
        started: Optional[float] = None,
        **stats: Any,
    ) -> None:
        elapsed = time.time() - (started or self._started_at)
        with self._lock:
            self.attacks[name] = AttackLine(
                name=name, phase=phase, detail=detail,
                elapsed=elapsed, timeout=timeout, stats=stats,
            )

    def clear_attack(self, name: str) -> None:
        with self._lock:
            self.attacks.pop(name, None)

    def render(self):
        with self._lock:
            if self.mode == "scan":
                return self._render_scan()
            if self.mode == "attack":
                return self._render_attack()
            return Panel("Ready", border_style="dim")

    def _render_scan(self) -> Group:
        parts = []
        header = Text()
        header.append(f"{'SCANNING':<{MODE_LABEL_WIDTH}}", style="bold cyan")
        header.append(f"  {int(self.scan_elapsed)}s", style="white")
        if self.scan_limit:
            header.append(f" / {self.scan_limit}s", style="dim")
        clients = sum(len(t.clients) for t in self.targets)
        hidden = sum(1 for t in self.targets if not t.essid_known)
        header.append(f"  |  {len(self.targets)} APs", style="green")
        if hidden:
            header.append(f"  |  {hidden} hidden", style="yellow")
        header.append(f"  |  {clients} clients", style="green")
        if self.decloaking:
            header.append("  |  ", style="dim")
            header.append("decloaking", style="bold magenta")
        header.append("  |  ", style="dim")
        header.append("Ctrl+C", style="bold yellow")
        header.append(" when ready", style="dim")
        parts.append(header)

        if self.scan_limit:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Scan progress"),
                BarColumn(bar_width=40),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TimeElapsedColumn(),
                expand=True,
            )
            pct = min(100, (self.scan_elapsed / self.scan_limit) * 100) if self.scan_limit else 0
            progress.add_task("scan", total=100, completed=pct)
            parts.append(progress)

        if self.targets:
            from .display import build_scan_table
            parts.append(build_scan_table(self.targets, show_index=False))
        else:
            parts.append(self._render_searching())
        if self.logs:
            parts.append(self._render_logs())
        return Group(*parts)

    def _render_attack(self) -> Group:
        parts = []
        ap = self.current_target
        if ap:
            header = Text()
            header.append(f"{'ATTACKING':<{MODE_LABEL_WIDTH}}", style="bold red")
            header.append(f"  [{self.target_index}/{self.target_total}]", style="dim")
            header.append("  |  ", style="dim")
            header.append(neutralize_mac_text(ap.display_name), style="bold white")
            header.append("  |  ", style="dim")
            header.append(neutralize_mac_text(ap.bssid), style="dim")
            header.append(f"  |  ch{ap.channel}", style="cyan")
            header.append(f"  |  {ap.encryption_label}", style="yellow")
            if self._show_skip_hint:
                header.append("  |  ", style="dim")
                header.append("Space", style="bold yellow")
                header.append(" skip attack", style="dim")
            parts.append(header)

        if self.attacks:
            table = Table(show_header=True, header_style="bold", expand=True, padding=(0, 1))
            table.add_column("Attack", width=LOG_TAG_WIDTH)
            table.add_column("Phase", width=10)
            table.add_column("Status", min_width=55)
            table.add_column("Time", width=18, justify="right")

            for line in self.attacks.values():
                time_str = f"{int(line.elapsed)}s"
                if line.timeout:
                    time_str += f"/{int(line.timeout)}s"
                if line.stats.get("eta"):
                    from .tools.hashcat import Hashcat
                    time_str += f"  [magenta]ETA {Hashcat._fmt_eta(int(line.stats['eta']))}[/]"
                stats_parts = []
                if "clients" in line.stats:
                    stats_parts.append(f"clients:{line.stats['clients']}")
                if "deauths" in line.stats:
                    stats_parts.append(f"deauths:{line.stats['deauths']}")
                if "eapol" in line.stats:
                    stats_parts.append(f"EAPOL:{line.stats['eapol']}")
                if "deauth_rx" in line.stats:
                    stats_parts.append(f"deauth:{line.stats['deauth_rx']}")
                if "auth" in line.stats:
                    stats_parts.append(f"auth:{line.stats['auth']}")
                if "assoc" in line.stats:
                    stats_parts.append(f"assoc:{line.stats['assoc']}")
                if "reconnect" in line.stats:
                    flag = "yes" if line.stats["reconnect"] else "no"
                    stats_parts.append(f"reconnect:{flag}")
                if line.stats.get("wordlist", "").startswith("smart:"):
                    stats_parts.append(f"smart:{line.stats['wordlist'].split(':', 1)[1]}")
                elif line.stats.get("wordlist"):
                    stats_parts.append(f"dict:{line.stats['wordlist']}")
                if "cap_kb" in line.stats:
                    stats_parts.append(f"cap:{line.stats['cap_kb']}KB")
                if "pcap_kb" in line.stats:
                    stats_parts.append(f"pcap:{line.stats['pcap_kb']}KB")
                detail = line.detail
                if line.phase != "crack" and stats_parts:
                    detail += f"  [dim]({', '.join(stats_parts)})[/]"

                table.add_row(
                    f"[cyan]{line.name:<{LOG_TAG_WIDTH}}[/]",
                    f"[yellow]{line.phase}[/]",
                    detail,
                    time_str,
                )
            parts.append(table)
        else:
            parts.append(Text("Preparing attacks...", style="dim italic"))

        if self.logs:
            parts.append(self._render_logs())
        return Group(*parts)

    def _render_searching(self) -> Panel:
        blink = int(self.scan_elapsed * 3) % 2 == 0
        star_bright = "✦"
        star_dim = "✧"
        left = star_bright if blink else star_dim
        right = star_dim if blink else star_bright

        body = Text(justify="center")
        body.append("\n")
        body.append(left, style="bold yellow" if blink else "dim yellow")
        body.append("  ")
        body.append(self.scan_status, style="bold cyan")
        body.append("  ")
        body.append(right, style="dim yellow" if blink else "bold yellow")
        body.append("\n\n")

        if self.scan_status.lower().startswith("probing"):
            detail = "Checking WPS on nearby access points…"
        else:
            detail = "Listening for wireless networks…"
        body.append(detail, style="dim italic")

        return Panel(
            Align.center(body),
            title="[cyan]Scanning[/]",
            border_style="cyan",
            padding=(1, 2),
        )

    def _sanitize_log_markup(self, entry: str) -> str:
        from rich.markup import render as render_markup

        try:
            render_markup(entry)
            return entry
        except MarkupError:
            return safe_markup(entry)

    def _render_logs(self) -> Panel:
        with self._lock:
            if self.logs:
                body = "\n".join(self._sanitize_log_markup(e) for e in self.logs)
            else:
                body = "[dim]No events yet[/]"
        return Panel(body, title="[dim]Activity[/]", border_style="dim", padding=(0, 1))

    def _compact_status(self) -> str:
        if self.mode == "scan":
            clients = sum(len(t.clients) for t in self.targets)
            hidden = sum(1 for t in self.targets if not t.essid_known)
            limit = f"/{self.scan_limit}s" if self.scan_limit else ""
            extra = f" | {hidden} hidden" if hidden else ""
            decloak = " | decloaking" if self.decloaking else ""
            if not self.targets:
                star = "✦" if int(self.scan_elapsed * 3) % 2 == 0 else "✧"
                return (
                    f"+ Scan {int(self.scan_elapsed)}s{limit} | "
                    f"{star} {self.scan_status} {star}{decloak}"
                )
            return (
                f"+ Scan {int(self.scan_elapsed)}s{limit} | "
                f"{len(self.targets)} APs{extra} | {clients} clients{decloak}"
            )
        if self.mode == "attack" and self.current_target:
            ap = self.current_target
            skip_hint = " | Space=skip" if self._show_skip_hint else ""
            parts = [
                f"+ {'ATTACKING':<{MODE_LABEL_WIDTH}} [{self.target_index}/{self.target_total}] "
                f"| {neutralize_mac_text(ap.display_name)} | {neutralize_mac_text(ap.bssid)} | ch{ap.channel}"
                f"{skip_hint}"
            ]
            for line in self.attacks.values():
                stats = []
                if "clients" in line.stats:
                    stats.append(f"clients={line.stats['clients']}")
                if "deauths" in line.stats:
                    stats.append(f"deauths={line.stats['deauths']}")
                if "eapol" in line.stats:
                    stats.append(f"EAPOL={line.stats['eapol']}")
                if "deauth_rx" in line.stats:
                    stats.append(f"deauth={line.stats['deauth_rx']}")
                if "reconnect" in line.stats:
                    stats.append(
                        f"reconnect={'yes' if line.stats['reconnect'] else 'no'}"
                    )
                if line.stats.get("progress_pct") is not None:
                    stats.append(f"{line.stats['progress_pct']:.1f}%")
                if line.stats.get("eta"):
                    from .tools.hashcat import Hashcat
                    stats.append(f"ETA {Hashcat._fmt_eta(int(line.stats['eta']))}")
                suffix = f" ({', '.join(stats)})" if stats else ""
                parts.append(
                    f"  {line.name:<{LOG_TAG_WIDTH}} {line.detail}{suffix} [{int(line.elapsed)}s]"
                )
            return "\n".join(parts)
        return "+ Working..."

    @contextmanager
    def live(self, *, refresh: float = 4):
        if supports_live():
            self._live = Live(
                self.render(), console=console,
                refresh_per_second=refresh, transient=False,
            )
            self._live.start()
            try:
                yield self
            finally:
                try:
                    self._live.stop()
                except (MarkupError, Exception):
                    pass
                self._live = None
        else:
            self._fallback = True
            try:
                yield self
            finally:
                self._fallback = False

    @contextmanager
    def suspend_live(self):
        """Pause the live attack UI for blocking prompts (tables, y/n)."""
        had_skip = self._show_skip_hint
        self._live_suspended = True
        self.disable_skip_controls()
        was_running = self._live is not None
        if self._live:
            try:
                self._live.stop()
            except Exception:
                pass
        try:
            console.clear()
        except Exception:
            console.print("\n" * 3)
        try:
            yield
        finally:
            self._live_suspended = False
            if was_running and self._live:
                try:
                    self._live.start()
                    self.refresh()
                except Exception:
                    pass
            if had_skip:
                self.enable_skip_controls()

    def refresh(self) -> None:
        if self._live_suspended:
            return
        if self._live:
            self._live.update(self.render())
        elif self._fallback:
            now = time.time()
            if now - self._last_fallback_print >= 1.0:
                console.print(self._compact_status())
                self._last_fallback_print = now

    def run_with_updates(self, fn: Callable[[], Any], attack_name: str, phase: str, detail: str) -> Any:
        """Run a blocking function while refreshing elapsed time."""
        started = time.time()
        result_box: list[Any] = []
        error_box: list[BaseException] = []

        def worker():
            try:
                result_box.append(fn())
            except BaseException as e:
                error_box.append(e)

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        while t.is_alive():
            self.update_attack(attack_name, phase, detail, started=started)
            self.refresh()
            time.sleep(0.25)
        if error_box:
            raise error_box[0]
        return result_box[0] if result_box else None


# Module-level tracker
_tracker: Optional[ProgressTracker] = None


def get_tracker() -> ProgressTracker:
    global _tracker
    if _tracker is None:
        _tracker = ProgressTracker()
    return _tracker


def reset_tracker() -> ProgressTracker:
    global _tracker
    _tracker = ProgressTracker()
    return _tracker