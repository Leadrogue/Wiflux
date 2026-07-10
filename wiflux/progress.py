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

from .display import (
    STYLE_CHANNEL,
    STYLE_ENC,
    console,
    neutralize_mac_text,
    safe_markup,
    supports_live,
    text_bssid,
    text_essid,
)
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
        self.scan_paused: bool = False
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
        self._paused_total: float = 0.0
        self._pause_started: float = 0.0
        self._skip_event = threading.Event()
        self._skip_pass_event = threading.Event()
        self._skip_listener: Optional[Any] = None
        self._show_skip_hint: bool = False
        self._show_scan_pause_hint: bool = False
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
            self.scan_paused = False
            self._started_at = time.time()
            self._paused_total = 0.0
            self._pause_started = 0.0
            self.logs.clear()

    def set_scan_status(self, status: str) -> None:
        with self._lock:
            self.scan_status = status

    def _effective_scan_elapsed(self) -> float:
        """Elapsed scan time excluding periods spent paused."""
        paused = self._paused_total
        if self.scan_paused and self._pause_started:
            paused += time.time() - self._pause_started
        if not self._started_at:
            return 0.0
        return max(0.0, time.time() - self._started_at - paused)

    def tick_scan(self) -> None:
        with self._lock:
            if self.mode == "scan" and not self.scan_paused:
                self.scan_elapsed = self._effective_scan_elapsed()

    def set_discovered_targets(self, targets: list[AccessPoint]) -> None:
        with self._lock:
            self.discovered_targets = list(targets)

    def update_scan(self, targets: list[AccessPoint], *, decloaking: bool = False) -> None:
        with self._lock:
            if self.scan_paused:
                # Keep last known list frozen while paused (caller should not update).
                return
            self.targets = targets
            self.scan_elapsed = self._effective_scan_elapsed()
            self.decloaking = decloaking
            if targets:
                self.scan_status = "Searching"

    def is_scan_paused(self) -> bool:
        with self._lock:
            return self.mode == "scan" and self.scan_paused

    def begin_attack(self, index: int, total: int, ap: AccessPoint) -> None:
        from .input import input_available

        with self._lock:
            self.mode = "attack"
            self.target_index = index
            self.target_total = total
            self.current_target = ap
            self.attacks.clear()
            self._started_at = time.time()
            self.clear_skip()
            # Orchestrator may enable controls before mode flips to attack.
            if input_available():
                self._show_skip_hint = True
            self.log(
                f"[cyan]{safe_markup(ap.display_name)}[/] [dim]({safe_markup(ap.bssid)})[/]",
                tag="attack",
            )

    def enable_skip_controls(self) -> None:
        """Enable Space listener for attack skip (next attack / next crack pass)."""
        from .input import SkipListener, input_available
        available = input_available()
        # Do not require mode == "attack": attack_all() enables controls before
        # begin_attack() flips the mode, which previously hid the Space hint
        # and prevented re-enable after suspend_live() prompts.
        self._show_skip_hint = available
        self._show_scan_pause_hint = False
        if not available:
            return
        if self._skip_listener is None:
            self._skip_listener = SkipListener(self)
        self._skip_listener.start()

    def enable_scan_controls(self) -> None:
        """Enable Space-to-pause during the initial live scan."""
        from .input import SkipListener, input_available
        self._show_scan_pause_hint = input_available()
        self._show_skip_hint = False
        if not self._show_scan_pause_hint:
            return
        if self._skip_listener is None:
            self._skip_listener = SkipListener(self)
        self._skip_listener.start()

    def disable_skip_controls(self) -> None:
        if self._skip_listener:
            self._skip_listener.stop()
            if self._skip_listener._thread:
                self._skip_listener._thread.join(timeout=2.0)
            self._skip_listener = None
        self._show_skip_hint = False
        self._show_scan_pause_hint = False
        self.clear_skip()
        # Ensure a paused scan cannot leave Live permanently stopped.
        if self.scan_paused:
            self._force_resume_scan_ui()

    def disable_scan_controls(self) -> None:
        """Stop scan Space listener and clear any pause freeze."""
        was_paused = self.scan_paused
        if was_paused:
            with self._lock:
                if self._pause_started:
                    self._paused_total += time.time() - self._pause_started
                    self._pause_started = 0.0
                self.scan_paused = False
            self._resume_scan_live()
        self.disable_skip_controls()

    def _in_crack_phase(self) -> bool:
        return any(line.phase == "crack" for line in self.attacks.values())

    def handle_space(self) -> None:
        """Route Space: pause/resume scan, or skip attack/crack pass."""
        with self._lock:
            mode = self.mode
        if mode == "scan":
            self.toggle_scan_pause()
        elif mode == "attack":
            self.request_skip()

    def toggle_scan_pause(self) -> None:
        """Toggle scan pause. While paused, Live UI freezes so text can be copied."""
        resume = False
        with self._lock:
            if self.mode != "scan":
                return
            if self.scan_paused:
                if self._pause_started:
                    self._paused_total += time.time() - self._pause_started
                    self._pause_started = 0.0
                self.scan_paused = False
                self.scan_elapsed = self._effective_scan_elapsed()
                resume = True
            else:
                self.scan_paused = True
                self._pause_started = time.time()
                # Freeze displayed elapsed at the moment of pause.
                self.scan_elapsed = self._effective_scan_elapsed()

        if resume:
            self.log("[green]Scan resumed[/] — Space pauses again", tag="scan")
            self._resume_scan_live()
            self.refresh()
        else:
            self.log(
                "[yellow]Scan paused[/] — copy text freely; [bold]Space[/] resumes",
                tag="scan",
            )
            self._freeze_scan_live()

    def _freeze_scan_live(self) -> None:
        """Stop Live redraw so the terminal buffer is stable for selection/copy."""
        self._live_suspended = True
        if self._live:
            try:
                self._live.update(self.render())
            except Exception:
                pass
            try:
                self._live.stop()
            except Exception:
                pass
        elif self._fallback:
            console.print(self.render())

    def _resume_scan_live(self) -> None:
        self._live_suspended = False
        if self._live:
            try:
                started = bool(getattr(self._live, "is_started", False))
                if not started:
                    self._live.start()
            except Exception:
                try:
                    self._live.start()
                except Exception:
                    pass
            try:
                self._live.update(self.render())
            except Exception:
                pass

    def _force_resume_scan_ui(self) -> None:
        with self._lock:
            if self._pause_started:
                self._paused_total += time.time() - self._pause_started
                self._pause_started = 0.0
            self.scan_paused = False
        self._resume_scan_live()

    def request_skip(self) -> None:
        with self._lock:
            if self.mode != "attack":
                return
            if self._in_crack_phase():
                if self._skip_pass_event.is_set():
                    return
                self._skip_pass_event.set()
                self.log("[yellow]Space — skipping to next crack pass[/]", tag="input")
            else:
                if self._skip_event.is_set():
                    return
                self._skip_event.set()
                self.log("[yellow]Space — skipping to next attack[/]", tag="input")
        self.refresh()

    def clear_skip(self) -> None:
        self._skip_event.clear()
        self._skip_pass_event.clear()

    def clear_skip_pass(self) -> None:
        self._skip_pass_event.clear()

    def skip_requested(self) -> bool:
        return self._skip_event.is_set()

    def skip_pass_requested(self) -> bool:
        return self._skip_pass_event.is_set()

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
        if self.scan_paused:
            header.append(f"{'PAUSED':<{MODE_LABEL_WIDTH}}", style="bold yellow")
        else:
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
        if self.decloaking and not self.scan_paused:
            header.append("  |  ", style="dim")
            header.append("decloaking", style="bold magenta")
        # Always surface Space pause/resume when a tty is available.
        if self._show_scan_pause_hint or self.scan_paused:
            header.append("  |  ", style="dim")
            header.append("Space", style="bold yellow")
            if self.scan_paused:
                header.append(" resume", style="dim")
            else:
                header.append(" pause", style="dim")
        header.append("  |  ", style="dim")
        header.append("Ctrl+C", style="bold yellow")
        header.append(" when ready", style="dim")
        parts.append(header)

        if self.scan_paused:
            parts.append(Panel(
                "[bold yellow]SCAN PAUSED[/]\n\n"
                "Live updates are frozen so you can select and copy text.\n"
                "[bold]Space[/]  resume scanning\n"
                "[dim]Ctrl+C  finish scan when ready[/]",
                border_style="yellow",
                padding=(0, 1),
            ))

        if self.scan_limit:
            progress = Progress(
                SpinnerColumn(),
                TextColumn(
                    "[yellow]Scan paused[/]" if self.scan_paused else "[cyan]Scan progress"
                ),
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
            # Show selection numbers while paused so copied rows include target #.
            parts.append(build_scan_table(
                self.targets,
                show_index=self.scan_paused,
                ranked=self.scan_paused,
            ))
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
            # Match Selected-line colours: cyan ESSID, solid dim BSSID.
            header.append_text(text_essid(ap.display_name))
            header.append("  |  ", style="dim")
            header.append_text(text_bssid(ap.bssid))
            header.append(f"  |  ch{ap.channel}", style=STYLE_CHANNEL)
            header.append(f"  |  {ap.encryption_label}", style=STYLE_ENC)
            if self._show_skip_hint:
                header.append("  |  ", style="dim")
                header.append("Space", style="bold yellow")
                if self._in_crack_phase():
                    header.append(" skip pass", style="dim")
                else:
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
            decloak = " | decloaking" if self.decloaking and not self.scan_paused else ""
            pause = " | PAUSED (Space=resume)" if self.scan_paused else " | Space=pause"
            if not self.targets:
                star = "✦" if int(self.scan_elapsed * 3) % 2 == 0 else "✧"
                return (
                    f"+ Scan {int(self.scan_elapsed)}s{limit} | "
                    f"{star} {self.scan_status} {star}{decloak}{pause}"
                )
            return (
                f"+ Scan {int(self.scan_elapsed)}s{limit} | "
                f"{len(self.targets)} APs{extra} | {clients} clients{decloak}{pause}"
            )
        if self.mode == "attack" and self.current_target:
            ap = self.current_target
            if self._show_skip_hint:
                skip_hint = (
                    " | Space=skip pass"
                    if self._in_crack_phase()
                    else " | Space=skip attack"
                )
            else:
                skip_hint = ""
            parts = [
                f"+ {'ATTACKING':<{MODE_LABEL_WIDTH}} [{self.target_index}/{self.target_total}] "
                f"| {ap.display_name} | {(ap.bssid or '').upper()} | ch{ap.channel}"
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
        # Re-enable skip after prompts if we had a listener, a visible hint, or
        # are in attack mode. Gating only on _show_skip_hint dropped Space skip
        # permanently after the first handshake/PMKID confirmation dialog.
        restore_skip = (
            self._skip_listener is not None
            or self._show_skip_hint
            or self.mode == "attack"
        )
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
            if restore_skip:
                self.enable_skip_controls()

    def refresh(self) -> None:
        if self._live_suspended or self.scan_paused:
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