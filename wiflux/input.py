"""Non-blocking keyboard input during live attack UI."""

from __future__ import annotations

import os
import select
import sys
import termios
import threading
import time
import tty
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .config import WifluxConfig
    from .models import AccessPoint
    from .progress import ProgressTracker


class SkipListener:
    """Listen for Space on /dev/tty to skip the current attack."""

    def __init__(self, tracker: ProgressTracker):
        self.tracker = tracker
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._fd: Optional[int] = None
        self._old_term: Optional[tuple[int, list]] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if not os.path.exists("/dev/tty"):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="wiflux-skip", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None
        self._restore_term()

    def _run(self) -> None:
        fd: Optional[int] = None
        try:
            fd = os.open("/dev/tty", os.O_RDONLY)
            self._fd = fd
            old = termios.tcgetattr(fd)
            self._old_term = (fd, old)
            tty.setcbreak(fd)
            while not self._stop.is_set():
                if getattr(self.tracker, "_live_suspended", False):
                    time.sleep(0.05)
                    continue
                ready, _, _ = select.select([fd], [], [], 0.2)
                if not ready:
                    continue
                data = os.read(fd, 8)
                if not data:
                    break
                if b" " in data:
                    self.tracker.request_skip()
                # Other keys are discarded here — must not run during prompts.
        except OSError:
            pass
        finally:
            self._restore_term()

    def _restore_term(self) -> None:
        if self._old_term:
            tfd, old = self._old_term
            try:
                termios.tcsetattr(tfd, termios.TCSADRAIN, old)
            except termios.error:
                pass
            self._old_term = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


def input_available() -> bool:
    return sys.stdin.isatty() or os.path.exists("/dev/tty")


def _tty_fd() -> int | None:
    """Return a tty fd for exclusive keyboard reads."""
    if sys.stdin.isatty():
        return sys.stdin.fileno()
    if os.path.exists("/dev/tty"):
        try:
            return os.open("/dev/tty", os.O_RDONLY | os.O_WRONLY)
        except OSError:
            return None
    return None


def _flush_tty_input(fd: int) -> None:
    """Discard stale keypresses left in the tty buffer."""
    try:
        old = termios.tcgetattr(fd)
    except termios.error:
        return
    try:
        tty.setcbreak(fd)
        while True:
            ready, _, _ = select.select([fd], [], [], 0)
            if not ready:
                break
            if not os.read(fd, 256):
                break
    except OSError:
        pass
    finally:
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
        except termios.error:
            pass


def prompt_yn(*, default: bool = False, timeout: float = 300.0) -> bool:
    """Read a single Y or N key from the tty (Enter not required)."""
    if not input_available():
        return default

    opened_fd = False
    fd = _tty_fd()
    if fd is None:
        return default
    if not sys.stdin.isatty():
        opened_fd = True

    try:
        sys.stdout.flush()
        sys.stderr.flush()
        _flush_tty_input(fd)
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            deadline = time.time() + timeout
            while time.time() < deadline:
                remaining = max(0.0, deadline - time.time())
                ready, _, _ = select.select([fd], [], [], remaining)
                if not ready:
                    os.write(fd, b"\n")
                    return default
                data = os.read(fd, 8)
                if not data:
                    return default
                for byte in data:
                    ch = bytes((byte,)).lower()
                    if ch == b"y":
                        os.write(fd, b"  \xe2\x86\x92 YES\n")
                        return True
                    if ch == b"n":
                        os.write(fd, b"  \xe2\x86\x92 NO\n")
                        return False
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except OSError:
        return default
    finally:
        if opened_fd:
            try:
                os.close(fd)
            except OSError:
                pass


def prompt_wordlist_count(
    *,
    default: int | None = None,
    maximum: int | None = None,
) -> int:
    """Ask how many smart-wordlist passwords to generate."""
    from .display import console
    from .tools.smart_wordlist import (
        DEFAULT_SMART_CANDIDATES,
        MAX_SMART_CANDIDATES,
        clamp_wordlist_size,
    )

    default_n = default or DEFAULT_SMART_CANDIDATES
    max_n = maximum or MAX_SMART_CANDIDATES

    console.print()
    console.print(
        "[bold]How many passwords should wiflux generate?[/]\n"
        f"[dim]Default:[/] [yellow]{default_n:,}[/]  "
        f"[dim]|[/]  [dim]Maximum:[/] [yellow]{max_n:,}[/]"
    )
    console.print("[dim]Press Enter for default, or type a number:[/]")
    try:
        reply = console.input("[bold cyan]›[/] ").strip().replace(",", "").replace("_", "")
    except (EOFError, KeyboardInterrupt):
        return default_n
    if not reply:
        return default_n
    try:
        requested = int(reply)
    except ValueError:
        console.print(f"[yellow]Invalid number — using default {default_n:,}[/]")
        return default_n
    if requested > max_n:
        console.print(f"[yellow]Capped at maximum {max_n:,}[/]")
    return clamp_wordlist_size(requested, default=default_n, maximum=max_n)


def confirm_action(prompt: str, *, default: bool = False) -> bool:
    """Read y/n from /dev/tty. Returns *default* when input is unavailable."""
    if not input_available():
        return default
    try:
        fd = os.open("/dev/tty", os.O_RDONLY | os.O_WRONLY)
    except OSError:
        return default
    try:
        yn = "Y/n" if default else "y/N"
        os.write(
            fd,
            (f"{prompt} [{yn}] (press key) ").encode("utf-8", errors="replace"),
        )
        old = termios.tcgetattr(fd)
        try:
            tty.setcbreak(fd)
            while True:
                ready, _, _ = select.select([fd], [], [], 300.0)
                if not ready:
                    os.write(fd, b"\n")
                    return default
                data = os.read(fd, 8)
                if not data:
                    return default
                ch = data[0:1].lower()
                if ch == b"y":
                    os.write(fd, b"\xe2\x86\x92 Yes\n")
                    return True
                if ch == b"n":
                    os.write(fd, b"\xe2\x86\x92 No\n")
                    return False
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except OSError:
        return default
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def should_offer_smart_wordlist(cfg: WifluxConfig) -> bool:
    """True when interactive mode should offer the smart wordlist step."""
    if cfg.attack.smart_wordlist is False:
        return False
    if cfg.auto_mode or cfg.output.quiet or cfg.output.json_output:
        return False
    return True


def _smart_wordlist_count(cfg: WifluxConfig) -> int:
    from .tools.smart_wordlist import DEFAULT_SMART_CANDIDATES, clamp_wordlist_size

    if cfg.attack.smart_wordlist_size > 0:
        return clamp_wordlist_size(cfg.attack.smart_wordlist_size)
    return DEFAULT_SMART_CANDIDATES


def prompt_smart_wordlist(
    cfg: WifluxConfig,
    ap: AccessPoint,
    tracker: ProgressTracker,
) -> tuple[str, int] | None:
    """Preview, confirm, generate. Returns (temp_path, count) or None."""
    if not should_offer_smart_wordlist(cfg):
        return None

    from .tools.smart_wordlist import (
        DEFAULT_SMART_CANDIDATES,
        _essid_for_ap,
        generate_and_write_smart_wordlist,
        generate_candidates,
        show_smart_wordlist_preview,
    )

    essid = ap.essid or ap.display_name

    if cfg.attack.yes_smart_wordlist:
        count = _smart_wordlist_count(cfg)
        with tracker.suspend_live():
            path, actual = generate_and_write_smart_wordlist(ap, cfg, count)
        if not path:
            return None
        tracker.log(
            f"[green]ESSID-smart wordlist enabled[/] "
            f"([yellow]{actual:,}[/] candidates, --yes-smart-wordlist)",
            tag="crack",
        )
        tracker.refresh()
        return path, actual

    preview_sample = generate_candidates(
        _essid_for_ap(ap),
        ap.bssid,
        ap.manufacturer,
        data_dir=cfg.output.data_dir,
        max_candidates=DEFAULT_SMART_CANDIDATES,
    )
    if not preview_sample:
        return None

    from .display import console

    path = ""
    actual = 0
    accepted = False
    with tracker.suspend_live():
        show_smart_wordlist_preview(ap, preview_sample, cfg)
        from rich.panel import Panel

        console.print()
        console.print(Panel(
            "[bold white]Use ESSID-smart wordlist before full dictionary?[/]\n\n"
            "    [black on bright_green]  Y  [/]  [bold bright_white]Yes[/]"
            "       "
            "[black on bright_red]  N  [/]  [bold bright_white]No[/]\n\n"
            "[bold bright_yellow]Press Y or N — no Enter required[/]",
            border_style="bright_yellow",
            padding=(1, 2),
        ))
        if prompt_yn(default=False):
            accepted = True
            count = prompt_wordlist_count()
            path, actual = generate_and_write_smart_wordlist(ap, cfg, count)

    if not accepted:
        tracker.log(
            "[yellow]ESSID-smart wordlist declined[/] — using full dictionary",
            tag="crack",
        )
        tracker.refresh()
        return None
    if not path:
        return None

    tracker.log(
        f"[green]ESSID-smart wordlist selected[/] — "
        f"[yellow]{actual:,}[/] candidates for [cyan]{essid}[/]",
        tag="crack",
    )
    tracker.refresh()
    return path, actual


def resolve_capture_health(cfg, tracker: ProgressTracker | None = None) -> bool:
    """Resolve whether to show live capture health (asks once per session)."""
    attack = cfg.attack
    if attack.capture_health is not None:
        return attack.capture_health
    if attack.yes_capture_health:
        return True
    if cfg.auto_mode or cfg.output.quiet or cfg.output.json_output:
        return False
    cached = getattr(cfg, "_resolved_capture_health", None)
    if cached is not None:
        return cached
    if tracker is None:
        from .progress import get_tracker
        tracker = get_tracker()
    from .display import console
    from rich.panel import Panel

    answer = False
    with tracker.suspend_live():
        console.print()
        console.print(Panel(
            "[bold white]Show live capture health during handshake capture?[/]\n\n"
            "[dim]Adds EAPOL / deauth / reconnect counters to the progress table.[/]\n\n"
            "    [black on bright_green]  Y  [/]  [bold bright_white]Yes[/]"
            "       "
            "[black on bright_red]  N  [/]  [bold bright_white]No[/]\n\n"
            "[bold bright_yellow]Press Y or N — no Enter required[/]",
            border_style="bright_yellow",
            padding=(1, 2),
        ))
        answer = prompt_yn(default=False)
    cfg._resolved_capture_health = answer
    return answer