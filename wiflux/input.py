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
    """Listen for Space on /dev/tty (scan pause/resume or attack skip)."""

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
            fd = os.open("/dev/tty", os.O_RDWR)
            self._fd = fd
            old = termios.tcgetattr(fd)
            self._old_term = (fd, old)
            tty.setcbreak(fd)
            while not self._stop.is_set():
                # During attack prompts Live is suspended and Space must not fire.
                # During scan pause Live is also suspended, but Space must still
                # resume — so only ignore suspended state outside scan pause.
                if getattr(self.tracker, "_live_suspended", False) and not getattr(
                    self.tracker, "scan_paused", False
                ):
                    time.sleep(0.05)
                    continue
                ready, _, _ = select.select([fd], [], [], 0.2)
                if not ready:
                    continue
                data = os.read(fd, 8)
                if not data:
                    break
                if b" " in data:
                    self.tracker.handle_space()
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
            return os.open("/dev/tty", os.O_RDWR)
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


def prompt_space_to_continue(
    *,
    message: str = "Press SPACE to continue",
    timeout: float = 600.0,
) -> None:
    """Block until the user presses Space on the tty."""
    from rich.panel import Panel

    from .display import console

    opened_fd = False
    fd = _tty_fd()
    if fd is None:
        return
    if not sys.stdin.isatty():
        opened_fd = True

    console.print()
    console.print(Panel(
        f"[bold bright_white]{message}[/]\n\n"
        "[bold bright_yellow]Press SPACE[/]  "
        "[dim]— no Enter required[/]",
        border_style="bright_cyan",
        padding=(1, 2),
    ))

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
                    return
                data = os.read(fd, 8)
                if not data:
                    return
                if b" " in data:
                    os.write(fd, b"\n")
                    return
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)
    except OSError:
        return
    finally:
        if opened_fd:
            try:
                os.close(fd)
            except OSError:
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
        fd = os.open("/dev/tty", os.O_RDWR)
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


def should_prompt_cached_handshake(cfg: WifluxConfig) -> bool:
    if cfg.attack.new_handshake:
        return False
    if cfg.auto_mode or cfg.output.quiet or cfg.output.json_output:
        return False
    return input_available()


def prompt_use_cached_handshake(
    capfile: str,
    ap: AccessPoint,
    tracker: ProgressTracker,
) -> bool:
    """Ask whether to reuse an existing hs/ capture. True = use cache."""
    import os

    from rich.panel import Panel

    from .display import console, safe_markup

    basename = os.path.basename(capfile)
    with tracker.suspend_live():
        console.print()
        console.print(Panel(
            "[bold white]Existing handshake found in hs/[/]\n\n"
            f"Network: [cyan]{safe_markup(ap.display_name)}[/]\n"
            f"File: [dim]{safe_markup(basename)}[/]\n\n"
            "[dim]Use this capture, or run a fresh handshake capture?[/]\n\n"
            "    [black on bright_green]  Y  [/]  [bold bright_white]Use saved[/]"
            "       "
            "[black on bright_red]  N  [/]  [bold bright_white]Capture fresh[/]\n\n"
            "[bold bright_yellow]Press Y or N — no Enter required[/]",
            border_style="bright_yellow",
            padding=(1, 2),
        ))
        return prompt_yn(default=False)


def should_offer_smart_wordlist(cfg: WifluxConfig) -> bool:
    """True when interactive mode should offer the smart wordlist step."""
    if cfg.attack.smart_wordlist is False:
        return False
    if cfg.auto_mode or cfg.output.quiet or cfg.output.json_output:
        return False
    return True


def prompt_resume_crack(
    cfg: WifluxConfig,
    checkpoint,
    tracker: ProgressTracker,
) -> bool:
    """Ask whether to resume a durable crack checkpoint. True = resume."""
    if not getattr(cfg.attack, "crack_checkpoints", True):
        return False
    if getattr(cfg.attack, "yes_resume_crack", False):
        tracker.log(
            "[green]Resuming crack checkpoint[/] (--yes-resume-crack)",
            tag="crack",
        )
        tracker.refresh()
        return True
    # Auto/quiet/json: resume without prompting so unattended runs continue.
    if cfg.auto_mode or cfg.output.quiet or cfg.output.json_output:
        tracker.log(
            "[green]Resuming crack checkpoint[/] (auto/quiet mode)",
            tag="crack",
        )
        tracker.refresh()
        return True
    if not input_available():
        return True

    from rich.panel import Panel

    from .display import console, safe_markup

    body_lines = [
        "[bold white]Incomplete crack checkpoint found[/]\n",
    ]
    for line in checkpoint.summary_lines():
        body_lines.append(safe_markup(line))
    body_lines.extend([
        "",
        "Resume hashcat from the saved stage/progress?",
        "",
        "    [black on bright_green]  Y  [/]  [bold bright_white]Resume[/]"
        "       "
        "[black on bright_red]  N  [/]  [bold bright_white]Start over[/]\n",
        "[bold bright_yellow]Press Y or N — no Enter required[/]",
    ])

    with tracker.suspend_live():
        console.print()
        console.print(Panel(
            "\n".join(body_lines),
            border_style="bright_cyan",
            padding=(1, 2),
        ))
        accepted = prompt_yn(default=True)

    if accepted:
        tracker.log("[green]Crack checkpoint resume accepted[/]", tag="crack")
    else:
        tracker.log("[yellow]Crack checkpoint declined — starting fresh[/]", tag="crack")
    tracker.refresh()
    return accepted


def _smart_wordlist_count(cfg: WifluxConfig) -> int:
    from .tools.smart_wordlist import DEFAULT_SMART_CANDIDATES, clamp_wordlist_size

    if cfg.attack.smart_wordlist_size > 0:
        return clamp_wordlist_size(cfg.attack.smart_wordlist_size)
    return DEFAULT_SMART_CANDIDATES


def prompt_smart_wordlist(
    cfg: WifluxConfig,
    ap: AccessPoint,
    tracker: ProgressTracker,
    *,
    capture_info=None,
    already_suspended: bool = False,
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

    def _prompt_body() -> tuple[str, int] | tuple[None, int]:
        from .display import console

        if cfg.attack.yes_smart_wordlist:
            count = _smart_wordlist_count(cfg)
            if capture_info is not None and capture_info.show_banner:
                from .models import HandshakeCaptureInfo, PMKIDCaptureInfo

                if isinstance(capture_info, HandshakeCaptureInfo):
                    from .display import show_handshake_captured_banner

                    show_handshake_captured_banner(ap, capture_info)
                elif isinstance(capture_info, PMKIDCaptureInfo):
                    from .display import show_pmkid_captured_banner

                    show_pmkid_captured_banner(ap, capture_info)
                console.print()
            path, actual = generate_and_write_smart_wordlist(ap, cfg, count)
            return path, actual

        path = ""
        actual = 0
        accepted = False
        if capture_info is not None and capture_info.show_banner:
            from .models import HandshakeCaptureInfo, PMKIDCaptureInfo

            if isinstance(capture_info, HandshakeCaptureInfo):
                from .display import show_handshake_captured_banner

                show_handshake_captured_banner(ap, capture_info)
            elif isinstance(capture_info, PMKIDCaptureInfo):
                from .display import show_pmkid_captured_banner

                show_pmkid_captured_banner(ap, capture_info)
            console.print()
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
            return None, 0
        return path, actual

    if cfg.attack.yes_smart_wordlist:
        if already_suspended:
            path, actual = _prompt_body()
        else:
            with tracker.suspend_live():
                path, actual = _prompt_body()
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

    if already_suspended:
        path, actual = _prompt_body()
    else:
        with tracker.suspend_live():
            path, actual = _prompt_body()

    if not path:
        if actual == 0:
            tracker.log(
                "[yellow]ESSID-smart wordlist declined[/] — using full dictionary",
                tag="crack",
            )
            tracker.refresh()
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