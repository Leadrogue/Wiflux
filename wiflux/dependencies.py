"""Dependency detection, startup check screen, and optional apt installation."""

from __future__ import annotations

import gzip
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from rich.align import Align
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .display import console, print_error, print_info, safe_markup
from .process import which

# Primary dictionary used by crack ladder defaults / Kali layout.
ROCKYOU_TXT = "/usr/share/wordlists/rockyou.txt"
ROCKYOU_GZ = "/usr/share/wordlists/rockyou.txt.gz"


@dataclass(frozen=True)
class Dependency:
    binary: str
    apt_package: str
    label: str
    required: bool = False


DEPENDENCIES: list[Dependency] = [
    # Core capture / interface (required)
    Dependency("airodump-ng", "aircrack-ng", "airodump-ng", required=True),
    Dependency("aireplay-ng", "aircrack-ng", "aireplay-ng (deauth)", required=True),
    Dependency("airmon-ng", "aircrack-ng", "airmon-ng", required=True),
    Dependency("aircrack-ng", "aircrack-ng", "aircrack-ng", required=True),
    Dependency("iw", "iw", "iw", required=True),
    Dependency("ip", "iproute2", "ip", required=True),
    # Multi-backend handshake deauth (optional — see deauth_backends DEFAULT_HANDSHAKE_TOOLS)
    Dependency("mdk4", "mdk4", "mdk4 (deauth)", required=False),
    Dependency("bettercap", "bettercap", "bettercap (deauth)", required=False),
    Dependency("mdk3", "mdk3", "mdk3 (deauth)", required=False),
    # WPS
    Dependency("wash", "reaver", "wash (WPS scan)", required=False),
    Dependency("reaver", "reaver", "reaver (WPS)", required=False),
    Dependency("bully", "bully", "bully (WPS)", required=False),
    Dependency("pixiewps", "pixiewps", "pixiewps (offline WPS)", required=False),
    # PMKID / crack
    Dependency("hcxdumptool", "hcxdumptool", "hcxdumptool (PMKID)", required=False),
    Dependency("hcxpcapngtool", "hcxtools", "hcxpcapngtool", required=False),
    Dependency("hashcat", "hashcat", "hashcat (crack)", required=False),
    # Capture analysis (handshake validation / capture health)
    Dependency("tshark", "tshark", "tshark (capture parse)", required=False),
]


@dataclass
class CheckRow:
    name: str
    status: str  # pending | checking | ok | warn | fail | working
    detail: str = ""
    group: str = "Tools"  # Tools | Wordlists


@dataclass
class StartupCheckState:
    rows: list[CheckRow] = field(default_factory=list)
    phase: str = "Checking system requirements…"
    footer: str = ""
    done: bool = False


def missing_dependencies() -> list[Dependency]:
    return [dep for dep in DEPENDENCIES if not which(dep.binary)]


def missing_required() -> list[Dependency]:
    return [dep for dep in missing_dependencies() if dep.required]


def packages_for(deps: list[Dependency]) -> list[str]:
    return sorted({dep.apt_package for dep in deps})


def rockyou_status() -> tuple[str, str]:
    """
    Return (state, detail) for rockyou.

    state: ok | gz | missing
    """
    if os.path.isfile(ROCKYOU_TXT) and os.path.getsize(ROCKYOU_TXT) > 0:
        size_mb = os.path.getsize(ROCKYOU_TXT) / (1024 * 1024)
        return "ok", f"{ROCKYOU_TXT}  ({size_mb:.0f} MB)"
    if os.path.isfile(ROCKYOU_GZ) and os.path.getsize(ROCKYOU_GZ) > 0:
        size_mb = os.path.getsize(ROCKYOU_GZ) / (1024 * 1024)
        return "gz", f"{ROCKYOU_GZ}  ({size_mb:.0f} MB compressed)"
    return "missing", f"not found at {ROCKYOU_TXT}"


def ensure_rockyou(
    *,
    on_progress: Optional[Callable[[str, float], None]] = None,
) -> tuple[bool, str]:
    """
    Ensure rockyou.txt exists. If only the .gz is present, unpack it.

    Returns (ok, message).
    """
    state, detail = rockyou_status()
    if state == "ok":
        return True, detail

    if state != "gz":
        return False, (
            f"rockyou not found. Install with: "
            f"apt install wordlists && gunzip {ROCKYOU_GZ}"
        )

    gz_path = Path(ROCKYOU_GZ)
    txt_path = Path(ROCKYOU_TXT)
    try:
        txt_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, f"Cannot create {txt_path.parent}: {exc}"

    total = gz_path.stat().st_size
    tmp_path = txt_path.with_suffix(".txt.partial")
    try:
        if on_progress:
            on_progress("Unpacking rockyou.txt.gz…", 0.0)
        written = 0
        # rockyou.txt is typically ~3–4× the .gz size; use that for a rough %.
        expected = max(total * 3.5, 1)
        with gzip.open(gz_path, "rb") as src, open(tmp_path, "wb") as dst:
            while True:
                chunk = src.read(1024 * 1024)
                if not chunk:
                    break
                dst.write(chunk)
                written += len(chunk)
                if on_progress:
                    pct = min(99.0, (written / expected) * 100)
                    mb = written / (1024 * 1024)
                    on_progress(
                        f"Unpacking rockyou.txt.gz… {mb:.0f} MB written ({pct:.0f}%)",
                        pct,
                    )
        os.replace(tmp_path, txt_path)
        # Prefer keeping the archive; if gunzip-style removal is desired later
        # we can make it optional. Keeping .gz is safer on shared systems.
        size_mb = txt_path.stat().st_size / (1024 * 1024)
        if on_progress:
            on_progress(f"Unpacked rockyou.txt ({size_mb:.0f} MB)", 100.0)
        return True, f"{txt_path}  ({size_mb:.0f} MB, unpacked from .gz)"
    except PermissionError:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return False, (
            f"Permission denied writing {txt_path} — re-run with sudo"
        )
    except OSError as exc:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        return False, f"Failed to unpack rockyou: {exc}"


def _read_tty_line(prompt: str) -> str:
    if os.path.exists("/dev/tty"):
        fd = os.open("/dev/tty", os.O_RDWR)
        try:
            os.write(fd, prompt.encode())
            data = b""
            while True:
                chunk = os.read(fd, 1)
                if not chunk or chunk in (b"\n", b"\r"):
                    break
                data += chunk
            return data.decode(errors="replace").strip().lower()
        finally:
            os.close(fd)
    return input(prompt).strip().lower()


def prompt_install_missing(deps: list[Dependency]) -> bool:
    if not deps:
        return False

    console.print()
    console.print("[bold cyan]Install missing packages?[/]")
    console.print("[dim]The following tools are not installed:[/]")
    for dep in deps:
        tag = "[red]required[/]" if dep.required else "[yellow]optional[/]"
        console.print(
            f"  [cyan]•[/] {dep.label} [dim]({dep.binary})[/] — apt: "
            f"[green]{dep.apt_package}[/] {tag}"
        )
    console.print()
    console.print("[dim]Install missing packages via apt?[/] [bold yellow][Y/n][/]")
    answer = _read_tty_line("> ")
    return answer in ("", "y", "yes")


def install_packages(packages: list[str]) -> bool:
    if not packages:
        return True
    if not shutil.which("apt-get"):
        print_error("apt-get not found — install packages manually.")
        return False

    cmd = ["apt-get", "install", "-y", *packages]
    print_info(f"Running: [cyan]{' '.join(cmd)}[/]")
    try:
        result = subprocess.run(cmd, check=False)
        return result.returncode == 0
    except OSError as exc:
        print_error(f"Install failed: {exc}")
        return False


def restart_program() -> None:
    """Re-exec Wiflux after installing packages.

    Prefer the original entrypoint (e.g. ``/usr/local/bin/wiflux``) over
    ``python -m wiflux``. The latter can import a *namespace* package when the
    cwd is a parent of a directory named ``wiflux`` (e.g. repo at
    ``/root/wiflux`` while cwd is ``/root``), which has no ``__version__`` and
    crashes the restart.
    """
    print_info("[green]Restarting Wiflux…[/]")
    extra = sys.argv[1:]
    py = sys.executable or "/usr/bin/python3"

    candidates: list[list[str]] = []
    # 1) Same script path the user launched (console_scripts wrapper)
    argv0 = sys.argv[0] if sys.argv else ""
    if argv0:
        script = os.path.abspath(argv0)
        if os.path.isfile(script):
            candidates.append([py, script, *extra])
    # 2) wiflux on PATH
    path_bin = shutil.which("wiflux")
    if path_bin and os.path.isfile(path_bin):
        cmd = [py, path_bin, *extra]
        if cmd not in candidates:
            candidates.append(cmd)
    # 3) -m wiflux from a directory that cannot shadow the package name
    for cmd in candidates:
        try:
            os.execv(cmd[0], cmd)
        except OSError:
            continue

    # Last resort: change cwd away from any local "wiflux/" directory
    try:
        os.chdir(tempfile.gettempdir())
    except OSError:
        try:
            os.chdir("/")
        except OSError:
            pass
    try:
        os.execv(py, [py, "-m", "wiflux", *extra])
    except OSError as exc:
        print_error(f"Restart failed: {exc}")
        print_info("Re-run wiflux manually after install.")
        sys.exit(1)


def _status_style(status: str) -> tuple[str, str]:
    return {
        "pending": ("dim", "·"),
        "checking": ("cyan", "…"),
        "working": ("yellow", "↻"),
        "ok": ("green", "✓"),
        "warn": ("yellow", "!"),
        "fail": ("red", "✗"),
    }.get(status, ("white", "?"))


def _render_check_screen(state: StartupCheckState) -> Panel:
    table = Table(
        show_header=True,
        header_style="bold",
        expand=True,
        box=None,
        padding=(0, 1),
    )
    table.add_column("", width=2, justify="center")
    table.add_column("Item", min_width=22, max_width=32, no_wrap=True)
    table.add_column("Status", min_width=40, overflow="ellipsis")

    current_group = None
    for row in state.rows:
        if row.group != current_group:
            current_group = row.group
            table.add_row("", f"[bold cyan]{row.group}[/]", "")
        style, glyph = _status_style(row.status)
        detail = row.detail if isinstance(row.detail, str) else str(row.detail or "")
        table.add_row(
            f"[{style}]{glyph}[/]",
            f"[{style}]{safe_markup(str(row.name))}[/]",
            f"[dim]{safe_markup(detail)}[/]" if detail else "",
        )

    body = Text.from_markup(
        f"[bold]{safe_markup(state.phase)}[/]\n"
    )
    if state.footer:
        body.append_text(Text.from_markup(f"\n{state.footer}"))

    grid = Table.grid(expand=True, padding=(0, 0))
    grid.add_row(Align.center(Text.from_markup(
        "[bold cyan]◆  WIFLUX DEPENDENCY CHECK  ◆[/]"
    )))
    grid.add_row("")
    grid.add_row(body)
    grid.add_row("")
    grid.add_row(table)
    if state.done:
        grid.add_row("")
        grid.add_row(Align.center(Text.from_markup(
            "[dim]Screen frozen — select/copy text freely "
            "(Shift+drag if the terminal captures the mouse)[/]"
        )))
        grid.add_row(Align.center(Text.from_markup(
            "[bold bright_yellow]Press SPACE[/]  [dim]to continue[/]  "
            "[dim]·[/]  [bold yellow]Ctrl+C[/]  [dim]to quit[/]"
        )))

    border = "green" if state.done else "cyan"
    return Panel(grid, border_style=border, padding=(1, 2))


def _wait_for_space(*, timeout: float = 600.0) -> bool:
    """
    Block until Space (or timeout).

    Returns True to continue, False if the user cancelled (Ctrl+C) or no tty.
    Terminal attributes are always restored before returning.
    """
    import select
    import termios
    import tty

    from .input import _flush_tty_input, _tty_fd

    fd = _tty_fd()
    if fd is None:
        time.sleep(1.0)
        return True
    opened = not sys.stdin.isatty()
    old = None
    try:
        sys.stdout.flush()
        _flush_tty_input(fd)
        old = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.0, deadline - time.time())
            ready, _, _ = select.select([fd], [], [], min(0.5, remaining))
            if not ready:
                continue
            data = os.read(fd, 8)
            if not data:
                return True
            if b" " in data:
                return True
        return True  # timeout — continue startup
    except KeyboardInterrupt:
        return False
    except OSError:
        return True
    finally:
        if old is not None:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, old)
            except termios.error:
                pass
        if opened:
            try:
                os.close(fd)
            except OSError:
                pass


def run_startup_dependency_check() -> None:
    """
    Full-screen dependency check after the welcome splash.

    Verifies attack tools and rockyou.txt; auto-unpacks rockyou.txt.gz when needed.
    """
    if not sys.stdout.isatty():
        # Headless / piped: still try rockyou unpack, no UI.
        ensure_rockyou()
        missing = missing_required()
        if missing:
            print_error(
                f"Missing required tools: {', '.join(d.binary for d in missing)}"
            )
            sys.exit(1)
        return

    def _exit_clean() -> None:
        print_info("Interrupted.")
        sys.exit(130)

    state = StartupCheckState()
    for dep in DEPENDENCIES:
        state.rows.append(CheckRow(
            name=dep.label,
            status="pending",
            detail="waiting…",
            group="Tools",
        ))
    rockyou_row = CheckRow(
        name="rockyou.txt",
        status="pending",
        detail="waiting…",
        group="Wordlists",
    )
    state.rows.append(rockyou_row)

    tool_rows = {dep.label: state.rows[i] for i, dep in enumerate(DEPENDENCIES)}

    def refresh(live: Live) -> None:
        live.update(_render_check_screen(state))

    try:
        try:
            console.clear()
        except Exception:
            console.print()

        # Live only while scanning — continuous redraw blocks text selection.
        # When finished we stop Live and print a static panel for copy-friendly output.
        with Live(
            _render_check_screen(state),
            console=console,
            refresh_per_second=12,
            transient=True,
        ) as live:
            # --- tool checks ---
            state.phase = "Checking attack tools…"
            refresh(live)
            time.sleep(0.15)

            for dep in DEPENDENCIES:
                row = tool_rows[dep.label]
                row.status = "checking"
                row.detail = f"looking for {dep.binary}"
                refresh(live)
                time.sleep(0.04)
                # process.which() is bool-only; shutil.which gives the real path.
                path = shutil.which(dep.binary)
                if path:
                    row.status = "ok"
                    row.detail = str(path)
                else:
                    row.status = "fail" if dep.required else "warn"
                    tag = "required" if dep.required else "optional"
                    row.detail = f"missing ({tag}) — apt: {dep.apt_package}"
                refresh(live)

            # --- rockyou ---
            state.phase = "Checking wordlists…"
            rockyou_row.status = "checking"
            rockyou_row.detail = f"looking for {ROCKYOU_TXT}"
            refresh(live)
            time.sleep(0.1)

            st, detail = rockyou_status()
            if st == "ok":
                rockyou_row.status = "ok"
                rockyou_row.detail = detail
                refresh(live)
            elif st == "gz":
                rockyou_row.status = "working"
                rockyou_row.detail = f"found archive — {detail}"
                state.phase = "Unpacking rockyou.txt.gz (one-time setup)…"
                refresh(live)

                def on_progress(msg: str, pct: float) -> None:
                    rockyou_row.status = "working"
                    rockyou_row.detail = msg
                    state.phase = f"Unpacking rockyou.txt.gz… {pct:.0f}%"
                    refresh(live)

                ok, message = ensure_rockyou(on_progress=on_progress)
                if ok:
                    rockyou_row.status = "ok"
                    rockyou_row.detail = message
                    state.phase = "Wordlist ready"
                else:
                    rockyou_row.status = "warn"
                    rockyou_row.detail = message
                    state.phase = "Wordlist setup incomplete"
                refresh(live)
            else:
                rockyou_row.status = "warn"
                rockyou_row.detail = (
                    f"{detail} — install: apt install wordlists "
                    f"&& gunzip {ROCKYOU_GZ}"
                )
                refresh(live)

            # --- summary (final Live frame, then freeze outside) ---
            missing = missing_dependencies()
            req_missing = [d for d in missing if d.required]
            opt_missing = [d for d in missing if not d.required]
            ry_ok = rockyou_row.status == "ok"

            if req_missing:
                state.phase = (
                    f"Missing {len(req_missing)} required tool(s)"
                    + (f", {len(opt_missing)} optional" if opt_missing else "")
                )
                state.footer = (
                    "[red]Required tools are missing — install will be offered next.[/]"
                )
            elif opt_missing or not ry_ok:
                bits = []
                if opt_missing:
                    bits.append(f"{len(opt_missing)} optional tool(s) missing")
                if not ry_ok:
                    bits.append("rockyou unavailable")
                state.phase = "Ready with warnings"
                state.footer = "[yellow]" + " · ".join(bits) + "[/]"
            else:
                state.phase = "All checks passed"
                state.footer = "[green]Tools and rockyou dictionary are ready.[/]"

            state.done = True
            refresh(live)

        # Static panel: no Live redraw, so the terminal can select/copy text.
        console.print(_render_check_screen(state))
        if not _wait_for_space():
            _exit_clean()

    except KeyboardInterrupt:
        _exit_clean()

    # After the static panel: offer apt install if anything is missing.
    missing = missing_dependencies()
    if missing:
        try:
            install = prompt_install_missing(missing)
        except KeyboardInterrupt:
            _exit_clean()
        if install:
            pkgs = packages_for(missing)
            if install_packages(pkgs):
                # Re-check rockyou after packages (wordlists package may ship .gz).
                ensure_rockyou()
                restart_program()
            print_error("Package install failed — fix manually and re-run.")
            sys.exit(1)
        req = missing_required()
        if req:
            print_error(
                f"Missing required tools: {', '.join(d.binary for d in req)}"
            )
            sys.exit(1)
        print_info("[yellow]Continuing without optional tools.[/]")

    # Soft warn only — other wordlists / --dict still work.
    st, _ = rockyou_status()
    if st != "ok":
        print_info(
            "[yellow]rockyou.txt not available[/] — cracking will use another "
            "wordlist if found, or pass [cyan]--dict[/]."
        )
