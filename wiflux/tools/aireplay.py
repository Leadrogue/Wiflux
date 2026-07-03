"""Deauthentication via aireplay-ng."""

from __future__ import annotations

import time

from ..config import WifluxConfig
from ..process import ManagedProcess


class Aireplay:
    @staticmethod
    def deauth(
        cfg: WifluxConfig,
        bssid: str,
        client: str | None = None,
        count: int = 3,
        *,
        send_window: float = 1.0,
    ) -> None:
        """Send deauth packets without blocking the attack loop."""
        if cfg.attack.no_deauth:
            return
        cmd = [
            "aireplay-ng", "--deauth", str(count),
            "--ignore-negative-one",
            "-a", bssid,
        ]
        if client:
            cmd.extend(["-c", client])
        cmd.append(cfg.scan.interface)

        # Fire-and-forget: aireplay-ng can hang if the AP is out of range.
        proc = ManagedProcess(cmd, devnull=True)
        time.sleep(send_window)
        proc.kill()