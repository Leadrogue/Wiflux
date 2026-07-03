"""Decloak hidden SSIDs by deauthing associated clients during scan."""

from __future__ import annotations

import time
from typing import Callable, Optional

from ..config import WifluxConfig
from ..models import AccessPoint
from ..process import run
from .aireplay import Aireplay

DECLOAK_COOLDOWN = 30  # seconds between deauth attempts per hidden BSSID


def set_channel(interface: str, channel: int) -> None:
    if channel > 0:
        run(["iw", "dev", interface, "set", "channel", str(channel)], timeout=5)


class DecloakManager:
    def __init__(self, cfg: WifluxConfig):
        self.cfg = cfg
        self.active = False
        self._last_attempt: dict[str, float] = {}

    def decloak_hidden(
        self,
        targets: list[AccessPoint],
        interface: str,
        *,
        on_log: Optional[Callable[[str], None]] = None,
    ) -> None:
        """Send deauths to hidden APs to force ESSID disclosure in beacons."""
        self.active = False

        if not self.cfg.scan.decloak or self.cfg.attack.no_deauth:
            return

        now = time.time()
        for ap in targets:
            if ap.essid_known or ap.channel <= 0:
                continue

            if now - self._last_attempt.get(ap.bssid, 0) < DECLOAK_COOLDOWN:
                continue

            self.active = True
            self._last_attempt[ap.bssid] = now

            set_channel(interface, ap.channel)

            if on_log:
                n_clients = len(ap.clients)
                on_log(
                    f"Deauthing hidden {ap.bssid} ch{ap.channel} "
                    f"(broadcast + {n_clients} client(s))"
                )

            try:
                Aireplay.deauth(self.cfg, ap.bssid, None, self.cfg.attack.num_deauths)
                for client in ap.clients:
                    Aireplay.deauth(self.cfg, ap.bssid, client.station, 1)
            except Exception as e:
                if on_log:
                    on_log(f"[yellow]failed for {ap.bssid}: {e}[/]")