"""Decloak hidden SSIDs by deauthing associated clients during scan."""

from __future__ import annotations

import time
from typing import Callable, Optional

from ..config import WifluxConfig
from ..models import AccessPoint
from .aireplay import Aireplay
from .radio import parse_channel_spec

DECLOAK_COOLDOWN = 30  # seconds between deauth attempts per hidden BSSID


class DecloakManager:
    def __init__(self, cfg: WifluxConfig):
        self.cfg = cfg
        self.active = False
        self._last_attempt: dict[str, float] = {}

    def _fixed_channel_scan(self) -> bool:
        """True when scan is locked to a single channel (safe to retune)."""
        spec = self.cfg.scan.channels
        if not spec:
            return False
        chans = parse_channel_spec(spec)
        return len(chans) == 1

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

        from .interface import set_channel

        # Retuning mid multi-channel hop steals the radio from airodump; only
        # force channel when the scan is already fixed, else best-effort inject.
        may_retune = self._fixed_channel_scan()
        now = time.time()
        for ap in targets:
            if ap.essid_known or ap.channel <= 0:
                continue

            if now - self._last_attempt.get(ap.bssid, 0) < DECLOAK_COOLDOWN:
                continue

            self.active = True
            self._last_attempt[ap.bssid] = now

            if may_retune:
                set_channel(interface, ap.channel, band=ap.radio_band or None)

            if on_log:
                n_clients = len(ap.clients)
                # Fixed-width "chN" (e.g. ch1 / ch11 / ch149) so "(broadcast…"
                # lines up in the Activity log.
                ch_label = f"ch{ap.channel}"
                on_log(
                    f"Deauthing hidden {(ap.bssid or '').upper()} {ch_label:<5} "
                    f"(broadcast + {n_clients} client(s))"
                )

            try:
                Aireplay.deauth(self.cfg, ap.bssid, None, self.cfg.attack.num_deauths)
                for client in ap.clients:
                    Aireplay.deauth(self.cfg, ap.bssid, client.station, 1)
            except Exception as e:
                if on_log:
                    on_log(f"[yellow]failed for {ap.bssid}: {e}[/]")