"""Live capture health metrics from growing .cap files."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass

from ..process import run, which

# Rate-limit expensive tshark runs during live capture.
_last_poll: dict[str, tuple[int, float, "CaptureHealth"]] = {}


@dataclass
class CaptureHealth:
    eapol: int = 0
    deauth: int = 0
    auth: int = 0
    assoc: int = 0
    reconnect: bool = False

    def as_stats(self) -> dict[str, int | bool]:
        return {
            "eapol": self.eapol,
            "deauth_rx": self.deauth,
            "auth": self.auth,
            "assoc": self.assoc,
            "reconnect": self.reconnect,
        }


def _count_frames(capfile: str, filt: str, *, timeout: int = 10) -> int:
    stdout, _, code = run(
        ["tshark", "-r", capfile, "-n", "-Y", filt, "-T", "fields", "-e", "frame.number"],
        timeout=timeout,
    )
    if code != 0 or not stdout:
        return 0
    return sum(1 for line in stdout.splitlines() if line.strip())


def analyze_cap_health(
    capfile: str,
    bssid: str,
    *,
    min_interval: float = 1.5,
) -> CaptureHealth:
    """Return cumulative frame counts for the target AP in *capfile*."""
    empty = CaptureHealth()
    if not which("tshark") or not capfile or not os.path.exists(capfile):
        return empty
    size = os.path.getsize(capfile)
    if size < 24:
        return empty

    key = f"{capfile}:{bssid.lower()}"
    now = time.time()
    prev = _last_poll.get(key)
    if prev and min_interval > 0:
        prev_size, prev_time, prev_health = prev
        if size == prev_size and now - prev_time < min_interval:
            return prev_health

    ap = bssid.lower()
    eapol_filt = f"(wlan.bssid == {ap}) and eapol"
    deauth_filt = f"(wlan.bssid == {ap}) and wlan.fc.type_subtype == 0x0c"
    auth_filt = f"(wlan.bssid == {ap}) and wlan.fc.type_subtype == 0x0b"
    assoc_filt = (
        f"(wlan.bssid == {ap}) and "
        "(wlan.fc.type_subtype == 0x00 or wlan.fc.type_subtype == 0x02)"
    )

    eapol = _count_frames(capfile, eapol_filt)
    deauth = _count_frames(capfile, deauth_filt)
    auth = _count_frames(capfile, auth_filt)
    assoc = _count_frames(capfile, assoc_filt)
    reconnect = eapol > 0 or auth > 0 or assoc > 0

    health = CaptureHealth(
        eapol=eapol,
        deauth=deauth,
        auth=auth,
        assoc=assoc,
        reconnect=reconnect,
    )
    _last_poll[key] = (size, now, health)
    return health


def reset_health_cache() -> None:
    _last_poll.clear()