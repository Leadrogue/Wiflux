"""Wireless interface recovery between tool switches."""

from __future__ import annotations

import time

from ..process import ProcessPool, run
from .airmon import Airmon


def find_monitor_interface(preferred: str) -> str | None:
    """Return a usable monitor interface, preferring the configured name."""
    if preferred and Airmon.is_monitor(preferred):
        return preferred
    monitors = [i["name"] for i in Airmon.list_interfaces() if i["type"] == "monitor"]
    if not monitors:
        return None
    if preferred:
        for name in monitors:
            if name == preferred or name.startswith(preferred) or preferred.startswith(name):
                return name
    return monitors[0]


def set_channel(iface: str, channel: int, band: str | None = None) -> str:
    """Tune the radio to a channel; use wide width on 5 GHz for VHT APs."""
    from .radio import infer_band, set_channel_cmd

    if channel <= 0:
        return "20MHz"
    resolved = band or infer_band(channel)
    for args in set_channel_cmd(iface, channel, resolved):
        _, _, code = run(args, timeout=5)
        if code == 0:
            if resolved == "6":
                return "6GHz"
            if resolved == "5":
                return args[-1] if args[-1] in ("80MHz", "40MHz", "20MHz") else "20MHz"
            return "20MHz"
    return "20MHz"


def recover_interface(
    interface: str,
    channel: int | None = None,
    band: str | None = None,
) -> str:
    """Reset monitor mode after hcxdumptool or other tools that reconfigure the radio.

    Returns the active monitor interface name (may differ from the input after hcxdumptool).
    """
    ProcessPool().cleanup_all()
    time.sleep(0.4)

    iface = find_monitor_interface(interface) or interface

    run(["ip", "link", "set", iface, "down"], timeout=5)
    time.sleep(0.2)
    run(["ip", "link", "set", iface, "up"], timeout=5)
    time.sleep(0.2)

    if not Airmon.is_monitor(iface):
        run(["iw", "dev", iface, "set", "type", "monitor"], timeout=5)
        time.sleep(0.2)

    if not Airmon.is_monitor(iface):
        try:
            iface = Airmon.start(iface, kill_conflicts=False)
        except RuntimeError:
            pass

    iface = find_monitor_interface(iface) or iface

    if channel and channel > 0:
        set_channel(iface, channel, band=band)

    time.sleep(0.3)
    return iface