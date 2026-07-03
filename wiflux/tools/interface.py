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


def recover_interface(interface: str, channel: int | None = None) -> str:
    """Reset monitor mode after hcxdumptool or other tools that reconfigure the radio.

    Returns the active monitor interface name (may differ from the input after hcxdumptool).
    """
    # hcxdumptool must be dead before airodump-ng can use the same radio
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

    # hcxdumptool can leave the iface managed — re-enter monitor via airmon-ng if needed
    if not Airmon.is_monitor(iface):
        try:
            iface = Airmon.start(iface, kill_conflicts=False)
        except RuntimeError:
            pass

    iface = find_monitor_interface(iface) or iface

    if channel and channel > 0:
        run(["iw", "dev", iface, "set", "channel", str(channel)], timeout=5)

    time.sleep(0.3)
    return iface