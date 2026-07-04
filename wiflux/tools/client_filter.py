"""Filter bogus / multicast stations from airodump client lists."""

from __future__ import annotations

import re

_BSSID_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")

# IEEE reserved / multicast / bridge — never real Wi-Fi clients.
_BLOCKED_PREFIXES = (
    "01:80:C2",  # STP / bridge group
    "01:00:5E",  # IPv4 multicast
    "33:33",     # IPv6 multicast
    "01:00:0C",  # Cisco multicast
    "FF:FF:FF:FF:FF:FF",
)


def is_valid_client(station: str, ap_bssid: str | None = None) -> bool:
    mac = station.strip().upper()
    if not _BSSID_RE.match(mac):
        return False
    if ap_bssid and mac == ap_bssid.strip().upper():
        return False
    if mac.startswith(_BLOCKED_PREFIXES):
        return False
    # Multicast: least-significant bit of first octet set.
    if int(mac.split(":")[0], 16) & 1:
        return False
    return True


def filter_clients(stations: list[str], ap_bssid: str | None = None) -> list[str]:
    """Return unique, valid client MACs preserving order."""
    out: list[str] = []
    for station in stations:
        mac = station.strip().upper()
        if not is_valid_client(mac, ap_bssid) or mac in out:
            continue
        out.append(mac)
    return out


def is_heard_client(mac: str, power: dict[str, int]) -> bool:
    """True when airodump reports a real signal (not stale PWR -1)."""
    return power.get(mac.strip().upper(), -1) != -1


def active_clients(
    clients: list[str],
    power: dict[str, int],
    ap_bssid: str | None = None,
    *,
    limit: int = 4,
) -> list[str]:
    """Clients heard recently (power != -1), strongest first."""
    valid = filter_clients(clients, ap_bssid)
    heard = [mac for mac in valid if is_heard_client(mac, power)]
    heard.sort(key=lambda mac: power.get(mac, -100), reverse=True)
    return heard[:limit]