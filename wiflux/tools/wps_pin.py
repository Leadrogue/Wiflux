"""Algorithmic WPS PIN candidates derived from BSSID and vendor OUI."""

from __future__ import annotations

import re


def wps_pin_checksum(pin7: int) -> int:
    """WPS PIN checksum digit for a 7-digit base."""
    accum = 0
    while pin7 > 0:
        accum += 3 * (pin7 % 10)
        pin7 //= 10
        accum += pin7 % 10
        pin7 //= 10
    return (10 - accum % 10) % 10


def format_wps_pin(pin7: int) -> str:
    pin7 = int(pin7) % 10_000_000
    return f"{pin7:07d}{wps_pin_checksum(pin7)}"


def algorithmic_wps_pins(bssid: str, manufacturer: str = "") -> list[str]:
    """Return ordered unique 8-digit WPS PIN candidates for *bssid*."""
    mac = re.sub(r"[^0-9A-Fa-f]", "", bssid).upper()
    pins: list[str] = []
    seen: set[str] = set()

    def add_raw(pin: str) -> None:
        pin = pin.strip()
        if len(pin) == 8 and pin.isdigit() and pin not in seen:
            seen.add(pin)
            pins.append(pin)

    def add_pin7(pin7: int) -> None:
        add_raw(format_wps_pin(pin7))

    if len(mac) == 12:
        last24 = int(mac[-6:], 16)
        first24 = int(mac[:6], 16)
        mid24 = int(mac[3:9], 16)
        full48 = int(mac, 16)

        add_pin7(last24 % 10_000_000)
        add_pin7((last24 >> 8) % 10_000_000)
        add_pin7(full48 % 10_000_000)
        add_pin7(first24 % 10_000_000)
        add_pin7(mid24 % 10_000_000)
        add_pin7((last24 ^ first24) % 10_000_000)

    for weak in (
        "12345670", "01234567", "00000000", "11111111", "22222222",
        "12345678", "87654321", "20131234", "12341234",
    ):
        add_raw(weak)

    mfr = (manufacturer or "").lower()
    if any(x in mfr for x in ("d-link", "dlink", "d link")):
        if len(mac) == 12:
            add_pin7(int(mac[-6:], 16) % 10_000_000)
    if "asus" in mfr and len(mac) == 12:
        add_pin7(int(mac[-4:], 16) % 10_000_000)
        add_pin7(int(mac[-6:], 16) % 10_000_000)
    if "netgear" in mfr and len(mac) == 12:
        add_pin7(int(mac[-6:], 16) % 10_000_000)
    if any(x in mfr for x in ("tp-link", "tplink", "mercury")) and len(mac) == 12:
        add_pin7(int(mac[-6:], 16) % 10_000_000)

    return pins[:24]