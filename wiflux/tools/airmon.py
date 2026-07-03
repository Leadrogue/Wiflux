"""Monitor mode interface management."""

from __future__ import annotations

import re
from typing import Optional

from ..process import run, which


class Airmon:
    base_interface: Optional[str] = None

    @staticmethod
    def list_interfaces() -> list[dict]:
        stdout, _, _ = run(["iw", "dev"])
        interfaces = []
        current: dict = {}
        for line in stdout.splitlines():
            if m := re.match(r"^\s*Interface\s+(\S+)", line):
                if current:
                    interfaces.append(current)
                current = {"name": m.group(1), "type": "unknown", "phy": ""}
            elif m := re.match(r"^\s*type\s+(\S+)", line):
                if current:
                    current["type"] = m.group(1)
            elif m := re.match(r"^\s*wiphy\s+(\d+)", line):
                if current:
                    current["phy"] = m.group(1)
        if current:
            interfaces.append(current)
        return interfaces

    @staticmethod
    def get_wireless_interfaces() -> list[str]:
        return [i["name"] for i in Airmon.list_interfaces() if i["type"] in ("managed", "monitor")]

    @staticmethod
    def is_monitor(interface: str) -> bool:
        for iface in Airmon.list_interfaces():
            if iface["name"] == interface:
                return iface["type"] == "monitor"
        return False

    @staticmethod
    def _parse_airmon_start(output: str) -> Optional[str]:
        """Extract monitor interface name from airmon-ng start output."""
        enabled_on_re = re.compile(
            r".*\(mac80211 monitor mode (?:(?:vif )?enabled|already enabled)"
            r"(?: for [^ ]+)? on (?:\[\w+])?([a-zA-Z][\w-]*(?:mon)?)\)?.*"
        )
        enabled_for_re = re.compile(
            r".*\(mac80211 monitor mode (?:(?:vif )?enabled|already enabled)"
            r" for (?:\[\w+])?([a-zA-Z][\w-]*).*on (?:\[\w+])?\d+\)?.*"
        )

        for line in output.splitlines():
            if "mac80211 monitor mode" not in line:
                if m := re.search(r"monitor mode enabled on (\S+)", line, re.I):
                    return m.group(1).rstrip(")")
                continue

            if m := enabled_on_re.match(line):
                name = m.group(1)
                if not name.isdigit():
                    return name

            if m := enabled_for_re.match(line):
                return m.group(1)

            if m := re.search(r"\[phy\d+\](\S+)\s+\(monitor mode enabled\)", line):
                return m.group(1)

        return None

    @classmethod
    def start(cls, interface: str, *, kill_conflicts: bool = False) -> str:
        # Already in monitor mode
        if Airmon.is_monitor(interface):
            cls.base_interface = interface
            return interface

        # Interface might already have a mon counterpart (e.g. wlan0 → wlan0mon)
        mon_candidate = f"{interface}mon"
        if Airmon.is_monitor(mon_candidate):
            cls.base_interface = interface
            return mon_candidate

        if kill_conflicts and which("airmon-ng"):
            run(["airmon-ng", "check", "kill"])

        stdout, stderr, _ = run(["airmon-ng", "start", interface])
        output = stdout + stderr

        enabled = cls._parse_airmon_start(output)
        if enabled:
            cls.base_interface = interface
            return enabled

        # Fallback: find any new monitor interface related to the base name
        for iface in Airmon.get_wireless_interfaces():
            if iface == interface and Airmon.is_monitor(iface):
                cls.base_interface = interface
                return iface
            if iface.startswith(interface) and Airmon.is_monitor(iface):
                cls.base_interface = interface
                return iface

        raise RuntimeError(f"Failed to enable monitor mode on {interface}:\n{output}")

    @classmethod
    def stop(cls, mon_interface: str) -> None:
        if which("airmon-ng"):
            run(["airmon-ng", "stop", mon_interface])
        if cls.base_interface:
            run(["ip", "link", "set", cls.base_interface, "up"])

    @staticmethod
    def ask() -> str:
        interfaces = Airmon.get_wireless_interfaces()
        if not interfaces:
            raise RuntimeError("No wireless interfaces found")

        # Prefer monitor interfaces if available
        monitor = [i for i in interfaces if Airmon.is_monitor(i)]
        if len(monitor) == 1:
            return monitor[0]
        if len(interfaces) == 1:
            return interfaces[0]

        print("\nAvailable interfaces:")
        for i, iface in enumerate(interfaces, 1):
            mode = "monitor" if Airmon.is_monitor(iface) else "managed"
            print(f"  {i}) {iface} ({mode})")
        while True:
            try:
                choice = input(f"Select interface [1-{len(interfaces)}]: ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    return interfaces[idx]
            except (ValueError, KeyboardInterrupt):
                pass
            print("Invalid selection.")