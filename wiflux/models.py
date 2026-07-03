"""Data models for access points, clients, and attack results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


class WPSState(IntEnum):
    NONE = 0
    UNLOCKED = 1
    LOCKED = 2
    UNKNOWN = 3


class EncryptionType(IntEnum):
    WEP = 0
    WPA = 1
    WPA2 = 2
    WPA3 = 3
    OWE = 4
    OPEN = 5
    UNKNOWN = 6


@dataclass
class Client:
    station: str
    power: int = 0
    packets: int = 0


@dataclass
class AccessPoint:
    bssid: str
    channel: int
    encryption: EncryptionType
    auth: str
    power: int
    essid: Optional[str] = None
    essid_known: bool = True
    wps: WPSState = WPSState.UNKNOWN
    beacons: int = 0
    ivs: int = 0
    clients: list[Client] = field(default_factory=list)
    decloaked: bool = False
    manufacturer: str = ""

    @property
    def display_name(self) -> str:
        if self.essid_known and self.essid:
            return self.essid
        return f"({self.bssid})"

    @property
    def is_enterprise(self) -> bool:
        return "MGT" in self.auth.upper()

    @property
    def is_wpa3_sae(self) -> bool:
        return self.encryption == EncryptionType.WPA3 or "SAE" in self.auth.upper()

    @property
    def encryption_label(self) -> str:
        labels = {
            EncryptionType.WEP: "WEP",
            EncryptionType.WPA: "WPA",
            EncryptionType.WPA2: "WPA2",
            EncryptionType.WPA3: "WPA3",
            EncryptionType.OWE: "OWE",
            EncryptionType.OPEN: "OPN",
            EncryptionType.UNKNOWN: "???",
        }
        label = labels.get(self.encryption, "???")
        if self.encryption in (EncryptionType.WPA, EncryptionType.WPA2) and "PSK" in self.auth:
            label += "-P"
        elif self.is_wpa3_sae:
            label += "-S"
        elif self.is_enterprise:
            label += "-E"
        return label

    def score(self) -> float:
        """Higher = more promising attack target (used for display/selection order)."""
        s = float(self.power)
        s += len(self.clients) * 15
        if self.wps == WPSState.UNLOCKED:
            s += 40
        if self.essid_known:
            s += 10
        if self.encryption == EncryptionType.WEP:
            s += 50
        if self.is_enterprise:
            s -= 1000
        if self.encryption == EncryptionType.OPEN:
            s -= 500
        return s


def rank_targets(targets: list[AccessPoint]) -> list[AccessPoint]:
    """Return targets sorted by score (highest first). Use for display AND selection."""
    return sorted(targets, key=lambda t: t.score(), reverse=True)


@dataclass
class CrackResult:
    bssid: str
    essid: str
    key: str
    method: str
    capture_file: str = ""
    cracked_at: str = ""