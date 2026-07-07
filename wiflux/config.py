"""Configuration management with dataclasses instead of global singletons."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


DEFAULT_WORDLISTS = [
    "/usr/share/wordlists/rockyou.txt",
    "/usr/share/wordlists/fern-wifi/common.txt",
    "/usr/share/dict/wordlist-probable.txt",
    "/usr/share/john/password.lst",
]


def find_wordlist(custom: Optional[str] = None) -> Optional[str]:
    if custom and os.path.isfile(custom):
        return custom
    for path in DEFAULT_WORDLISTS:
        if os.path.isfile(path):
            return path
    return None


@dataclass
class ScanConfig:
    interface: Optional[str] = None
    channels: Optional[str] = None
    band_2ghz: bool = True
    band_5ghz: bool = False
    band_6ghz: bool = False
    scan_time: int = 0
    min_power: int = 0
    clients_only: bool = False
    target_bssid: Optional[str] = None
    target_essid: Optional[str] = None
    ignore_essids: list[str] = field(default_factory=list)
    decloak: bool = True  # deauth hidden APs during scan to reveal ESSIDs
    filter_wep: bool = False
    filter_wpa: bool = False
    filter_wpa3: bool = False
    filter_owe: bool = False
    filter_wps: bool = False
    ignore_cracked: bool = True


@dataclass
class AttackConfig:
    wps: bool = True
    wps_pixie_only: bool = False
    wps_no_pixie: bool = False
    wps_pin: bool = True
    wps_ignore_locks: bool = False
    pmkid: bool = True
    pmkid_only: bool = False
    handshake: bool = True
    wep: bool = True
    new_handshake: bool = False
    wep_timeout: int = 600
    wep_crack_ivs: int = 10000
    no_deauth: bool = False
    num_deauths: int = 8
    wpa_timeout: int = 300
    pmkid_timeout: int = 120
    wps_timeout: int = 300
    deauth_burst: int = 5    # baseline deauth packets per burst (adaptive engine tunes from here)
    deauth_listen: int = 8   # baseline RX window (seconds); adaptive engine scales per round
    adaptive_deauth: bool = True  # tune deauth cadence from live capture-health feedback
    deauth_tools: list[str] = field(
        default_factory=lambda: ["mdk4", "aireplay", "bettercap", "mdk3"],
    )
    deauth_rotate: bool = True   # rotate backend each round when not combo mode
    deauth_combo: bool = False   # run every available backend each round
    skip_crack: bool = False
    wordlist: Optional[str] = None
    use_bully: bool = False
    attack_max: int = 0
    parallel_pmkid: bool = False  # deprecated: same interface can't run hcxdump+airodump
    capture_health: Optional[bool] = None  # None = prompt in interactive mode
    smart_wordlist: Optional[bool] = None  # None = prompt before crack
    yes_capture_health: bool = False
    yes_smart_wordlist: bool = False
    smart_wordlist_size: int = 0  # 0 = prompt; otherwise fixed count (max 100000)
    transition_downgrade: bool = True  # WPA2/WPA3 mixed APs: prefer WPA2 capture + crack
    algorithmic_wps: bool = True
    offline_pixie: bool = True
    pmkid_passive_ratio: float = 0.45
    pmkid_band_rotate: bool = True
    client_band_stalk: bool = True
    crack_ladder: bool = True


@dataclass
class OutputConfig:
    data_dir: str = "wiflux-data"
    handshake_dir: str = "hs"
    json_output: bool = False
    verbose: int = 0
    quiet: bool = False


@dataclass
class WifluxConfig:
    scan: ScanConfig = field(default_factory=ScanConfig)
    attack: AttackConfig = field(default_factory=AttackConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    auto_mode: bool = False
    kill_conflicting: bool = False
    random_mac: bool = False
    restore_managed: bool = False
    infinite: bool = False

    def __post_init__(self):
        if self.attack.wordlist is None:
            self.attack.wordlist = find_wordlist()
        self.output.data_dir = str(Path(self.output.data_dir).resolve())
        self.output.handshake_dir = str(Path(self.output.handshake_dir).resolve())
        Path(self.output.data_dir).mkdir(parents=True, exist_ok=True)
        Path(self.output.handshake_dir).mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_file(cls, path: str) -> WifluxConfig:
        with open(path) as f:
            data = json.load(f)
        cfg = cls()
        for section, values in data.items():
            if hasattr(cfg, section) and isinstance(values, dict):
                section_obj = getattr(cfg, section)
                for k, v in values.items():
                    if hasattr(section_obj, k):
                        setattr(section_obj, k, v)
        return cfg

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)