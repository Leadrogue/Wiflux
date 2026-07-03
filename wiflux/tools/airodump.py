"""Airodump-ng wrapper with CSV parsing."""

from __future__ import annotations

import csv
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Optional

from ..config import WifluxConfig
from ..models import AccessPoint, Client, EncryptionType, WPSState
from ..process import ManagedProcess
from .wash import Wash

WPS_MIN_CAP_BYTES = 4096
WPS_SCAN_INTERVAL = 5  # re-parse cap every N seconds as it grows
_BSSID_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


class Airodump:
    def __init__(
        self,
        cfg: WifluxConfig,
        *,
        channel: Optional[int] = None,
        bssid: Optional[str] = None,
        prefix: str = "wiflux",
        wps_cache: Optional[dict[str, WPSState]] = None,
    ):
        self.cfg = cfg
        self.interface = cfg.scan.interface
        self.channel = channel or (int(cfg.scan.channels.split(",")[0]) if cfg.scan.channels and "," not in cfg.scan.channels and "-" not in cfg.scan.channels else None)
        self.bssid = bssid
        self.prefix = prefix
        self.temp_dir = tempfile.mkdtemp(prefix="wiflux_")
        self.csv_prefix = os.path.join(self.temp_dir, prefix)
        self.proc: Optional[ManagedProcess] = None
        self._wps_cap_size: int = 0
        self._wps_last_run: float = 0.0
        self._wps_cache: dict[str, WPSState] = dict(wps_cache or {})

    def _build_cmd(self) -> list[str]:
        cmd = [
            "airodump-ng", self.interface,
            "--background", "1",
            "-a",
            "-w", self.csv_prefix,
            "--write-interval", "1",
            "--output-format", "pcap,csv",
        ]
        if self.channel:
            cmd.extend(["-c", str(self.channel)])
        elif self.cfg.scan.band_5ghz and self.cfg.scan.band_2ghz:
            cmd.extend(["--band", "abg"])
        elif self.cfg.scan.band_5ghz:
            cmd.extend(["--band", "a"])
        if self.bssid:
            cmd.extend(["--bssid", self.bssid])
        return cmd

    def start(self) -> None:
        self._cleanup_files()
        self.proc = ManagedProcess(self._build_cmd())

    def stop(self) -> None:
        if self.proc:
            self.proc.kill()
            self.proc = None
        self._cleanup_files()

    def _cleanup_files(self) -> None:
        for f in Path(self.temp_dir).glob(f"{self.prefix}*"):
            try:
                f.unlink()
            except OSError:
                pass

    def alive(self) -> bool:
        return self.proc is not None and self.proc.running()

    def get_cap_file(self) -> Optional[str]:
        caps = list(Path(self.temp_dir).glob(f"{self.prefix}*.cap"))
        if not caps:
            return None
        return str(max(caps, key=lambda p: p.stat().st_size))

    def parse_targets(self, old: Optional[list[AccessPoint]] = None) -> list[AccessPoint]:
        csv_files = list(Path(self.temp_dir).glob(f"{self.prefix}*.csv"))
        if not csv_files:
            return old or []
        csv_path = max(csv_files, key=lambda p: p.stat().st_mtime)
        try:
            aps, clients_map = self._parse_csv(csv_path)
        except Exception:
            return old or []

        # WPS from wash -f on growing cap; cache results as more beacons are captured
        if not self.bssid:
            capfile = self.get_cap_file()
            if capfile:
                cap_size = os.path.getsize(capfile)
                now = time.time()
                should_scan = (
                    cap_size >= WPS_MIN_CAP_BYTES
                    and (
                        cap_size != self._wps_cap_size
                        or now - self._wps_last_run >= WPS_SCAN_INTERVAL
                    )
                )
                if should_scan:
                    states = Wash.scan_cap(capfile)
                    if states:
                        self._wps_cache.update(states)
                    self._wps_cap_size = cap_size
                    self._wps_last_run = now
                Wash.apply_states(aps, self._wps_cache)

        # Attach clients
        for ap in aps:
            ap.clients = clients_map.get(ap.bssid, [])

        # Merge state from previous scan pass
        if old:
            old_map = {a.bssid: a for a in old}
            for ap in aps:
                if ap.bssid not in old_map:
                    continue
                prev = old_map[ap.bssid]
                if ap.essid_known and not prev.essid_known:
                    # Hidden → revealed: decloak success
                    ap.decloaked = True
                elif prev.essid_known and not ap.essid_known:
                    # AP briefly hidden again — keep known name
                    ap.essid = prev.essid
                    ap.essid_known = True
                    ap.decloaked = prev.decloaked
                elif prev.decloaked and prev.essid_known:
                    ap.essid = ap.essid or prev.essid
                    ap.essid_known = True
                    ap.decloaked = True
                # Keep WPS once seen — partial cap parses must not flip yes/lock → no
                if ap.wps == WPSState.NONE and prev.wps in (WPSState.UNLOCKED, WPSState.LOCKED):
                    ap.wps = prev.wps
                elif ap.wps == WPSState.UNKNOWN and prev.wps != WPSState.UNKNOWN:
                    ap.wps = prev.wps

        return aps

    def _parse_csv(self, path: Path) -> tuple[list[AccessPoint], dict[str, list[Client]]]:
        aps: list[AccessPoint] = []
        clients_map: dict[str, list[Client]] = {}
        section = None

        with open(path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or not row[0].strip():
                    continue
                header = row[0].strip()
                if header == "BSSID":
                    section = "ap"
                    continue
                if "Station MAC" in header:
                    section = "client"
                    continue
                if section == "ap":
                    ap = self._parse_ap_row(row)
                    if ap:
                        aps.append(ap)
                elif section == "client":
                    self._parse_client_row(row, clients_map)
        return aps, clients_map

    def _parse_ap_row(self, fields: list[str]) -> Optional[AccessPoint]:
        if len(fields) < 14:
            return None
        bssid = fields[0].strip().upper()
        if not _BSSID_RE.match(bssid):
            return None
        if re.match(r"^(FF:FF:FF:FF:FF:FF|00:00:00:00:00:00)$", bssid):
            return None
        if re.match(r"^(01:00:5E|01:80:C2|33:33)", bssid):
            return None

        channel = int(fields[3].strip()) if fields[3].strip().lstrip("-").isdigit() else 0
        privacy = fields[5].strip()
        auth = fields[7].strip()
        power = int(fields[8].strip())
        if power < 0:
            power += 100

        enc = self._parse_encryption(privacy)
        essid_len = int(fields[12].strip()) if fields[12].strip().isdigit() else 0
        essid = self._sanitize_essid(fields[13].strip() if len(fields) > 13 else "")
        essid_known = bool(essid and essid != "\\x00" * essid_len)

        return AccessPoint(
            bssid=bssid, channel=channel, encryption=enc, auth=auth,
            power=power, essid=essid if essid_known else None,
            essid_known=essid_known,
            beacons=int(fields[9].strip()) if fields[9].strip().isdigit() else 0,
            ivs=int(fields[10].strip()) if fields[10].strip().isdigit() else 0,
        )

    @staticmethod
    def _sanitize_essid(essid: str) -> str:
        if not essid:
            return ""
        # Collapse whitespace; drop non-printables from corrupted CSV rows
        cleaned = "".join(c for c in essid if c.isprintable() and c not in "\r\n\t")
        return " ".join(cleaned.split())

    @staticmethod
    def _parse_encryption(privacy: str) -> EncryptionType:
        p = privacy.upper()
        if "WPA3" in p:
            return EncryptionType.WPA3
        if "WPA2" in p:
            return EncryptionType.WPA2
        if "WPA" in p:
            return EncryptionType.WPA
        if "WEP" in p:
            return EncryptionType.WEP
        if "OWE" in p:
            return EncryptionType.OWE
        if not p or p == "OPN":
            return EncryptionType.OPEN
        return EncryptionType.UNKNOWN

    @staticmethod
    def _parse_client_row(fields: list[str], clients_map: dict[str, list[Client]]) -> None:
        if len(fields) < 6:
            return
        station = fields[0].strip()
        bssid = fields[5].strip() if len(fields) > 5 else ""
        if not bssid or bssid == "(not associated)":
            return
        power = int(fields[3].strip()) if fields[3].strip().lstrip("-").isdigit() else 0
        client = Client(station=station, power=power)
        clients_map.setdefault(bssid, []).append(client)

    def __enter__(self) -> Airodump:
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception:
            pass