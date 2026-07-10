"""WPS state detection via live wash and airodump capture files."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

from ..models import WPSState
from ..process import run, which

_BSSID_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")


class Wash:
    @staticmethod
    def available() -> bool:
        return which("wash")

    @staticmethod
    def scan_live(
        interface: str,
        *,
        timeout: int = 12,
        band_2ghz: bool = True,
        band_5ghz: bool = True,
        band_6ghz: bool = False,
    ) -> dict[str, WPSState]:
        """Probe WPS on the live interface (airodump must be stopped)."""
        if not Wash.available():
            return {}

        # wash has no native 6 GHz flag; 6-only scans use -5 as best-effort
        # (dual-band APs often answer on 5 GHz) instead of skipping entirely.
        cmd = ["wash", "-i", interface, "-j", "-a"]
        if band_2ghz:
            cmd.append("-2")
        if band_5ghz or band_6ghz:
            cmd.append("-5")

        blob = Wash._run_wash(cmd, timeout)
        if not blob.strip():
            return {}
        return Wash._parse_json_blob(blob)

    @staticmethod
    def scan_cap(capfile: str) -> dict[str, WPSState]:
        """Parse WPS state from an airodump cap via wash -f -j -a."""
        if not Wash.available():
            return {}

        path = Path(capfile)
        if not path.is_file() or path.stat().st_size < 4096:
            return {}

        blob = Wash._run_wash(["wash", "-f", capfile, "-j", "-a"], timeout=45)
        if not blob.strip():
            return {}
        return Wash._parse_json_blob(blob)

    @staticmethod
    def _run_wash(cmd: list[str], timeout: int) -> str:
        """Run wash and return combined output (live probe may time out with partial data)."""
        try:
            stdout, stderr, code = run(cmd, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
        except OSError:
            return ""
        else:
            if code != 0 and not (stdout or stderr).strip():
                return ""
        return Wash._decode_output(stdout) or Wash._decode_output(stderr)

    @staticmethod
    def _decode_output(data: object) -> str:
        if not data:
            return ""
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="replace")
        return str(data)

    @staticmethod
    def _parse_json_blob(blob: str) -> dict[str, WPSState]:
        states: dict[str, WPSState] = {}
        for line in blob.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            bssid = str(obj.get("bssid", "")).upper()
            if not _BSSID_RE.match(bssid):
                continue

            state = Wash._parse_wps_state(obj)
            if state is not None:
                states[bssid] = state
        return states

    @staticmethod
    def apply_states(targets: list, states: dict[str, WPSState]) -> None:
        for ap in targets:
            key = ap.bssid.upper()
            if key in states:
                ap.wps = states[key]

    @staticmethod
    def _parse_wps_state(obj: dict) -> WPSState | None:
        """Map wash JSON fields to WPSState.

        wash -j uses wps_locked:
          0 = no WPS
          1 = WPS locked  (live wash column Lck: Yes)
          2 = WPS active  (live wash column Lck: No)
        """
        locked = obj.get("wps_locked")
        version = obj.get("wps_version") or 0
        state = obj.get("wps_state") or 0

        if locked == 1:
            return WPSState.LOCKED
        if locked == 2:
            return WPSState.UNLOCKED
        if locked == 0:
            return WPSState.NONE

        if version or state:
            if Wash._is_locked_legacy(locked):
                return WPSState.LOCKED
            return WPSState.UNLOCKED

        return WPSState.NONE

    @staticmethod
    def _is_locked_legacy(value: object) -> bool:
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        return text in {"1", "true", "yes", "locked"}