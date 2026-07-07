"""Reliable WPA handshake detection — hcxpcapngtool is authoritative for airodump caps."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import time

from dataclasses import dataclass

from ..process import run, which

_MAC = r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
_EAPOL_RE = re.compile(
    rf"({_MAC})\s*.*\s*({_MAC}).*Message\s*(\d)\s*of\s*(\d)",
    re.IGNORECASE,
)

# Rate-limit expensive hcxpcapngtool runs during live capture.
_last_check: dict[str, tuple[int, float, bool]] = {}


def _stable_copy(capfile: str) -> str | None:
    try:
        fd, path = tempfile.mkstemp(suffix=".cap", prefix="wiflux_hs_")
        os.close(fd)
        shutil.copy2(capfile, path)
        return path
    except OSError:
        return None


def _bssid_norm(bssid: str) -> str:
    return bssid.replace(":", "").lower()


def _bssid_display(bssid: str) -> str:
    raw = _bssid_norm(bssid)
    if len(raw) != 12:
        return bssid.upper()
    return ":".join(raw[i:i + 2] for i in range(0, 12, 2)).upper()


def tshark_has_handshake(capfile: str, bssid: str) -> bool:
    if not which("tshark"):
        return False
    stdout, _, code = run(
        ["tshark", "-r", capfile, "-n", "-Y", "eapol"],
        timeout=15,
    )
    if code != 0 or not stdout:
        return False

    bssid_low = bssid.lower()
    progress: dict[str, int] = {}

    for line in stdout.splitlines():
        match = _EAPOL_RE.search(line)
        if not match:
            continue
        src, dst, index_s, total_s = match.groups()
        if int(total_s) != 4:
            continue
        index = int(index_s)
        if index % 2 == 1:
            ap, client = src.lower(), dst.lower()
        else:
            client, ap = src.lower(), dst.lower()
        if ap != bssid_low:
            continue
        key = f"{ap},{client}"
        if index == 1:
            progress[key] = 1
        elif key in progress and index - 1 == progress[key]:
            progress[key] = index

    return any(step == 4 for step in progress.values())


def aircrack_has_handshake(capfile: str, bssid: str) -> bool:
    if not which("aircrack-ng"):
        return False
    stdout, _, _ = run(["aircrack-ng", "-b", bssid, capfile], timeout=8)
    low = stdout.lower()
    if "no matching network" in low:
        return False
    return "1 handshake" in low or "wpa (1 handshake)" in low


def extract_hash(
    capfile: str,
    bssid: str,
    *,
    prefer_wpa2: bool = False,
    allow_wpa3_fallback: bool = True,
) -> str | None:
    """Return a hashcat 22000/22001 line for *bssid* in *capfile*."""
    from .transition import select_hash_line

    pairs = [
        (mac, line)
        for mac, line in list_hash_bssids(capfile)
        if _bssid_norm(mac) == _bssid_norm(bssid)
    ]
    picked = select_hash_line(
        pairs,
        prefer_wpa2=prefer_wpa2,
        allow_wpa3_fallback=allow_wpa3_fallback,
    )
    return picked[1] if picked else None


def check_handshake(
    capfile: str,
    bssid: str,
    essid: str | None = None,
    *,
    min_interval: float = 0.0,
) -> bool:
    """True when hcxpcapngtool can extract a crackable hash for this BSSID.

    airodump-ng caps often fail tshark/aircrack but still convert via hcxpcapngtool.
    """
    if not capfile or not os.path.exists(capfile) or os.path.getsize(capfile) < 24:
        return False

    key = f"{capfile}:{_bssid_norm(bssid)}"
    size = os.path.getsize(capfile)
    now = time.time()
    prev = _last_check.get(key)
    if prev and min_interval > 0:
        prev_size, prev_time, prev_result = prev
        if size == prev_size and now - prev_time < min_interval:
            return prev_result

    snapshot = _stable_copy(capfile)
    if not snapshot:
        return False
    try:
        result = extract_hash(snapshot, bssid) is not None
    finally:
        try:
            os.remove(snapshot)
        except OSError:
            pass

    _last_check[key] = (size, now, result)
    return result


def reset_check_cache() -> None:
    _last_check.clear()


@dataclass(frozen=True)
class HandshakeValidation:
    valid: bool
    bssid: str = ""
    hash_line: str = ""
    message: str = ""
    four_way_complete: bool = False


def validate_handshake_capture(
    capfile: str,
    prefer_bssids: list[str],
    *,
    essid: str | None = None,
    prefer_wpa2: bool = False,
) -> HandshakeValidation:
    """Full validation before cracking — always bypasses live poll cache."""
    from .transition import hash_key_type

    if not capfile or not os.path.exists(capfile) or os.path.getsize(capfile) < 24:
        return HandshakeValidation(valid=False, message="Capture file missing or too small")

    reset_check_cache()
    bssid = find_hash_bssid(
        capfile,
        prefer_bssids,
        min_interval=0,
        prefer_wpa2=prefer_wpa2,
        allow_wpa3_fallback=True,
    )
    if not bssid:
        return HandshakeValidation(
            valid=False,
            message="No crackable WPA handshake found in capture",
        )

    hash_line = extract_hash(
        capfile,
        bssid,
        prefer_wpa2=prefer_wpa2,
        allow_wpa3_fallback=True,
    )
    if not hash_line:
        return HandshakeValidation(
            valid=False,
            bssid=bssid,
            message="hcxpcapngtool could not extract a hashcat hash",
        )

    four_way = tshark_has_handshake(capfile, bssid) if which("tshark") else True
    if four_way:
        detail = "Complete 4-way handshake — ready to crack"
    else:
        detail = "Hash extractable — EAPOL 4-way incomplete but may still crack"

    key_type = hash_key_type(hash_line)
    if prefer_wpa2 and key_type == "wpa2":
        detail += " — WPA2 downgrade path"
    elif prefer_wpa2 and key_type == "wpa3":
        detail += " — WPA3/SAE only (downgrade missed)"

    if essid:
        detail += f" ({essid})"

    return HandshakeValidation(
        valid=True,
        bssid=bssid,
        hash_line=hash_line,
        message=detail,
        four_way_complete=four_way,
    )


def list_hash_bssids(capfile: str) -> list[tuple[str, str]]:
    """Return all (bssid, hash_line) pairs hcxpcapngtool can extract from *capfile*."""
    if not which("hcxpcapngtool"):
        return []
    if not capfile or not os.path.exists(capfile) or os.path.getsize(capfile) < 24:
        return []

    tmp_hash = f"{capfile}.wiflux_all.22000"
    try:
        if os.path.exists(tmp_hash):
            os.remove(tmp_hash)
        run(["hcxpcapngtool", "-o", tmp_hash, capfile], timeout=30)
        if not os.path.exists(tmp_hash) or os.path.getsize(tmp_hash) == 0:
            return []
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        with open(tmp_hash) as f:
            for line in f:
                line = line.strip()
                if not line.startswith("WPA*"):
                    continue
                parts = line.split("*")
                if len(parts) < 4:
                    continue
                bssid = _bssid_display(parts[3])
                key = _bssid_norm(bssid)
                if key in seen:
                    continue
                seen.add(key)
                out.append((bssid, line))
        return out
    except (subprocess.TimeoutExpired, OSError):
        return []
    finally:
        if os.path.exists(tmp_hash):
            os.remove(tmp_hash)


def find_hash_bssid(
    capfile: str,
    bssids: list[str],
    *,
    min_interval: float = 0.0,
    prefer_wpa2: bool = False,
    allow_wpa3_fallback: bool = True,
) -> str | None:
    """Return the first BSSID from *bssids* with a crackable handshake in *capfile*."""
    for bssid in bssids:
        if prefer_wpa2:
            if extract_hash(
                capfile,
                bssid,
                prefer_wpa2=True,
                allow_wpa3_fallback=allow_wpa3_fallback,
            ):
                return bssid
            continue
        if check_handshake(capfile, bssid, min_interval=min_interval):
            return bssid
    return None


def extract_hash_preferred(
    capfile: str,
    prefer_bssids: list[str],
    *,
    prefer_wpa2: bool = False,
) -> tuple[str, str] | None:
    """Return (bssid, hash_line), preferring *prefer_bssids* then any other in the cap."""
    from .transition import select_hash_line

    pairs = list_hash_bssids(capfile)
    return select_hash_line(
        pairs,
        prefer_bssids=prefer_bssids,
        prefer_wpa2=prefer_wpa2,
        allow_wpa3_fallback=True,
    )


def cap_has_reconnect(capfile: str, bssid: str) -> bool:
    """True when the capture shows auth/assoc activity for this AP."""
    if not which("tshark") or not capfile or not os.path.exists(capfile):
        return False
    filt = (
        f"(wlan.bssid == {bssid.lower()}) and "
        "(wlan.fc.type_subtype == 0x0b or wlan.fc.type_subtype == 0x00 or "
        "wlan.fc.type_subtype == 0x02 or eapol)"
    )
    stdout, _, code = run(
        ["tshark", "-r", capfile, "-n", "-Y", filt, "-c", "1"],
        timeout=8,
    )
    return code == 0 and bool(stdout.strip())