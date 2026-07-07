"""WPA2/WPA3 transition (mixed) mode detection and downgrade strategy."""

from __future__ import annotations

from ..models import AccessPoint


def detect_transition_mode(privacy: str, auth: str = "") -> bool:
    """True when the AP advertises both WPA2 and WPA3 (transition / mixed mode)."""
    p = (privacy or "").upper()
    a = (auth or "").upper()
    if "WPA2" in p and "WPA3" in p:
        return True
    if "SAE" in a and "PSK" in a:
        return True
    return False


def transition_downgrade_enabled(cfg, ap: AccessPoint) -> bool:
    return bool(cfg.attack.transition_downgrade and ap.transition_mode)


def hash_key_type(hash_line: str) -> str:
    """Return ``wpa2``, ``wpa3``, or ``unknown`` from a hashcat 22000/22001 line."""
    parts = (hash_line or "").strip().split("*")
    if len(parts) < 2:
        return "unknown"
    key = parts[1]
    if key == "02":
        return "wpa2"
    if key == "01":
        return "wpa3"
    return "unknown"


def select_hash_line(
    pairs: list[tuple[str, str]],
    *,
    prefer_bssids: list[str] | None = None,
    prefer_wpa2: bool = False,
    allow_wpa3_fallback: bool = True,
) -> tuple[str, str] | None:
    """Pick the best (bssid, hash_line) from hcxpcapngtool output."""
    if not pairs:
        return None

    prefer = {b.replace(":", "").lower() for b in (prefer_bssids or []) if b}

    def rank(entry: tuple[str, str]) -> tuple[int, int, str]:
        bssid, line = entry
        bssid_key = bssid.replace(":", "").lower()
        preferred = 0 if not prefer or bssid_key in prefer else 1
        key_type = hash_key_type(line)
        if prefer_wpa2:
            type_rank = 0 if key_type == "wpa2" else (1 if key_type == "wpa3" else 2)
        else:
            type_rank = 0 if key_type == "wpa3" else (1 if key_type == "wpa2" else 2)
        return (preferred, type_rank, bssid)

    ordered = sorted(pairs, key=rank)
    if prefer_wpa2 and not allow_wpa3_fallback:
        for bssid, line in ordered:
            if hash_key_type(line) == "wpa2":
                return bssid, line
        return None

    return ordered[0]


def strategy_summary(ap: AccessPoint) -> str:
    if not ap.transition_mode:
        return ""
    return (
        "WPA2/WPA3 transition mode — preferring WPA2 handshake/PMKID and "
        "hashcat mode 22000 (PSK downgrade path)"
    )