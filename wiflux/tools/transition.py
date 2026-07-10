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


def hash_frame_type(hash_line: str) -> str:
    """Return ``pmkid``, ``eapol``, or ``unknown`` from a hc22000 hash line.

    In hashcat 22000 format, field 2 is the message/frame type:
    ``01`` = PMKID, ``02`` = EAPOL — not WPA2 vs WPA3.
    """
    parts = (hash_line or "").strip().split("*")
    if len(parts) < 2:
        return "unknown"
    key = parts[1]
    if key == "01":
        return "pmkid"
    if key == "02":
        return "eapol"
    return "unknown"


def hash_key_type(hash_line: str) -> str:
    """Backward-compatible alias.

    Historically (and incorrectly) returned wpa2/wpa3. Now returns
    ``eapol`` / ``pmkid`` / ``unknown``. Prefer :func:`hash_frame_type`.
    """
    return hash_frame_type(hash_line)


def select_hash_line(
    pairs: list[tuple[str, str]],
    *,
    prefer_bssids: list[str] | None = None,
    prefer_wpa2: bool = False,
    allow_wpa3_fallback: bool = True,
) -> tuple[str, str] | None:
    """Pick the best (bssid, hash_line) from hcxpcapngtool output.

    When *prefer_wpa2* is True (transition downgrade path), prefer **EAPOL**
    (4-way) over **PMKID**. Otherwise prefer PMKID (clientless, faster).
    Both use hashcat mode 22000 for password cracking.
    """
    if not pairs:
        return None

    prefer = {b.replace(":", "").lower() for b in (prefer_bssids or []) if b}

    def rank(entry: tuple[str, str]) -> tuple[int, int, str]:
        bssid, line = entry
        bssid_key = bssid.replace(":", "").lower()
        preferred = 0 if not prefer or bssid_key in prefer else 1
        frame = hash_frame_type(line)
        if prefer_wpa2:
            # Prefer full 4-way (EAPOL) for transition "WPA2 path"
            type_rank = 0 if frame == "eapol" else (1 if frame == "pmkid" else 2)
        else:
            type_rank = 0 if frame == "pmkid" else (1 if frame == "eapol" else 2)
        return (preferred, type_rank, bssid)

    ordered = sorted(pairs, key=rank)
    if prefer_wpa2 and not allow_wpa3_fallback:
        for bssid, line in ordered:
            if hash_frame_type(line) == "eapol":
                return bssid, line
        return None

    return ordered[0]


def strategy_summary(ap: AccessPoint) -> str:
    if not ap.transition_mode:
        return ""
    return (
        "WPA2/WPA3 transition mode — preferring EAPOL (4-way) when available, "
        "hashcat mode 22000 (password / PBKDF2)"
    )


def bssid_from_hash_line(hash_line: str) -> str:
    """Extract colon-formatted AP BSSID from a WPA* hashcat line, or ''."""
    parts = (hash_line or "").strip().split("*")
    if len(parts) < 4:
        return ""
    raw = parts[3].replace(":", "").strip()
    if len(raw) != 12:
        return ""
    try:
        int(raw, 16)
    except ValueError:
        return ""
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2)).upper()
