"""Multi-band AP discovery for PMKID rotation and client band-stalk."""

from __future__ import annotations

import re

from ..models import AccessPoint


def _essid_root(essid: str | None) -> str:
    if not essid:
        return ""
    root = re.sub(r"(?i)(5\s*ghz|2\.?4\s*ghz|24\s*ghz|5g|2g|6\s*ghz|6g)", "", essid)
    return re.sub(r"[^a-z0-9]", "", root.lower())


def band_sibling_aps(
    ap: AccessPoint,
    pool: list[AccessPoint],
    *,
    include_self: bool = False,
) -> list[AccessPoint]:
    """Return same-ESSID APs on other bands (shared PSK candidates)."""
    root = _essid_root(ap.essid)
    if not root:
        return []
    out: list[AccessPoint] = []
    seen: set[str] = set()
    for candidate in pool:
        if candidate.bssid in seen:
            continue
        if not include_self and candidate.bssid == ap.bssid:
            continue
        other = _essid_root(candidate.essid)
        if not other:
            continue
        if root not in other and other not in root:
            continue
        if candidate.radio_band == ap.radio_band and candidate.bssid != ap.bssid:
            continue
        if candidate.bssid == ap.bssid and not include_self:
            continue
        seen.add(candidate.bssid)
        out.append(candidate)
    out.sort(key=lambda t: (t.radio_band != ap.radio_band, -t.power))
    return out