"""Multi-stage hashcat crack ladder after capture."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from ..config import WifluxConfig
from ..models import AccessPoint
from .smart_wordlist import (
    COMMON_WIFI_PASSWORDS,
    _vendor_candidates,
    lookup_vendor,
)


RULE_CANDIDATES = (
    "/usr/share/hashcat/rules/best64.rule",
    "/usr/share/hashcat/rules/d3ad0ne.rule",
    "/usr/share/hashcat/rules/rockyou-30000.rule",
    "/usr/share/hashcat/rules/OneRuleToRuleThemAll.rule",
    "/usr/share/hashcat/rules/toggles1.rule",
)


def discover_hashcat_rules() -> list[str]:
    found: list[str] = []
    for path in RULE_CANDIDATES:
        if os.path.isfile(path):
            found.append(path)
    rules_dir = Path("/usr/share/hashcat/rules")
    if rules_dir.is_dir() and not found:
        for path in sorted(rules_dir.glob("*.rule"))[:3]:
            found.append(str(path))
    return found


def generate_vendor_defaults(
    ap: AccessPoint,
    cfg: WifluxConfig,
    *,
    max_candidates: int = 400,
) -> list[str]:
    vendor = ap.manufacturer or lookup_vendor(ap.bssid, cfg.output.data_dir)
    seen: set[str] = set()
    out: list[str] = []

    def add(word: str) -> None:
        w = word.strip()
        if not w or len(w) < 8 or len(w) > 63:
            return
        key = w.casefold()
        if key in seen:
            return
        seen.add(key)
        out.append(w)

    for word in _vendor_candidates(vendor):
        add(word)
        if len(out) >= max_candidates:
            return out
    for word in COMMON_WIFI_PASSWORDS:
        add(word)
        if len(out) >= max_candidates:
            break
    essid = ap.essid or ""
    if essid:
        for suffix in ("123", "1234", "12345", "2024", "2025", "2026"):
            add(f"{essid}{suffix}")
            if len(out) >= max_candidates:
                break
    return out


def write_vendor_wordlist(ap: AccessPoint, cfg: WifluxConfig) -> tuple[str, int] | None:
    words = generate_vendor_defaults(ap, cfg)
    if not words:
        return None
    fd, path = tempfile.mkstemp(prefix="wiflux_vendor_", suffix=".txt")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as fh:
        for word in words:
            fh.write(word + "\n")
    return path, len(words)