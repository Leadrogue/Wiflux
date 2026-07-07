"""Multi-stage hashcat crack ladder after capture."""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..config import WifluxConfig
from ..models import AccessPoint
from .hashcat import PASS_TIMEOUT
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


@dataclass
class CrackStage:
    wordlist: str
    label: str
    rules: str | None = None
    candidates: int = 0
    eta_seconds: int = 0
    capped: bool = False


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


def append_crack_ladder_stages(
    stages: list[tuple[str, str, str | None]],
    base_wl: str,
) -> None:
    """
    Append hashcat ladder stages after smart/vendor passes.

    Order: full wordlist first, then rule passes shortest-to-longest ETA,
    with d3ad0ne.rule always last.
    """
    if not base_wl or not os.path.isfile(base_wl):
        return

    wl_name = os.path.basename(base_wl)
    d3ad0ne: str | None = None
    other_rules: list[str] = []
    for path in discover_hashcat_rules():
        if os.path.basename(path).lower() == "d3ad0ne.rule":
            d3ad0ne = path
        else:
            other_rules.append(path)

    stages.append((base_wl, f"Full dictionary ({wl_name})", None))

    other_rules.sort(key=lambda rule: estimate_stage_candidates(base_wl, rule))
    for rule in other_rules:
        stages.append((
            base_wl,
            f"Rules ({os.path.basename(rule)})",
            rule,
        ))

    if d3ad0ne and os.path.isfile(d3ad0ne):
        stages.append((base_wl, "Rules (d3ad0ne.rule)", d3ad0ne))


def count_file_lines(path: str) -> int:
    if not path or not os.path.isfile(path):
        return 0
    count = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            count += chunk.count(b"\n")
    return count


def count_rule_lines(path: str) -> int:
    if not path or not os.path.isfile(path):
        return 0
    count = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                count += 1
    return count


def estimate_stage_candidates(wordlist: str, rules: str | None) -> int:
    wl_count = count_file_lines(wordlist)
    if not rules or not os.path.isfile(rules):
        return wl_count
    return wl_count * count_rule_lines(rules)


def enrich_stage_etas(stages: list[CrackStage], speed: int) -> None:
    for stage in stages:
        stage.candidates = estimate_stage_candidates(stage.wordlist, stage.rules)
        if speed <= 0 or stage.candidates <= 0:
            stage.eta_seconds = 0
            stage.capped = False
            continue
        raw = stage.candidates / speed
        stage.capped = raw > PASS_TIMEOUT
        stage.eta_seconds = min(PASS_TIMEOUT, int(raw))


def build_crack_stages(
    ap: AccessPoint,
    cfg: WifluxConfig,
    wordlist: str,
    wl_label: str,
    temp_path: str | None,
) -> tuple[list[CrackStage], list[str]]:
    cleanup: list[str] = []
    if temp_path:
        cleanup.append(temp_path)

    stages: list[CrackStage] = []
    if wl_label.startswith("smart:"):
        count = wl_label.split(":", 1)[1]
        stages.append(CrackStage(wordlist, f"ESSID-smart ({count})"))
    else:
        stages.append(CrackStage(wordlist, f"Dictionary ({wl_label})"))

    if cfg.attack.crack_ladder:
        vendor = write_vendor_wordlist(ap, cfg)
        if vendor:
            vpath, vcount = vendor
            cleanup.append(vpath)
            stages.append(CrackStage(vpath, f"Vendor defaults ({vcount})"))
        tuple_stages: list[tuple[str, str, str | None]] = []
        append_crack_ladder_stages(tuple_stages, cfg.attack.wordlist)
        for wl_path, detail, rules in tuple_stages:
            stages.append(CrackStage(wl_path, detail, rules))

    return stages, cleanup


def format_crack_plan(
    stages: list[CrackStage],
    *,
    speed: int = 0,
    pass_timeout: int = PASS_TIMEOUT,
) -> list[str]:
    from .hashcat import Hashcat

    lines = ["[bold]Crack plan[/]"]
    total_eta = 0
    for idx, stage in enumerate(stages, 1):
        cand = Hashcat._fmt_num(stage.candidates) if stage.candidates else "?"
        if stage.eta_seconds:
            eta = Hashcat._fmt_eta(stage.eta_seconds)
            if stage.capped:
                eta += f" [dim](cap {Hashcat._fmt_eta(pass_timeout)}/pass)[/]"
            total_eta += stage.eta_seconds
        else:
            eta = "—"
        lines.append(
            f"  [cyan]{idx}/{len(stages)}[/] {stage.label}  "
            f"[dim]·[/] [yellow]{cand}[/] candidates  "
            f"[dim]·[/] ETA [magenta]{eta}[/]"
        )
    if speed > 0 and total_eta:
        lines.append(
            f"  [dim]Total (capped): ~{Hashcat._fmt_eta(total_eta)} "
            f"at {Hashcat._fmt_speed(speed)}[/]"
        )
    return lines


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