"""Standalone utility commands (--check, --crack, --update-db)."""

from __future__ import annotations

import csv
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen

from .config import WifluxConfig
from .display import console, print_error, print_info, safe_markup
from .process import run, which
from .results import ResultStore
from .tools.hashcat import Hashcat


OUI_SOURCES = {
    "OUI": "https://standards-oui.ieee.org/oui/oui.csv",
    "MAM": "https://standards-oui.ieee.org/oui28/mam.csv",
    "OUI36": "https://standards-oui.ieee.org/oui36/oui36.csv",
    "IAB": "https://standards-oui.ieee.org/iab/iab.csv",
}


def check_handshakes(path: Optional[str], cfg: WifluxConfig) -> int:
    hs_dir = Path(cfg.output.handshake_dir)
    if path and path != "<all>":
        caps = [Path(path)]
    else:
        caps = sorted(hs_dir.glob("*.cap"))
        if not caps:
            print_info(f"No .cap files in {hs_dir}/")
            return 0

    ok = 0
    for cap in caps:
        if not cap.is_file():
            print_error(f"Not found: {cap}")
            continue
        console.print(f"[cyan]+[/] Checking [white]{cap}[/]")
        bssid, essid = _cap_identity(cap)
        valid = Hashcat.check_handshake(str(cap), bssid or "", essid)
        if valid:
            ok += 1
            label = f"{essid or '?'} ({bssid})" if bssid or essid else "handshake"
            console.print(f"  [green]✓ Valid WPA handshake[/] — {safe_markup(label)}")
        else:
            console.print("  [red]✗ No valid handshake[/]")
    return ok


def _cap_identity(cap: Path) -> tuple[str, str]:
    bssid = essid = ""
    m = re.search(r"([0-9A-Fa-f]{2}(?:-[0-9A-Fa-f]{2}){5})", cap.stem)
    if m:
        bssid = m.group(1).replace("-", ":").upper()
    parts = cap.stem.split("_")
    for part in parts:
        if part and not re.match(r"^(handshake|pmkid|\d{8}T\d{6})$", part) and "-" not in part[:3]:
            if len(part) > 2:
                essid = part
                break
    return bssid, essid


def show_crack_commands(cfg: WifluxConfig) -> None:
    hs_dir = Path(cfg.output.handshake_dir)
    caps = sorted(hs_dir.glob("*.cap"))
    hashes = sorted(hs_dir.glob("*.22000"))
    wl = cfg.attack.wordlist or "/path/to/wordlist.txt"

    if not caps and not hashes:
        print_info(f"No captures in {hs_dir}/")
        return

    console.print("[bold cyan]Crack commands[/] [dim](copy/paste)[/]\n")
    for cap in caps:
        bssid, essid = _cap_identity(cap)
        if Hashcat.check_handshake(str(cap), bssid, essid):
            hash_file = f"{cap}.22000"
            console.print(f"[yellow]# {cap.name}[/]")
            console.print(
                f"hcxpcapngtool -o {hash_file} {cap}\n"
                f"hashcat -m 22000 {hash_file} {wl}\n"
                f"aircrack-ng -b {bssid or 'BSSID'} -w {wl} {cap}\n"
            )
    for h in hashes:
        console.print(f"[yellow]# {h.name} (PMKID)[/]")
        console.print(f"hashcat -m 22000 {h} {wl}\n")


def update_oui_database(cfg: WifluxConfig) -> None:
    out = Path(cfg.output.data_dir) / "ieee-oui.txt"
    console.print(f"[cyan]+[/] Updating OUI database → {out}")
    written = 0
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(f"# Wiflux OUI database\n# {datetime.now(timezone.utc).isoformat()}\n")
        for name, url in OUI_SOURCES.items():
            console.print(f"  [dim]Fetching {name}…[/]")
            try:
                req = Request(url, headers={"User-Agent": "Wiflux/1.0"})
                with urlopen(req, timeout=60) as resp:
                    text = resp.read().decode("utf-8", errors="replace")
                for row in csv.DictReader(text.splitlines()):
                    assignment = (row.get("Assignment") or row.get("MAC Address") or "").strip()
                    org = (row.get("Organization Name") or row.get("Organization") or "").strip()
                    if assignment and org:
                        prefix = assignment.replace("-", "").upper()[:6]
                        fh.write(f"{prefix}\t{org}\n")
                        written += 1
            except Exception as exc:
                print_error(f"{name}: {exc}")
    print_info(f"Done — {written} entries written to {out}")


def show_ignored(cfg: WifluxConfig) -> None:
    store = ResultStore(cfg.output.data_dir)
    rows = store.list_ignored()
    if not rows:
        print_info("No ignored access points.")
        return
    for bssid, essid, reason, ignored_at in rows:
        console.print(
            f"  [cyan]{safe_markup(essid or bssid)}[/] [dim]{safe_markup(bssid)}[/] "
            f"[yellow]{reason}[/] [dim]{ignored_at}[/]"
        )