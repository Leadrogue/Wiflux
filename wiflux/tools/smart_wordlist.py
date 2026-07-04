"""ESSID- and vendor-aware targeted wordlist generation."""

from __future__ import annotations

import os
import re
import tempfile
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ..config import WifluxConfig
from ..models import AccessPoint

DEFAULT_SMART_CANDIDATES = 1000
MAX_SMART_CANDIDATES = 100_000
PREVIEW_EXAMPLE_COUNT = 8


def clamp_wordlist_size(
    value: int,
    *,
    default: int = DEFAULT_SMART_CANDIDATES,
    maximum: int = MAX_SMART_CANDIDATES,
) -> int:
    """Clamp a user-requested wordlist size to the allowed range."""
    if value < 1:
        return default
    return min(value, maximum)

# Common default passwords keyed by normalized vendor substring.
VENDOR_DEFAULTS: dict[str, list[str]] = {
    "tp-link": [
        "tplink", "tp-link", "admin", "password", "12345678", "87654321",
        "tplink123", "tplink1234", "wireless", "internet",
    ],
    "tplink": [
        "tplink", "tp-link", "admin", "password", "12345678", "87654321",
        "tplink123", "tplink1234",
    ],
    "netgear": [
        "netgear", "password", "12345678", "admin", "wireless", "netgear1",
        "netgear123", "NETGEAR",
    ],
    "d-link": [
        "dlink", "d-link", "admin", "password", "12345678", "wireless",
    ],
    "dlink": ["dlink", "d-link", "admin", "password", "12345678"],
    "linksys": [
        "linksys", "admin", "password", "wireless", "linksys123", "12345678",
    ],
    "asus": [
        "asus", "admin", "password", "12345678", "wireless", "asus1234",
    ],
    "zyxel": ["zyxel", "1234", "admin", "password", "12345678"],
    "huawei": [
        "huawei", "admin", "password", "12345678", "welcome", "user",
    ],
    "arris": ["arris", "password", "admin", "12345678"],
    "technicolor": ["technicolor", "password", "admin", "12345678"],
    "sagemcom": ["sagemcom", "admin", "password", "12345678"],
    "belkin": ["belkin", "password", "admin", "12345678"],
    "cisco": ["cisco", "admin", "password", "12345678"],
    "ubiquiti": ["ubnt", "ubiquiti", "admin", "password"],
    "mikrotik": ["mikrotik", "admin", "password"],
    "vodafone": ["vodafone", "password", "12345678", "wireless"],
    "bt": ["bt", "password", "admin", "12345678"],
    "sky": ["sky", "password", "admin", "12345678"],
    "virgin": ["virgin", "password", "admin", "12345678"],
    "talktalk": ["talktalk", "password", "admin", "12345678"],
}

COMMON_PREFIXES = (
    "my", "the", "our", "welcome", "guest", "home", "wifi", "secure", "private",
)
COMMON_SUFFIXES = (
    "home", "house", "wifi", "net", "network", "router", "pass", "password",
    "guest", "internet", "online", "family", "mobile", "fiber", "broadband",
)
COMMON_INFIXES = ("", "-", "_", ".")
SYMBOL_SUFFIXES = ("!", "!!", "@", "#", "*", "?", "1!", "123!")
YEAR_RANGE = range(2000, 2027)
COMMON_WIFI_PASSWORDS = (
    "12345678", "87654321", "password", "password1", "password123",
    "changeme", "letmein", "welcome1", "internet", "wireless",
    "qwerty123", "abc12345", "football", "baseball", "sunshine",
    "trustno1", "iloveyou", "admin123", "default1", "passw0rd",
    "P@ssw0rd", "Passw0rd", "Winter2024", "Summer2024", "Spring2024",
)


def _normalize_vendor(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def lookup_vendor(bssid: str, data_dir: str) -> str:
    """Return organization name for the BSSID OUI prefix, if known."""
    prefix = bssid.replace(":", "").upper()[:6]
    oui_path = Path(data_dir) / "ieee-oui.txt"
    if not oui_path.is_file():
        return ""
    try:
        with open(oui_path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#") or "\t" not in line:
                    continue
                key, org = line.split("\t", 1)
                if key.strip().upper() == prefix:
                    return org.strip()
    except OSError:
        return ""
    return ""


def _valid_password(value: str) -> bool:
    return bool(value) and 8 <= len(value) <= 63


def _bases_from_essid(essid: str) -> list[str]:
    if not essid or not essid.strip():
        return []
    raw = essid.strip()
    alnum = re.sub(r"[^a-zA-Z0-9]", "", raw)
    tokens = re.findall(r"[a-zA-Z0-9]+", raw)
    compact = re.sub(r"[^a-zA-Z0-9]+", "", raw)
    spaced = re.sub(r"[^a-zA-Z0-9]+", " ", raw).strip()

    bases: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        value = value.strip()
        if not value or len(value) < 3:
            return
        key = value.casefold()
        if key in seen:
            return
        seen.add(key)
        bases.append(value)

    for value in (raw, alnum, compact, spaced.replace(" ", "")):
        add(value)
        add(value.lower())
        add(value.upper())
        add(value.title())
        add(value.capitalize())

    for token in tokens:
        add(token)
        add(token.lower())
        add(token.upper())
        add(token.title())

    if " " in spaced:
        parts = spaced.split()
        if len(parts) >= 2:
            add("".join(parts))
            add("".join(p.title() for p in parts))
            add("_".join(parts))
            add("-".join(parts))

    return bases


def _leet_variants(base: str) -> Iterator[str]:
    table = str.maketrans({
        "a": "@", "A": "@",
        "e": "3", "E": "3",
        "i": "1", "I": "1",
        "o": "0", "O": "0",
        "s": "$", "S": "$",
    })
    translated = base.translate(table)
    if translated != base:
        yield translated
    lower = base.lower().translate(table)
    if lower != base.lower():
        yield lower
        yield lower.title()


def _expand_base_priority(base: str) -> Iterator[str]:
    """High-likelihood mutations before bulk numeric fill."""
    if not base:
        return

    yield base

    for suffix in ("1", "12", "123", "1234", "12345", "123456", "1234567", "12345678"):
        yield f"{base}{suffix}"

    for year in YEAR_RANGE:
        yield f"{base}{year}"
        yield f"{base}{year % 100:02d}"
        if len(base) >= 4:
            yield f"{base[-4:]}{year}"

    for sym in SYMBOL_SUFFIXES:
        yield f"{base}{sym}"

    for prefix in COMMON_PREFIXES:
        yield f"{prefix}{base}"
        yield f"{prefix}{base.title()}"

    for suffix in COMMON_SUFFIXES:
        yield f"{base}{suffix}"
        yield f"{base}{suffix.title()}"

    for sep in COMMON_INFIXES:
        if not sep:
            continue
        for year in range(2018, 2027):
            yield f"{base}{sep}{year}"
        for n in (1, 12, 123, 1234):
            yield f"{base}{sep}{n}"

    yield f"{base}wifi"
    yield f"wifi{base}"
    yield f"{base}WiFi"
    yield f"WiFi{base}"

    for variant in _leet_variants(base):
        yield variant
        yield f"{variant}123"
        yield f"{variant}1234"

    for tail in COMMON_WIFI_PASSWORDS:
        yield f"{base}{tail}"
        yield f"{tail}{base}"


def _expand_base_numeric(base: str) -> Iterator[str]:
    for n in range(0, MAX_SMART_CANDIDATES):
        yield f"{base}{n}"


def _vendor_candidates(manufacturer: str) -> list[str]:
    if not manufacturer:
        return []
    norm = _normalize_vendor(manufacturer)
    out: list[str] = []
    for key, words in VENDOR_DEFAULTS.items():
        key_norm = _normalize_vendor(key)
        if key_norm in norm or norm in key_norm:
            out.extend(words)
    if not out:
        token = re.sub(r"[^a-zA-Z0-9]", "", manufacturer.split()[0])
        if len(token) >= 3:
            out.extend([token.lower(), token, token.upper(), f"{token.lower()}123"])
    return out


def _iter_candidate_sources(
    essid: str,
    bssid: str,
    manufacturer: str,
    *,
    data_dir: str,
) -> Iterator[str]:
    vendor = manufacturer or lookup_vendor(bssid, data_dir)
    essid_bases = _bases_from_essid(essid)

    for base in essid_bases:
        yield from _expand_base_priority(base)

    for word in _vendor_candidates(vendor):
        yield word
        yield from _expand_base_priority(word)

    if vendor:
        for base in _bases_from_essid(vendor.split()[0]):
            yield from _expand_base_priority(base)

    for common in COMMON_WIFI_PASSWORDS:
        yield common
        compact = re.sub(r"[^a-zA-Z0-9]", "", essid or "")
        if compact:
            yield f"{compact}{common}"
            yield f"{common}{compact}"

    for base in essid_bases:
        yield from _expand_base_numeric(base)

    for word in _vendor_candidates(vendor):
        yield from _expand_base_numeric(word)


def generate_candidates(
    essid: str,
    bssid: str,
    manufacturer: str = "",
    *,
    data_dir: str = "wiflux-data",
    max_candidates: int = MAX_SMART_CANDIDATES,
) -> list[str]:
    """Build deduplicated password candidates for *essid* / *bssid*."""
    seen: set[str] = set()
    ordered: list[str] = []

    for candidate in _iter_candidate_sources(essid, bssid, manufacturer, data_dir=data_dir):
        if not _valid_password(candidate):
            continue
        key = candidate.casefold()
        if key in seen:
            continue
        seen.add(key)
        ordered.append(candidate)
        if len(ordered) >= max_candidates:
            break

    return ordered


def select_preview_examples(
    candidates: list[str],
    count: int = PREVIEW_EXAMPLE_COUNT,
) -> list[str]:
    """Pick a small, spread-out sample for the confirmation preview."""
    if len(candidates) <= count:
        return list(candidates)
    if count <= 1:
        return [candidates[0]]

    indices: list[int] = []
    step = (len(candidates) - 1) / (count - 1)
    for i in range(count):
        indices.append(min(len(candidates) - 1, round(i * step)))
    # Deduplicate while preserving order
    seen: set[int] = set()
    unique: list[int] = []
    for idx in indices:
        if idx not in seen:
            seen.add(idx)
            unique.append(idx)
    return [candidates[i] for i in unique]


def write_temp_wordlist(candidates: list[str]) -> str:
    fd, path = tempfile.mkstemp(suffix=".txt", prefix="wiflux_smart_")
    os.close(fd)
    with open(path, "w", encoding="utf-8") as fh:
        for word in candidates:
            fh.write(word + "\n")
    return path


def show_smart_wordlist_preview(
    ap: AccessPoint,
    candidates: list[str],
    cfg: WifluxConfig,
) -> None:
    """Print an explanation and a few example candidates before confirmation."""
    from rich.panel import Panel
    from rich.table import Table

    from ..display import console, safe_markup, safe_text

    essid = ap.essid or ap.display_name
    vendor = ap.manufacturer or lookup_vendor(ap.bssid, cfg.output.data_dir)
    fallback = os.path.basename(cfg.attack.wordlist or "wordlist.txt")
    examples = select_preview_examples(candidates)

    lines = [
        "[bold]ESSID-smart wordlist[/] — targeted guesses before the full dictionary.",
        "",
        f"Network: [cyan]{safe_markup(essid)}[/]  BSSID: [dim]{safe_markup(ap.bssid)}[/]",
    ]
    if vendor:
        lines.append(f"Vendor: [dim]{safe_markup(vendor)}[/]")
    lines.extend([
        "",
        "Passwords are built from the network name (mutations, years, symbols, leet variants),",
        "router vendor defaults, and common WiFi patterns.",
        f"[dim]Default size:[/] [yellow]{DEFAULT_SMART_CANDIDATES:,}[/]  "
        f"[dim]|[/]  [dim]Maximum:[/] [yellow]{MAX_SMART_CANDIDATES:,}[/]",
        f"If none match, wiflux falls back to [yellow]{safe_markup(fallback)}[/].",
    ])
    console.print(Panel("\n".join(lines), border_style="cyan", padding=(0, 1)))

    table = Table(
        title=f"Examples ({len(examples)} of {len(candidates)} candidates)",
        expand=True,
        show_lines=False,
    )
    table.add_column("Example", style="yellow", no_wrap=True)
    for word in examples:
        table.add_row(safe_text(word))
    if len(candidates) > len(examples):
        table.add_row(safe_text(f"… and {len(candidates) - len(examples)} more"))
    console.print(table)


def _essid_for_ap(ap: AccessPoint) -> str:
    if ap.essid and ap.essid_known:
        return ap.essid
    name = ap.display_name
    if name.startswith("(") and name.endswith(")"):
        return ""
    return name


def generate_and_write_smart_wordlist(
    ap: AccessPoint,
    cfg: WifluxConfig,
    max_candidates: int,
) -> tuple[str, int]:
    """Generate candidates with a live progress graphic; return (path, count)."""
    import threading
    import time

    from rich.align import Align
    from rich.panel import Panel
    from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
    from rich.text import Text

    from ..display import console, safe_markup

    goal = clamp_wordlist_size(max_candidates)
    essid = _essid_for_ap(ap) or ap.display_name

    console.print()
    console.print(Panel(
        Align.center(Text.from_markup(
            f"[bold cyan]◆  ESSID-SMART WORDLIST GENERATOR  ◆[/]\n\n"
            f"[dim]network[/]   [yellow]{safe_markup(essid)}[/]\n"
            f"[dim]target[/]    [bold yellow]{goal:,}[/] passwords"
        )),
        border_style="cyan",
        padding=(1, 2),
    ))

    stages = (
        "Extracting ESSID patterns...",
        "Applying mutations & years...",
        "Adding vendor defaults...",
        "Deduplicating candidates...",
        "Writing wordlist file...",
    )
    result_box: list[list[str]] = []
    error_box: list[BaseException] = []

    def worker() -> None:
        try:
            result_box.append(generate_candidates(
                _essid_for_ap(ap),
                ap.bssid,
                ap.manufacturer,
                data_dir=cfg.output.data_dir,
                max_candidates=goal,
            ))
        except BaseException as exc:
            error_box.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()

    with Progress(
        SpinnerColumn("dots12"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=40, pulse_style="bold cyan", style="dim cyan"),
        TimeElapsedColumn(),
        console=console,
        expand=True,
    ) as progress:
        task = progress.add_task(stages[0], total=len(stages))
        tick = 0
        while thread.is_alive():
            progress.update(
                task,
                description=stages[tick % len(stages)],
                completed=min(tick % len(stages), len(stages) - 1),
            )
            tick += 1
            time.sleep(0.12)
        thread.join()
        if error_box:
            raise error_box[0]
        progress.update(task, description="[green]Complete![/]", completed=len(stages))

    candidates = result_box[0] if result_box else []
    if not candidates:
        console.print(Panel("[red]No candidates generated[/]", border_style="red"))
        return "", 0

    path = write_temp_wordlist(candidates)
    console.print(Panel(
        f"[bold green]✓[/]  Generated [bold yellow]{len(candidates):,}[/] passwords",
        border_style="green",
        padding=(0, 1),
    ))
    console.print()
    return path, len(candidates)


def build_smart_wordlist(
    ap: AccessPoint,
    cfg: WifluxConfig,
    *,
    max_candidates: int = DEFAULT_SMART_CANDIDATES,
) -> tuple[str, int] | None:
    """Generate a temp wordlist; return (path, count) or None if empty."""
    candidates = generate_candidates(
        _essid_for_ap(ap),
        ap.bssid,
        ap.manufacturer,
        data_dir=cfg.output.data_dir,
        max_candidates=max_candidates,
    )
    if not candidates:
        return None
    return write_temp_wordlist(candidates), len(candidates)