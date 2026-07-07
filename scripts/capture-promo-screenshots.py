#!/usr/bin/env python3
"""Generate promotional PNG screenshots for Wiflux marketing material."""

from __future__ import annotations

import random
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from PIL import Image, ImageDraw, ImageFont
from rich.console import Console
from rich.panel import Panel

from wiflux import __version__
from wiflux.display import build_scan_table
from wiflux.models import AccessPoint, Client, CrackResult, EncryptionType, WPSState
from wiflux.progress import ProgressTracker
from wiflux.splash import MatrixRain

OUT_DIR = ROOT / "assets" / "promo"
BG = (8, 12, 8)
TERM_BG = "#0a0e0a"
FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_SIZE = 16
COLS = 100
ROWS = 32

LEVEL_COLORS = {
    0: BG,
    1: (0, 28, 0),
    2: (0, 55, 0),
    3: (0, 120, 0),
    4: (0, 190, 0),
    5: (57, 255, 20),
    6: (240, 255, 240),
    7: (0, 255, 70),
    8: (0, 220, 220),
    9: (255, 230, 0),
    10: (0, 170, 55),
}


def sample_targets() -> list[AccessPoint]:
    return [
        AccessPoint(
            bssid="92:B4:74:3A:F1:92", channel=44, encryption=EncryptionType.WPA2,
            auth="PSK", power=79, essid="Yaxley 5ghz", essid_known=True,
            wps=WPSState.UNLOCKED,
            clients=[Client("FE:32:E8:12:1E:0A", -42), Client("EE:D7:16:FD:EC:18", -55)],
        ),
        AccessPoint(
            bssid="3C:A6:2F:7E:AF:D0", channel=11, encryption=EncryptionType.WPA2,
            auth="PSK", power=62, essid="Yaxley24ghz", essid_known=True,
            wps=WPSState.LOCKED,
            clients=[Client("AA:BB:CC:DD:EE:01", -48)],
        ),
        AccessPoint(
            bssid="0E:92:84:DA:ED:29", channel=6, encryption=EncryptionType.WPA2,
            auth="PSK", power=54, essid="Workshop-Guest", essid_known=True,
            wps=WPSState.NONE,
            clients=[Client("11:22:33:44:55:66", -60), Client("22:33:44:55:66:77", -65)],
        ),
        AccessPoint(
            bssid="64:FD:96:CD:AF:EB", channel=1, encryption=EncryptionType.WPA3,
            auth="SAE", power=41, essid="SecureHome", essid_known=True,
            wps=WPSState.NONE,
        ),
        AccessPoint(
            bssid="A4:2B:8C:11:22:33", channel=36, encryption=EncryptionType.WPA2,
            auth="PSK", power=35, essid=None, essid_known=False,
            wps=WPSState.UNKNOWN,
            clients=[Client("CC:DD:EE:FF:00:11", -70)],
        ),
        AccessPoint(
            bssid="B8:27:EB:44:55:66", channel=9, encryption=EncryptionType.OPEN,
            auth="", power=28, essid="CafeWiFi-Free", essid_known=True,
        ),
    ]


def render_welcome(path: Path) -> None:
    random.seed(42)
    rain = MatrixRain(COLS, ROWS)
    for _ in range(48):
        rain.tick()

    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    bbox = probe.textbbox((0, 0), "M", font=font)
    cell_w = bbox[2] - bbox[0]
    cell_h = bbox[3] - bbox[1] + 4

    img = Image.new("RGB", (cell_w * COLS + 40, cell_h * ROWS + 40), BG)
    draw = ImageDraw.Draw(img)
    ox, oy = 20, 20

    grid_chars = [[" "] * rain.width for _ in range(rain.height)]
    grid_bright = [[0] * rain.width for _ in range(rain.height)]
    for y in range(rain.height):
        for x in range(rain.width):
            level = rain.brightness[y][x]
            if level > 0:
                grid_chars[y][x] = rain.chars[y][x]
                grid_bright[y][x] = level
    rain._apply_logo(grid_chars, grid_bright, __version__)

    for y in range(rain.height):
        for x in range(rain.width):
            ch = grid_chars[y][x]
            level = grid_bright[y][x]
            if ch == " " and level <= 0:
                continue
            color = LEVEL_COLORS.get(level, LEVEL_COLORS[3])
            draw.text((ox + x * cell_w, oy + y * cell_h), ch, font=font, fill=color)

    img.save(path, "PNG", optimize=True)
    print(f"  wrote {path.name}")


def rich_to_png(renderable, path: Path, *, width: int = 118) -> None:
    svg_path = path.with_suffix(".svg")
    console = Console(
        record=True, width=width, force_terminal=True,
        color_system="truecolor", emoji=False,
    )
    console.print(renderable)
    console.save_svg(str(svg_path), title="Wiflux")
    subprocess.run(
        [
            "convert", "-background", TERM_BG, "-density", "144",
            str(svg_path), "-trim", "+repage", str(path),
        ],
        check=True,
        capture_output=True,
    )
    svg_path.unlink(missing_ok=True)
    print(f"  wrote {path.name}")


def render_scanning(path: Path, targets: list[AccessPoint]) -> None:
    import time

    tracker = ProgressTracker()
    tracker.begin_scan(scan_limit=120)
    tracker._started_at = time.time() - 34.0
    tracker.update_scan(targets, decloaking=True)
    tracker.log("Monitor mode enabled on wlan0mon", tag="interface")
    tracker.log("WPS probe started (wash)", tag="wash")
    tracker.log("Decloaking hidden network A4:2B:8C:11:22:33", tag="decloak")
    rich_to_png(tracker.render(), path)


def render_target_selection(path: Path, targets: list[AccessPoint]) -> None:
    table = build_scan_table(targets, ranked=True)
    panel = Panel(
        table,
        title="[bold green]Select targets[/] [dim](comma-separated numbers, or 'all')[/]",
        border_style="green",
        subtitle="[dim]Ctrl+C when ready to attack selected networks[/]",
    )
    rich_to_png(panel, path)


def render_attack(path: Path, targets: list[AccessPoint]) -> None:
    tracker = ProgressTracker()
    ap = targets[0]
    tracker.begin_attack(1, 3, ap)
    tracker.enable_skip_controls()
    tracker.update_attack(
        "handshake", "capture",
        "Deauth burst → listening for EAPOL",
        timeout=300,
        started=__import__("time").time() - 47,
        clients=2,
        deauths=15,
        eapol=3,
        deauth_rx=12,
        auth=2,
        assoc=1,
        reconnect=True,
        cap_kb=128,
    )
    tracker.log("Sent deauth to FE:32:E8:12:1E:0A", tag="aireplay")
    tracker.log("EAPOL frame captured (message 1 of 4)", tag="capture")
    tracker.log("Client reconnect detected", tag="health")
    rich_to_png(tracker.render(), path)


def render_cracked(path: Path) -> None:
    result = CrackResult(
        bssid="92:B4:74:3A:F1:92",
        essid="Yaxley 5ghz",
        key="yaxley2024!",
        method="handshake + smart wordlist",
        capture_file="hs/handshake-92:B4:74:3A:F1:92.cap",
        cracked_at="18:42:07",
    )
    panel = Panel(
        f"[bold green]CRACKED[/]\n"
        f"ESSID: [cyan]{result.essid}[/]\n"
        f"BSSID: [dim]{result.bssid}[/]\n"
        f"Key:   [bold yellow]{result.key}[/]\n"
        f"Method: {result.method}",
        border_style="green",
    )
    rich_to_png(panel, path, width=72)


def render_searching(path: Path) -> None:
    import time

    tracker = ProgressTracker()
    tracker.begin_scan(scan_limit=0)
    tracker._started_at = time.time() - 6.0
    tracker.tick_scan()
    tracker.log("Putting wlan0 into monitor mode...", tag="interface")
    tracker.log("Starting airodump-ng on 2.4 GHz channels", tag="scan")
    rich_to_png(tracker.render(), path, width=90)


def render_banner(path: Path) -> None:
    panel = Panel.fit(
        f"[bold green]WIFLUX[/] [dim]v{__version__}[/]\n"
        "[cyan]Modern wireless security auditor[/]",
        border_style="green",
    )
    rich_to_png(panel, path, width=60)


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    targets = sample_targets()

    print(f"Generating promotional screenshots in {OUT_DIR}/")
    render_welcome(OUT_DIR / "01-welcome-matrix.png")
    render_banner(OUT_DIR / "02-banner.png")
    render_searching(OUT_DIR / "03-searching.png")
    render_scanning(OUT_DIR / "04-live-scan.png", targets)
    render_target_selection(OUT_DIR / "05-target-selection.png", targets)
    render_attack(OUT_DIR / "06-attack-handshake.png", targets)
    render_cracked(OUT_DIR / "07-cracked-success.png")

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())