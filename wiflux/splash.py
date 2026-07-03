"""Matrix-style raining code splash screen."""

from __future__ import annotations

import os
import random
import select
import shutil
import sys
import termios
import time
import tty
from typing import Optional

MATRIX_CHARS = (
    "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾄﾅﾆﾇﾈﾉ"
    "ﾊﾋﾌﾍﾎﾏﾐﾑﾒﾓﾔﾕﾖﾗﾘﾙﾚﾛﾜｦﾝ"
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "$%#&@<>{}[]|/\\+=*~"
)

LOGO_WIDE = [
    "██╗    ██╗██╗███████╗██╗     ██╗   ██╗██╗  ██╗",
    "██║    ██║██║██╔════╝██║     ██║   ██║╚██╗██╔╝",
    "██║ █╗ ██║██║█████╗  ██║     ██║   ██║ ╚███╔╝ ",
    "██║███╗██║██║██╔══╝  ██║     ██║   ██║ ██╔██╗ ",
    "╚███╔███╔╝██║██║     ███████╗╚██████╔╝██╔╝ ██╗",
    " ╚══╝╚══╝ ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝",
]

LOGO_NARROW = [
    "╦ ╦╔═╗╔═╗╦  ╦ ╦╦═╗",
    "║║║╠╣ ║ ║║  ║ ║╠╦╝",
    "╚╩╝╩  ╚═╝╩═╝╚═╝╩╚═",
]

_STYLES = {
    0: "",
    1: "\033[38;5;22m",
    2: "\033[38;5;28m",
    3: "\033[32m",
    4: "\033[92m",
    5: "\033[1;92m",
    6: "\033[1;97m",
    7: "\033[1;32m",   # logo
    8: "\033[96m",     # subtitle
    9: "\033[1;93m",   # prompt highlight
    10: "\033[38;5;34m",  # prompt border
}
_RESET = "\033[0m"


def _logo_for_width(width: int) -> list[str]:
    if width >= 52:
        return LOGO_WIDE
    return LOGO_NARROW


def _prompt_banner(width: int, pulse: int) -> list[tuple[str, int]]:
    """Return centered prompt lines with brightness levels."""
    highlight = 9 if pulse < 12 else 6
    border_level = 10
    core = "PRESS SPACE TO BEGIN"

    if width >= len(core) + 14:
        inner = f"▶  {core}  ◀"
        fill = "═" * (len(inner) + 2)
        return [
            (f"╔{fill}╗", border_level),
            (f"║ {inner} ║", highlight),
            (f"╚{fill}╝", border_level),
        ]

    compact = f"»  {core}  «"
    return [(compact, highlight)]


class MatrixRain:
    def __init__(self, width: int, height: int):
        self.width = max(40, width)
        self.height = max(12, height)
        self.chars = [
            [random.choice(MATRIX_CHARS) for _ in range(self.width)]
            for _ in range(self.height)
        ]
        self.brightness = [[0] * self.width for _ in range(self.height)]
        self.drops = [random.uniform(-self.height, 0) for _ in range(self.width)]
        self.speeds = [random.uniform(0.35, 1.6) for _ in range(self.width)]
        self.trails = [random.randint(7, 20) for _ in range(self.width)]
        self._pulse = 0

    def tick(self) -> None:
        self._pulse = (self._pulse + 1) % 24
        for y in range(self.height):
            for x in range(self.width):
                if self.brightness[y][x] > 0:
                    self.brightness[y][x] -= 1
                    if random.random() < 0.03:
                        self.chars[y][x] = random.choice(MATRIX_CHARS)

        for x in range(self.width):
            self.drops[x] += self.speeds[x]
            head = int(self.drops[x])
            if head >= self.height + 2:
                self.drops[x] = random.uniform(-self.height * 0.6, -4)
                self.speeds[x] = random.uniform(0.35, 1.6)
                self.trails[x] = random.randint(7, 20)
                continue

            for i in range(self.trails[x]):
                y = head - i
                if not 0 <= y < self.height:
                    continue
                if i == 0:
                    level = 6 if random.random() < 0.15 else 5
                elif i < 2:
                    level = 5
                elif i < 5:
                    level = 4
                elif i < 10:
                    level = 3
                else:
                    level = max(1, 2 - i // 8)
                self.brightness[y][x] = max(self.brightness[y][x], level)
                if i == 0 or random.random() < 0.35:
                    self.chars[y][x] = random.choice(MATRIX_CHARS)

    @staticmethod
    def _blit_line(
        grid_chars: list[list[str]],
        grid_bright: list[list[int]],
        y: int,
        text: str,
        level: int,
        width: int,
    ) -> None:
        if not 0 <= y < len(grid_chars):
            return
        x0 = max(0, (width - len(text)) // 2)
        for j, ch in enumerate(text):
            x = x0 + j
            if x >= width:
                break
            grid_chars[y][x] = ch
            grid_bright[y][x] = level

    def _apply_logo(
        self,
        grid_chars: list[list[str]],
        grid_bright: list[list[int]],
        version: str,
    ) -> None:
        logo = _logo_for_width(self.width)
        prompt = _prompt_banner(self.width, self._pulse)
        block_h = len(logo) + len(prompt) + 4
        start_y = max(1, (self.height - block_h) // 2)

        logo_glow = 7 if self._pulse < 12 else 5
        for i, line in enumerate(logo):
            self._blit_line(grid_chars, grid_bright, start_y + i, line, logo_glow, self.width)

        tag_y = start_y + len(logo) + 1
        self._blit_line(
            grid_chars, grid_bright, tag_y,
            "WIRELESS SECURITY AUDITOR", 8, self.width,
        )

        ver_y = tag_y + 1
        self._blit_line(grid_chars, grid_bright, ver_y, f"v{version}", 4, self.width)

        prompt_start = self.height - len(prompt) - 1
        for i, (line, level) in enumerate(prompt):
            self._blit_line(grid_chars, grid_bright, prompt_start + i, line, level, self.width)

    def frame(self, version: str) -> str:
        grid_chars = [[" "] * self.width for _ in range(self.height)]
        grid_bright = [[0] * self.width for _ in range(self.height)]

        for y in range(self.height):
            for x in range(self.width):
                level = self.brightness[y][x]
                if level > 0:
                    grid_chars[y][x] = self.chars[y][x]
                    grid_bright[y][x] = level

        self._apply_logo(grid_chars, grid_bright, version)

        lines: list[str] = []
        for y in range(self.height):
            row: list[str] = []
            for x in range(self.width):
                level = grid_bright[y][x]
                ch = grid_chars[y][x]
                if level <= 0:
                    row.append(" ")
                else:
                    row.append(f"{_STYLES.get(level, _STYLES[3])}{ch}{_RESET}")
            lines.append("".join(row))
        return "\n".join(lines)


def _open_input_fd() -> tuple[int, bool]:
    if os.path.exists("/dev/tty"):
        return os.open("/dev/tty", os.O_RDONLY), True
    return sys.stdin.fileno(), False


def _space_pressed(fd: int) -> bool:
    ready, _, _ = select.select([fd], [], [], 0)
    if not ready:
        return False
    return b" " in os.read(fd, 16)


def show_splash(version: str) -> None:
    """Matrix rain welcome screen — runs until Space is pressed."""
    if not sys.stdout.isatty():
        return

    cols, rows = shutil.get_terminal_size((80, 24))
    rain = MatrixRain(cols, rows - 1)
    fd, owned = _open_input_fd()
    old_term: Optional[list] = None

    try:
        old_term = termios.tcgetattr(fd)
        tty.setcbreak(fd)
        sys.stdout.write("\033[?25l\033[?1049h\033[2J\033[H")
        sys.stdout.flush()

        while True:
            if _space_pressed(fd):
                break
            rain.tick()
            sys.stdout.write("\033[H")
            sys.stdout.write(rain.frame(version))
            sys.stdout.flush()
            time.sleep(0.045)
    finally:
        if old_term is not None:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_term)
        if owned:
            os.close(fd)
        sys.stdout.write("\033[?1049l\033[?25h\033[0m")
        sys.stdout.flush()