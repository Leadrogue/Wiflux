"""Non-blocking keyboard input during live attack UI."""

from __future__ import annotations

import os
import select
import sys
import termios
import threading
import tty
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from .progress import ProgressTracker


class SkipListener:
    """Listen for Space on /dev/tty to skip the current attack."""

    def __init__(self, tracker: ProgressTracker):
        self.tracker = tracker
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._fd: Optional[int] = None
        self._old_term: Optional[tuple[int, list]] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if not os.path.exists("/dev/tty"):
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="wiflux-skip", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1.0)
            self._thread = None
        self._restore_term()

    def _run(self) -> None:
        fd: Optional[int] = None
        try:
            fd = os.open("/dev/tty", os.O_RDONLY)
            self._fd = fd
            old = termios.tcgetattr(fd)
            self._old_term = (fd, old)
            tty.setcbreak(fd)
            while not self._stop.is_set():
                ready, _, _ = select.select([fd], [], [], 0.2)
                if not ready:
                    continue
                data = os.read(fd, 8)
                if not data:
                    break
                if b" " in data:
                    self.tracker.request_skip()
        except OSError:
            pass
        finally:
            self._restore_term()

    def _restore_term(self) -> None:
        if self._old_term:
            tfd, old = self._old_term
            try:
                termios.tcsetattr(tfd, termios.TCSADRAIN, old)
            except termios.error:
                pass
            self._old_term = None
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None


def input_available() -> bool:
    return sys.stdin.isatty() or os.path.exists("/dev/tty")