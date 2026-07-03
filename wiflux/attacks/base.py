"""Base attack class."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from ..config import WifluxConfig
from ..models import AccessPoint, CrackResult

if TYPE_CHECKING:
    from ..progress import ProgressTracker


@dataclass
class AttackResult:
    success: bool
    crack: CrackResult | None = None
    message: str = ""
    skipped: bool = False


class Attack(ABC):
    name: str = "base"

    def __init__(
        self,
        cfg: WifluxConfig,
        ap: AccessPoint,
        tracker: Optional[ProgressTracker] = None,
    ):
        self.cfg = cfg
        self.ap = ap
        if tracker is None:
            from ..progress import get_tracker
            tracker = get_tracker()
        self.tracker = tracker

    def status(self, phase: str, detail: str, *, timeout: float = 0.0, started: float | None = None, **stats) -> None:
        self.tracker.update_attack(
            self.name, phase, detail,
            timeout=timeout, started=started, **stats,
        )
        self.tracker.refresh()

    def should_stop(self) -> bool:
        return self.tracker.skip_requested()

    def abort_if_skipped(self) -> bool:
        if not self.should_stop():
            return False
        from ..process import ProcessPool
        ProcessPool().cleanup_all()
        return True

    def skipped_result(self, message: str = "Skipped by user") -> AttackResult:
        return AttackResult(False, message=message, skipped=True)

    def crack_hashcat(self, hash_line: str, started: float) -> str | None:
        from ..tools.hashcat import CrackProgress, Hashcat

        def on_progress(progress: CrackProgress) -> None:
            self.status(
                "crack",
                Hashcat.format_progress(progress),
                started=started,
                progress_pct=round(progress.percent, 1),
                speed=progress.speed,
                eta=progress.eta_seconds,
                candidate=progress.candidate,
                words_done=progress.current,
                words_total=progress.total,
            )

        return Hashcat.crack_hash(
            hash_line,
            self.cfg.attack.wordlist,
            self.ap.is_wpa3_sae,
            on_progress=on_progress,
            should_stop=self.should_stop,
        )

    @abstractmethod
    def can_attack(self) -> bool:
        ...

    @abstractmethod
    def run(self) -> AttackResult:
        ...