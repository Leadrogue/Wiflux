"""Base attack class."""

from __future__ import annotations

import os
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

    @staticmethod
    def _smart_wordlist_essid(ap: AccessPoint) -> str:
        if ap.essid and ap.essid_known:
            return ap.essid
        name = ap.display_name
        if name.startswith("(") and name.endswith(")"):
            return ""
        return name

    def _resolve_crack_wordlist(self) -> tuple[str, str | None, str]:
        """Return (wordlist_path, temp_path_to_cleanup_or_None, activity_label)."""
        from ..input import prompt_smart_wordlist

        default = self.cfg.attack.wordlist
        if not default:
            return "", None, ""

        default_name = os.path.basename(default)
        built = prompt_smart_wordlist(self.cfg, self.ap, self.tracker)
        if not built:
            return default, None, default_name

        path, count = built
        self.tracker.log(
            f"[cyan]hashcat[/] pass 1/2: ESSID-smart wordlist "
            f"([yellow]{count:,}[/] passwords)",
            tag=self.name,
        )
        self.tracker.refresh()
        return path, path, f"smart:{count}"

    def crack_hashcat(self, hash_line: str, started: float) -> str | None:
        from ..tools.hashcat import CrackProgress, Hashcat

        wordlist, temp_path, wl_label = self._resolve_crack_wordlist()
        if not wordlist:
            return None

        if wl_label.startswith("smart:"):
            count = wl_label.split(":", 1)[1]
            crack_detail = f"ESSID-smart wordlist ({count} candidates)"
        else:
            crack_detail = f"Full dictionary ({wl_label})"

        self.status("crack", crack_detail, started=started, wordlist=wl_label)
        self.tracker.refresh()

        def on_progress(progress: CrackProgress) -> None:
            self.status(
                "crack",
                f"{crack_detail} — {Hashcat.format_progress(progress)}",
                started=started,
                progress_pct=round(progress.percent, 1),
                speed=progress.speed,
                eta=progress.eta_seconds,
                candidate=progress.candidate,
                words_done=progress.current,
                words_total=progress.total,
                wordlist=wl_label,
            )

        try:
            key = Hashcat.crack_hash(
                hash_line,
                wordlist,
                self.ap.is_wpa3_sae,
                on_progress=on_progress,
                should_stop=self.should_stop,
            )
            if key or temp_path is None or self.should_stop():
                return key

            wl = os.path.basename(self.cfg.attack.wordlist or "")
            smart_count = (
                wl_label.split(":", 1)[1]
                if wl_label.startswith("smart:")
                else "?"
            )
            self.tracker.log(
                f"ESSID-smart wordlist finished ([yellow]{smart_count}[/] passwords) — "
                f"[red]password not found[/], continuing with full dictionary [yellow]{wl}[/]",
                tag=self.name,
            )
            self.tracker.refresh()
            crack_detail = f"Full dictionary ({wl})"
            self.status(
                "crack",
                crack_detail,
                started=started,
                wordlist=wl,
            )

            def on_fallback(progress: CrackProgress) -> None:
                self.status(
                    "crack",
                    f"{crack_detail} — {Hashcat.format_progress(progress)}",
                    started=started,
                    progress_pct=round(progress.percent, 1),
                    speed=progress.speed,
                    eta=progress.eta_seconds,
                    candidate=progress.candidate,
                    words_done=progress.current,
                    words_total=progress.total,
                    wordlist=wl,
                )

            return Hashcat.crack_hash(
                hash_line,
                self.cfg.attack.wordlist,
                self.ap.is_wpa3_sae,
                on_progress=on_fallback,
                should_stop=self.should_stop,
            )
        finally:
            if temp_path:
                try:
                    os.remove(temp_path)
                except OSError:
                    pass

    @abstractmethod
    def can_attack(self) -> bool:
        ...

    @abstractmethod
    def run(self) -> AttackResult:
        ...