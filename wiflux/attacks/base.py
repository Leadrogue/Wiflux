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

    def _resolve_crack_wordlist(
        self,
        *,
        already_suspended: bool = False,
    ) -> tuple[str, str | None, str]:
        """Return (wordlist_path, temp_path_to_cleanup_or_None, activity_label)."""
        from ..input import prompt_smart_wordlist

        preresolved = getattr(self, "_preresolved_wordlist", None)
        if preresolved is not None:
            return preresolved

        default = self.cfg.attack.wordlist
        if not default:
            return "", None, ""

        default_name = os.path.basename(default)
        capture_info = getattr(self, "_handshake_capture_info", None)
        if capture_info is None:
            capture_info = getattr(self, "_pmkid_capture_info", None)
        built = prompt_smart_wordlist(
            self.cfg,
            self.ap,
            self.tracker,
            capture_info=capture_info,
            already_suspended=already_suspended,
        )
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
        from ..tools.crack_ladder import discover_hashcat_rules, write_vendor_wordlist
        from ..tools.hashcat import CrackProgress, Hashcat

        wordlist, temp_path, wl_label = self._resolve_crack_wordlist()
        if not wordlist:
            return None

        cleanup: list[str] = []
        if temp_path:
            cleanup.append(temp_path)

        stages: list[tuple[str, str, str | None]] = []
        if wl_label.startswith("smart:"):
            count = wl_label.split(":", 1)[1]
            stages.append((wordlist, f"ESSID-smart ({count})", None))
        else:
            stages.append((wordlist, f"Dictionary ({wl_label})", None))

        if self.cfg.attack.crack_ladder:
            vendor = write_vendor_wordlist(self.ap, self.cfg)
            if vendor:
                vpath, vcount = vendor
                cleanup.append(vpath)
                stages.append((vpath, f"Vendor defaults ({vcount})", None))
            base_wl = self.cfg.attack.wordlist
            if base_wl and os.path.isfile(base_wl):
                for rule in discover_hashcat_rules()[:2]:
                    stages.append((
                        base_wl,
                        f"Rules ({os.path.basename(rule)})",
                        rule,
                    ))
                wl_name = os.path.basename(base_wl)
                if not any(s[0] == base_wl and s[2] is None for s in stages):
                    stages.append((base_wl, f"Full dictionary ({wl_name})", None))

        try:
            for idx, (wl_path, detail, rules) in enumerate(stages, start=1):
                if self.should_stop():
                    return None
                label = f"pass {idx}/{len(stages)}: {detail}"
                self.tracker.log(f"[cyan]hashcat[/] {label}", tag=self.name)
                self.status("crack", label, started=started, wordlist=detail)
                self.tracker.refresh()

                def on_progress(progress: CrackProgress, _detail=detail) -> None:
                    self.status(
                        "crack",
                        f"{_detail} — {Hashcat.format_progress(progress)}",
                        started=started,
                        progress_pct=round(progress.percent, 1),
                        speed=progress.speed,
                        eta=progress.eta_seconds,
                        candidate=progress.candidate,
                        words_done=progress.current,
                        words_total=progress.total,
                        wordlist=_detail,
                    )

                key = Hashcat.crack_hash(
                    hash_line,
                    wl_path,
                    self.ap.crack_use_wpa3,
                    rules=rules,
                    on_progress=on_progress,
                    should_stop=self.should_stop,
                )
                if key:
                    return key
                if idx < len(stages):
                    self.tracker.log(
                        f"[yellow]{detail}[/] exhausted — next crack stage",
                        tag=self.name,
                    )
            return None
        finally:
            for path in cleanup:
                try:
                    os.remove(path)
                except OSError:
                    pass

    @abstractmethod
    def can_attack(self) -> bool:
        ...

    @abstractmethod
    def run(self) -> AttackResult:
        ...