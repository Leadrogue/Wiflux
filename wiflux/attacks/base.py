"""Base attack class."""

from __future__ import annotations

import os
import time
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
            f"[cyan]hashcat[/] ESSID-smart wordlist "
            f"([yellow]{count:,}[/] passwords) — first crack stage",
            tag=self.name,
        )
        self.tracker.refresh()
        return path, path, f"smart:{count}"

    def crack_hashcat(
        self,
        hash_line: str,
        started: float,
        *,
        method: str = "crack",
        capture_file: str = "",
    ) -> str | None:
        from ..input import prompt_resume_crack
        from ..tools.crack_checkpoint import (
            create_checkpoint,
            delete_checkpoint,
            load_checkpoint,
            mark_stage_done,
            mark_stage_running,
            save_checkpoint,
            update_stage_progress,
        )
        from ..tools.crack_ladder import (
            build_crack_stages,
            enrich_stage_etas,
            format_crack_plan,
        )
        from ..tools.hashcat import CrackProgress, Hashcat

        use_ckpt = bool(getattr(self.cfg.attack, "crack_checkpoints", True))
        data_dir = self.cfg.output.data_dir
        wpa3 = self.ap.crack_use_wpa3
        cleanup: list[str] = []
        checkpoint = None
        resume = False
        start_idx = 0

        if use_ckpt:
            existing = load_checkpoint(data_dir, self.ap.bssid)
            if existing and existing.is_resumable():
                resume = prompt_resume_crack(
                    self.cfg,
                    existing,
                    self.tracker,
                )
                if resume:
                    checkpoint = existing
                    hash_line = existing.hash_line
                    # Password wordlists always use mode 22000 (never PMK 22001),
                    # even if an older checkpoint stored wpa3=True.
                    wpa3 = False
                    existing.wpa3 = False
                    start_idx = max(0, existing.stage_index)
                    stages = [s.to_crack_stage() for s in existing.stages]
                    self.tracker.log(
                        f"[green]Resuming crack checkpoint[/] — "
                        f"stage {start_idx + 1}/{len(stages)}",
                        tag="hashcat",
                    )
                else:
                    delete_checkpoint(data_dir, self.ap.bssid)
                    self.tracker.log(
                        "[yellow]Crack checkpoint discarded[/] — starting fresh",
                        tag="hashcat",
                    )

        if checkpoint is None:
            wordlist, temp_path, wl_label = self._resolve_crack_wordlist()
            if not wordlist:
                return None

            stages, cleanup = build_crack_stages(
                self.ap, self.cfg, wordlist, wl_label, temp_path,
            )
            if use_ckpt:
                checkpoint = create_checkpoint(
                    self.ap,
                    data_dir,
                    hash_line,
                    stages,
                    method=method,
                    capture_file=capture_file,
                    wpa3=wpa3,
                )
                stages = [s.to_crack_stage() for s in checkpoint.stages]
                # Temp smart/vendor lists are copied into the job dir; safe to remove.
                for path in cleanup:
                    try:
                        os.remove(path)
                    except OSError:
                        pass
                cleanup = []

        backend_args, backend_summary = Hashcat.backend_args_from_cfg(self.cfg)
        speed = Hashcat.benchmark_wpa_speed(wpa3, cfg=self.cfg)
        enrich_stage_etas(stages, speed)
        for line in format_crack_plan(stages, speed=speed):
            self.tracker.log(line, tag="hashcat")
        self.tracker.log(
            f"[cyan]hashcat[/] backend: [yellow]{backend_summary}[/]",
            tag="hashcat",
        )
        if use_ckpt and checkpoint:
            self.tracker.log(
                "[dim]Checkpoints enabled — progress survives restart "
                f"({data_dir}/crack_checkpoints/)[/]",
                tag="hashcat",
            )
        self.tracker.refresh()

        last_progress_save = 0.0

        try:
            for idx in range(start_idx, len(stages)):
                stage = stages[idx]
                wl_path, detail, rules = stage.wordlist, stage.label, stage.rules
                if self.should_stop():
                    if checkpoint:
                        save_checkpoint(checkpoint)
                        self.tracker.log(
                            "[yellow]Crack paused[/] — checkpoint saved for resume",
                            tag="hashcat",
                        )
                    return None
                self.tracker.clear_skip_pass()
                label = f"pass {idx + 1}/{len(stages)}: {detail}"
                if resume and idx == start_idx:
                    label += " [restore]"
                self.tracker.log(f"[cyan]hashcat[/] {label}", tag=self.name)
                self.status("crack", label, started=started, wordlist=detail)
                self.tracker.refresh()

                session = None
                restore_path = None
                hash_file = None
                potfile = None
                do_restore = False
                if checkpoint and idx < len(checkpoint.stages):
                    mark_stage_running(checkpoint, idx)
                    sc = checkpoint.stages[idx]
                    session = sc.session
                    restore_path = sc.restore_path
                    hash_file = checkpoint.hash_file
                    potfile = checkpoint.potfile
                    do_restore = (
                        os.path.isfile(restore_path)
                        and os.path.getsize(restore_path) > 0
                    )
                    if do_restore:
                        self.tracker.log(
                            f"[cyan]hashcat[/] restoring session "
                            f"[dim]{session}[/]",
                            tag=self.name,
                        )

                def on_progress(
                    progress: CrackProgress,
                    _detail=detail,
                    _idx=idx,
                ) -> None:
                    nonlocal last_progress_save
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
                    if checkpoint:
                        now = time.time()
                        # Persist progress every ~5s so restarts show last %.
                        if now - last_progress_save >= 5.0:
                            last_progress_save = now
                            update_stage_progress(
                                checkpoint,
                                _idx,
                                progress_pct=progress.percent,
                                words_done=progress.current,
                                words_total=progress.total,
                            )

                key = Hashcat.crack_hash(
                    hash_line,
                    wl_path,
                    wpa3,
                    rules=rules,
                    on_progress=on_progress,
                    should_stop=self.tracker.skip_pass_requested,
                    session=session,
                    restore=do_restore,
                    restore_file_path=restore_path,
                    hash_file=hash_file,
                    potfile_path=potfile,
                    keep_hash_file=bool(hash_file),
                    cfg=self.cfg,
                    backend_args=backend_args,
                )
                if key:
                    if checkpoint:
                        mark_stage_done(checkpoint, idx, "cracked")
                        delete_checkpoint(data_dir, self.ap.bssid)
                    return key
                if self.tracker.skip_pass_requested():
                    self.tracker.clear_skip_pass()
                    if checkpoint:
                        mark_stage_done(checkpoint, idx, "skipped")
                    if idx + 1 < len(stages):
                        self.tracker.log(
                            f"[yellow]{detail}[/] skipped — next crack stage",
                            tag=self.name,
                        )
                    continue
                if self.should_stop():
                    if checkpoint:
                        save_checkpoint(checkpoint)
                        self.tracker.log(
                            "[yellow]Crack paused[/] — checkpoint saved for resume",
                            tag="hashcat",
                        )
                    return None
                if checkpoint:
                    mark_stage_done(checkpoint, idx, "exhausted")
                if idx + 1 < len(stages):
                    self.tracker.log(
                        f"[yellow]{detail}[/] exhausted — next crack stage",
                        tag=self.name,
                    )
            # All stages finished without a key — drop checkpoint.
            if checkpoint:
                delete_checkpoint(data_dir, self.ap.bssid)
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