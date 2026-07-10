"""Durable hashcat crack checkpoints (survive wiflux / system restarts)."""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from ..models import AccessPoint
from .crack_ladder import CrackStage

CHECKPOINT_ROOT = "crack_checkpoints"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def bssid_key(bssid: str) -> str:
    return re.sub(r"[^0-9A-Fa-f]", "", bssid).upper()


def checkpoint_root(data_dir: str) -> Path:
    path = Path(data_dir) / CHECKPOINT_ROOT
    path.mkdir(parents=True, exist_ok=True)
    return path


def job_dir(data_dir: str, bssid: str) -> Path:
    path = checkpoint_root(data_dir) / bssid_key(bssid)
    path.mkdir(parents=True, exist_ok=True)
    return path


@dataclass
class StageCheckpoint:
    index: int
    label: str
    wordlist: str
    rules: Optional[str]
    session: str
    restore_path: str
    status: str = "pending"  # pending | running | exhausted | skipped | cracked
    progress_pct: float = 0.0
    words_done: int = 0
    words_total: int = 0

    def to_crack_stage(self) -> CrackStage:
        return CrackStage(
            wordlist=self.wordlist,
            label=self.label,
            rules=self.rules,
            candidates=self.words_total,
        )


@dataclass
class CrackCheckpoint:
    bssid: str
    essid: str
    method: str
    hash_line: str
    hash_file: str
    wpa3: bool
    stage_index: int
    stages: list[StageCheckpoint] = field(default_factory=list)
    capture_file: str = ""
    potfile: str = ""
    created_at: str = ""
    updated_at: str = ""
    data_dir: str = ""

    def is_resumable(self) -> bool:
        if not self.hash_line or not self.stages:
            return False
        if not self.hash_file or not os.path.isfile(self.hash_file):
            return False
        if self.stage_index < 0 or self.stage_index >= len(self.stages):
            return False
        # Need at least one unfinished stage with a usable wordlist.
        for stage in self.stages[self.stage_index :]:
            if stage.status in ("cracked",):
                return False
            if stage.status in ("exhausted", "skipped"):
                continue
            if stage.wordlist and os.path.isfile(stage.wordlist):
                return True
        return False

    def current_stage(self) -> StageCheckpoint | None:
        if 0 <= self.stage_index < len(self.stages):
            return self.stages[self.stage_index]
        return None

    def summary_lines(self) -> list[str]:
        stage = self.current_stage()
        total = len(self.stages)
        idx = self.stage_index + 1 if stage else 0
        lines = [
            f"Network: {self.essid or '(unknown)'}  ({self.bssid})",
            f"Method: {self.method or 'crack'}  |  WPA3: {'yes' if self.wpa3 else 'no'}",
            f"Stage: {idx}/{total}" + (f" — {stage.label}" if stage else ""),
        ]
        if stage and stage.progress_pct > 0:
            lines.append(
                f"Progress: {stage.progress_pct:.1f}%"
                + (
                    f"  ({stage.words_done:,}/{stage.words_total:,})"
                    if stage.words_total
                    else ""
                )
            )
        if self.updated_at:
            lines.append(f"Last saved: {self.updated_at}")
        restore = stage and stage.restore_path and os.path.isfile(stage.restore_path)
        if restore:
            lines.append("Hashcat restore file: present (will continue mid-stage)")
        elif stage:
            lines.append("Hashcat restore file: none (restart this stage from the beginning)")
        return lines

    def to_dict(self) -> dict[str, Any]:
        return {
            "bssid": self.bssid,
            "essid": self.essid,
            "method": self.method,
            "hash_line": self.hash_line,
            "hash_file": self.hash_file,
            "wpa3": self.wpa3,
            "stage_index": self.stage_index,
            "stages": [asdict(s) for s in self.stages],
            "capture_file": self.capture_file,
            "potfile": self.potfile,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "data_dir": self.data_dir,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CrackCheckpoint:
        stages = [StageCheckpoint(**s) for s in data.get("stages") or []]
        return cls(
            bssid=data.get("bssid") or "",
            essid=data.get("essid") or "",
            method=data.get("method") or "",
            hash_line=data.get("hash_line") or "",
            hash_file=data.get("hash_file") or "",
            wpa3=bool(data.get("wpa3")),
            stage_index=int(data.get("stage_index") or 0),
            stages=stages,
            capture_file=data.get("capture_file") or "",
            potfile=data.get("potfile") or "",
            created_at=data.get("created_at") or "",
            updated_at=data.get("updated_at") or "",
            data_dir=data.get("data_dir") or "",
        )


def meta_path(data_dir: str, bssid: str) -> Path:
    return job_dir(data_dir, bssid) / "meta.json"


def load_checkpoint(data_dir: str, bssid: str) -> CrackCheckpoint | None:
    path = meta_path(data_dir, bssid)
    if not path.is_file():
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        cp = CrackCheckpoint.from_dict(data)
        cp.data_dir = data_dir
        return cp
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return None


def save_checkpoint(cp: CrackCheckpoint) -> None:
    cp.updated_at = _utc_now()
    if not cp.created_at:
        cp.created_at = cp.updated_at
    path = meta_path(cp.data_dir, cp.bssid)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(cp.to_dict(), fh, indent=2)
        fh.write("\n")
    os.replace(tmp, path)


def delete_checkpoint(data_dir: str, bssid: str) -> None:
    root = job_dir(data_dir, bssid)
    if not root.is_dir():
        return
    shutil.rmtree(root, ignore_errors=True)


def _session_name(bssid: str, stage_index: int) -> str:
    return f"wiflux_{bssid_key(bssid)}_s{stage_index}"


def _copy_if_needed(src: str, dest: Path) -> str:
    """Ensure wordlist lives under the job dir when it would otherwise vanish."""
    if not src or not os.path.isfile(src):
        return src
    src_abs = os.path.abspath(src)
    dest_abs = os.path.abspath(str(dest))
    if src_abs == dest_abs:
        return src_abs
    # Already under job directory
    if src_abs.startswith(os.path.abspath(str(dest.parent)) + os.sep):
        return src_abs
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_abs, dest_abs)
    return dest_abs


def create_checkpoint(
    ap: AccessPoint,
    data_dir: str,
    hash_line: str,
    stages: list[CrackStage],
    *,
    method: str,
    capture_file: str = "",
    wpa3: bool | None = None,
) -> CrackCheckpoint:
    """Create a durable job directory from in-memory crack stages."""
    # Wipe any prior job for this BSSID so restore files cannot mix sessions.
    delete_checkpoint(data_dir, ap.bssid)
    root = job_dir(data_dir, ap.bssid)

    hash_file = root / "hash.22000"
    with open(hash_file, "w", encoding="utf-8") as fh:
        fh.write(hash_line.strip() + "\n")

    potfile = root / "hashcat.potfile"
    potfile.touch(exist_ok=True)

    stage_rows: list[StageCheckpoint] = []
    for i, stage in enumerate(stages):
        wl_name = f"stage{i:02d}_wordlist.txt"
        # Stable system dictionaries stay as absolute paths (rockyou etc.).
        src = stage.wordlist
        if src and os.path.isfile(src):
            # Copy anything under /tmp or previous checkpoint temps; keep system paths.
            if src.startswith(tempfile_prefixes()) or "wiflux_smart_" in os.path.basename(src) \
                    or "wiflux_vendor_" in os.path.basename(src) \
                    or Path(src).parent == root:
                durable_wl = _copy_if_needed(src, root / wl_name)
            else:
                # Still copy small lists; leave large system lists in place.
                try:
                    size = os.path.getsize(src)
                except OSError:
                    size = 0
                if size and size < 2_000_000:
                    durable_wl = _copy_if_needed(src, root / wl_name)
                else:
                    durable_wl = os.path.abspath(src)
        else:
            durable_wl = src

        rules = stage.rules
        if rules and os.path.isfile(rules):
            rules = os.path.abspath(rules)
        else:
            rules = None

        stage_rows.append(StageCheckpoint(
            index=i,
            label=stage.label,
            wordlist=durable_wl,
            rules=rules,
            session=_session_name(ap.bssid, i),
            restore_path=str(root / f"stage{i:02d}.restore"),
            status="pending",
            words_total=stage.candidates or 0,
        ))

    cp = CrackCheckpoint(
        bssid=ap.bssid,
        essid=ap.display_name,
        method=method,
        hash_line=hash_line.strip(),
        hash_file=str(hash_file),
        wpa3=bool(ap.crack_use_wpa3 if wpa3 is None else wpa3),
        stage_index=0,
        stages=stage_rows,
        capture_file=capture_file or "",
        potfile=str(potfile),
        created_at=_utc_now(),
        updated_at=_utc_now(),
        data_dir=data_dir,
    )
    save_checkpoint(cp)
    return cp


def tempfile_prefixes() -> tuple[str, ...]:
    return (
        "/tmp/",
        "/var/tmp/",
        os.path.join(os.environ.get("TMPDIR", "/tmp"), ""),
    )


def stages_from_checkpoint(cp: CrackCheckpoint) -> list[CrackStage]:
    return [s.to_crack_stage() for s in cp.stages]


def mark_stage_running(cp: CrackCheckpoint, index: int) -> None:
    cp.stage_index = index
    if 0 <= index < len(cp.stages):
        cp.stages[index].status = "running"
    save_checkpoint(cp)


def mark_stage_done(cp: CrackCheckpoint, index: int, status: str) -> None:
    if 0 <= index < len(cp.stages):
        cp.stages[index].status = status
        restore = cp.stages[index].restore_path
        if status in ("exhausted", "skipped", "cracked") and restore:
            try:
                os.remove(restore)
            except OSError:
                pass
    if status in ("exhausted", "skipped"):
        cp.stage_index = index + 1
    save_checkpoint(cp)


def update_stage_progress(
    cp: CrackCheckpoint,
    index: int,
    *,
    progress_pct: float = 0.0,
    words_done: int = 0,
    words_total: int = 0,
) -> None:
    if not (0 <= index < len(cp.stages)):
        return
    stage = cp.stages[index]
    new_pct = float(progress_pct or 0.0)
    prev_pct = float(stage.progress_pct or 0.0)
    totals_changed = (
        (words_total and words_total != stage.words_total)
        or (words_done and words_done != stage.words_done)
    )
    stage.progress_pct = new_pct
    if words_done:
        stage.words_done = int(words_done)
    if words_total:
        stage.words_total = int(words_total)
    # Throttle disk writes: ≥1% progress move or totals change.
    if totals_changed or abs(new_pct - prev_pct) >= 1.0 or new_pct >= 100.0:
        save_checkpoint(cp)
