"""Hashcat and hcxtools integration."""

from __future__ import annotations

import json
import os
import re
import select
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..models import AccessPoint
from ..process import ManagedProcess, ProcessPool, run, which


def hcx_channel(channel: int) -> str:
    """Format channel for hcxdumptool 7.x (e.g. 6a, 36b)."""
    band = "a" if channel <= 14 else "b"
    return f"{channel}{band}"


class HcxTools:
    @staticmethod
    def capture_pmkid(
        ap: AccessPoint,
        interface: str,
        outfile: str,
        timeout: int,
        on_tick: Optional[Callable[[float, int], None]] = None,
        on_log: Optional[Callable[[str], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> str | None:
        if not which("hcxdumptool") or not which("hcxpcapngtool"):
            if on_log:
                on_log("hcxdumptool or hcxpcapngtool not found")
            return None

        if os.path.exists(outfile):
            os.remove(outfile)

        bpf_file = None
        try:
            bpf_file = HcxTools._write_bpf_filter(ap.bssid)
            cmd = HcxTools._build_hcxdump_cmd(interface, outfile, ap, bpf_file)
            if on_log:
                on_log(f"hcxdumptool -c {hcx_channel(ap.channel)} → {os.path.basename(outfile)}")

            start = time.time()
            proc = ManagedProcess(cmd)
            last_extract = 0.0
            try:
                deadline = time.time() + timeout
                while proc.running() and time.time() < deadline:
                    if should_stop and should_stop():
                        proc.kill()
                        return None
                    elapsed = time.time() - start
                    pcap_kb = os.path.getsize(outfile) // 1024 if os.path.exists(outfile) else 0
                    if on_tick:
                        on_tick(elapsed, pcap_kb)

                    # Don't run hcxpcapngtool every 0.5s — it slows capture and blows past timeout
                    now = time.time()
                    if now - last_extract >= 3.0:
                        last_extract = now
                        hash_val = HcxTools._extract_pmkid(outfile, ap)
                        if hash_val:
                            proc.kill()
                            return hash_val

                    time.sleep(0.5)

                if not proc.running() and on_log:
                    on_log(f"hcxdumptool exited early (code {proc.poll()})")
            finally:
                proc.kill()
        finally:
            if bpf_file and os.path.exists(bpf_file):
                os.unlink(bpf_file)

        if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
            return HcxTools._extract_pmkid(outfile, ap)
        return None

    @staticmethod
    def _build_hcxdump_cmd(interface: str, outfile: str, ap: AccessPoint, bpf_file: str) -> list[str]:
        """Build command for hcxdumptool 7.x."""
        return [
            "hcxdumptool",
            "-i", interface,
            "-w", outfile,
            "-c", hcx_channel(ap.channel),
            f"--bpf={bpf_file}",
            "--exitoneapol=1",
            "-t", "2",
        ]

    @staticmethod
    def _write_bpf_filter(bssid: str) -> str:
        bpf_out, _, code = run(
            ["hcxdumptool", f"--bpfc=wlan addr3 {bssid}"],
            timeout=10,
        )
        if code != 0 or not bpf_out.strip():
            # Fallback: capture on channel only
            bpf_out, _, _ = run(
                ["hcxdumptool", f"--bpfc=wlan type mgt subtype beacon"],
                timeout=10,
            )
        path = tempfile.mktemp(suffix=".bpf", prefix="wiflux_")
        with open(path, "w") as f:
            f.write(bpf_out)
        return path

    @staticmethod
    def _extract_pmkid(pcapng: str, ap: AccessPoint) -> str | None:
        if not os.path.exists(pcapng) or os.path.getsize(pcapng) < 24:
            return None
        tmp_hash = pcapng + ".22000"
        if os.path.exists(tmp_hash):
            os.remove(tmp_hash)
        _, stderr, code = run(["hcxpcapngtool", "-o", tmp_hash, pcapng], timeout=30)
        if not os.path.exists(tmp_hash) or os.path.getsize(tmp_hash) == 0:
            return None
        bssid_target = ap.bssid.replace(":", "").lower()
        with open(tmp_hash) as f:
            for line in f:
                line = line.strip()
                if not line.startswith("WPA*"):
                    continue
                parts = line.split("*")
                if len(parts) >= 4 and parts[3].lower().replace(":", "") == bssid_target:
                    return line
        return None

    @staticmethod
    def cap_to_hash(capfile: str, bssid: str, essid: str | None) -> str | None:
        if not which("hcxpcapngtool"):
            return None
        out = capfile + ".22000"
        if os.path.exists(out):
            os.remove(out)
        run(["hcxpcapngtool", "-o", out, capfile], timeout=60)
        if not os.path.exists(out):
            return None
        bssid_target = bssid.replace(":", "").lower()
        with open(out) as f:
            for line in f:
                if bssid_target in line.replace(":", "").lower():
                    return line.strip()
        return None


@dataclass
class CrackProgress:
    current: int = 0
    total: int = 0
    percent: float = 0.0
    speed: int = 0
    eta_seconds: int = 0
    candidate: str = ""
    wordlist: str = ""


class _WordlistReader:
    """Read forward through a wordlist to resolve hashcat restore points."""

    def __init__(self, path: str):
        self._path = path
        self._fh = open(path, "rb")
        self._line = 0

    def get_line(self, index: int) -> str:
        if index <= 0:
            return ""
        if index < self._line:
            self._fh.seek(0)
            self._line = 0
        while self._line < index:
            self._fh.readline()
            self._line += 1
        raw = self._fh.readline()
        return raw.decode("utf-8", errors="replace").strip()

    def close(self) -> None:
        self._fh.close()


class Hashcat:
    @staticmethod
    def crack_hash(
        hash_line: str,
        wordlist: str,
        wpa3: bool = False,
        *,
        on_progress: Optional[Callable[[CrackProgress], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> str | None:
        if not which("hashcat") or not wordlist or not os.path.isfile(wordlist):
            return None

        with tempfile.NamedTemporaryFile(mode="w", suffix=".22000", delete=False) as f:
            f.write(hash_line + "\n")
            hash_file = f.name

        reader: _WordlistReader | None = None
        proc: subprocess.Popen | None = None
        try:
            mode = "22001" if wpa3 else "22000"
            cmd = [
                "hashcat", "-m", mode, hash_file, wordlist,
                "--force", "-w", "3",
                "--status", "--status-json", "--status-timer=1",
            ]
            popen_kwargs: dict = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT}
            if on_progress:
                popen_kwargs.update(text=True, encoding="utf-8", errors="replace", bufsize=1)
            else:
                popen_kwargs["stdout"] = subprocess.DEVNULL
                popen_kwargs["stderr"] = subprocess.DEVNULL

            proc = subprocess.Popen(cmd, **popen_kwargs)
            hc_proc = _HashcatProcess(proc)
            ProcessPool().register(hc_proc)

            if on_progress:
                reader = _WordlistReader(wordlist)
                wl_name = os.path.basename(wordlist)
                last_candidate_at = 0.0

                on_progress(CrackProgress(wordlist=wl_name, candidate="starting..."))

                def emit(data: dict) -> None:
                    nonlocal last_candidate_at
                    prog = data.get("progress") or [0, 0]
                    current, total = int(prog[0]), int(prog[1])
                    percent = (current / total * 100.0) if total else 0.0
                    speed = 0
                    devices = data.get("devices") or []
                    if devices:
                        speed = int(devices[0].get("speed") or 0)

                    eta = 0
                    est_stop = int(data.get("estimated_stop") or 0)
                    if est_stop:
                        eta = max(0, est_stop - int(time.time()))
                    elif total > current and speed > 0:
                        eta = int((total - current) / speed)

                    candidate = ""
                    now = time.time()
                    if now - last_candidate_at >= 1.0:
                        pos = int(data.get("restore_point") or current or 0)
                        candidate = reader.get_line(pos)[:40]
                        last_candidate_at = now

                    on_progress(CrackProgress(
                        current=current,
                        total=total,
                        percent=percent,
                        speed=speed,
                        eta_seconds=eta,
                        candidate=candidate,
                        wordlist=wl_name,
                    ))

                if proc.stdout:
                    while proc.poll() is None:
                        if should_stop and should_stop():
                            _HashcatProcess(proc).kill()
                            return None
                        ready, _, _ = select.select([proc.stdout], [], [], 0.5)
                        if not ready:
                            continue
                        line = proc.stdout.readline()
                        if not line:
                            break
                        match = re.search(r"\{.*\}", line)
                        if not match:
                            continue
                        try:
                            emit(json.loads(match.group()))
                        except json.JSONDecodeError:
                            continue

            proc.wait(timeout=3600)
            return Hashcat._read_cracked_key(mode, hash_file)
        except subprocess.TimeoutExpired:
            if proc:
                _HashcatProcess(proc).kill()
            return None
        finally:
            if reader:
                reader.close()
            os.unlink(hash_file)

    @staticmethod
    def _read_cracked_key(mode: str, hash_file: str) -> str | None:
        stdout, _, _ = run(["hashcat", "-m", mode, hash_file, "--show"])
        for line in stdout.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 2:
                return parts[-1]
        return None

    @staticmethod
    def format_progress(p: CrackProgress) -> str:
        bar = Hashcat._progress_bar(p.percent, width=18)
        words = Hashcat._fmt_words(p.current, p.total)
        speed = Hashcat._fmt_speed(p.speed)
        eta = Hashcat._fmt_eta(p.eta_seconds)
        wl = p.wordlist or "wordlist"

        parts = [f"{bar} [cyan]{p.percent:5.1f}%[/]"]
        if p.candidate:
            shown = p.candidate.replace("[", "\\[")
            parts.append(f'[yellow]"{shown}"[/]')
        parts.append(f"[dim]{words}[/]")
        parts.append(f"[green]{speed}[/]")
        parts.append(f"[magenta]ETA {eta}[/]")
        parts.append(f"[dim]({wl})[/]")
        return "  ".join(parts)

    @staticmethod
    def _progress_bar(percent: float, width: int = 18) -> str:
        pct = max(0.0, min(100.0, percent))
        filled = int(width * pct / 100)
        return f"[cyan]{'█' * filled}{'░' * (width - filled)}[/]"

    @staticmethod
    def _fmt_words(current: int, total: int) -> str:
        if total <= 0:
            return "counting..."
        return f"{Hashcat._fmt_num(current)}/{Hashcat._fmt_num(total)}"

    @staticmethod
    def _fmt_num(n: int) -> str:
        if n >= 1_000_000:
            return f"{n / 1_000_000:.1f}M"
        if n >= 1_000:
            return f"{n / 1_000:.1f}k"
        return str(n)

    @staticmethod
    def _fmt_speed(hps: int) -> str:
        if hps >= 1_000_000:
            return f"{hps / 1_000_000:.1f} MH/s"
        if hps >= 1_000:
            return f"{hps / 1_000:.1f} kH/s"
        return f"{hps} H/s"

    @staticmethod
    def _fmt_eta(seconds: int) -> str:
        if seconds <= 0:
            return "—"
        if seconds < 60:
            return f"{seconds}s"
        if seconds < 3600:
            return f"{seconds // 60}m{seconds % 60:02d}s"
        return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"

    @staticmethod
    def check_handshake(capfile: str, bssid: str, essid: str | None = None) -> bool:
        """Fast, non-fatal handshake check — must never raise or block capture for long."""
        if not os.path.exists(capfile) or os.path.getsize(capfile) < 64:
            return False

        bssid_target = bssid.replace(":", "").lower()

        if which("hcxpcapngtool"):
            tmp_hash = f"{capfile}.wiflux_hs_check.22000"
            try:
                if os.path.exists(tmp_hash):
                    os.remove(tmp_hash)
                run(["hcxpcapngtool", "-o", tmp_hash, capfile], timeout=8)
                if os.path.exists(tmp_hash) and os.path.getsize(tmp_hash) > 0:
                    with open(tmp_hash) as f:
                        for line in f:
                            parts = line.strip().split("*")
                            if len(parts) >= 4 and parts[3].lower().replace(":", "") == bssid_target:
                                return True
            except (subprocess.TimeoutExpired, OSError):
                pass
            finally:
                if os.path.exists(tmp_hash):
                    os.remove(tmp_hash)

        try:
            stdout, _, _ = run(["aircrack-ng", "-b", bssid, capfile], timeout=5)
            low = stdout.lower()
            return "1 handshake" in low or "wpa (1 handshake)" in low
        except (subprocess.TimeoutExpired, OSError):
            return False


class _HashcatProcess:
    """Thin wrapper so ProcessPool can terminate hashcat."""

    def __init__(self, proc: subprocess.Popen):
        self.proc = proc

    def running(self) -> bool:
        return self.proc.poll() is None

    def kill(self) -> None:
        if self.running():
            self.proc.terminate()
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        ProcessPool().unregister(self)