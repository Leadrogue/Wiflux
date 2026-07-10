"""Hashcat and hcxtools integration."""

from __future__ import annotations

import json
import os
import re
import select
import signal
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from ..models import AccessPoint
from ..process import ManagedProcess, ProcessPool, run, which


def hcx_channel(channel: int, band: str | None = None) -> str:
    """Format channel for hcxdumptool 7.x (e.g. 11a, 44b, 37c)."""
    from .radio import hcx_channel as _hcx_channel
    return _hcx_channel(channel, band=band)


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
        *,
        prefer_wpa2: bool = False,
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
                on_log(
                    f"hcxdumptool -c {hcx_channel(ap.channel, band=ap.radio_band)} "
                    f"→ {os.path.basename(outfile)}",
                )

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
                        hash_val = HcxTools._extract_pmkid(
                            outfile,
                            ap,
                            prefer_wpa2=prefer_wpa2,
                        )
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
            return HcxTools._extract_pmkid(outfile, ap, prefer_wpa2=prefer_wpa2)
        return None

    @staticmethod
    def _build_hcxdump_cmd(interface: str, outfile: str, ap: AccessPoint, bpf_file: str) -> list[str]:
        """Build command for hcxdumptool 7.x."""
        return [
            "hcxdumptool",
            "-i", interface,
            "-w", outfile,
            "-c", hcx_channel(ap.channel, band=ap.radio_band),
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
    def _extract_pmkid(
        pcapng: str,
        ap: AccessPoint,
        *,
        prefer_wpa2: bool = False,
    ) -> str | None:
        from .transition import select_hash_line

        if not os.path.exists(pcapng) or os.path.getsize(pcapng) < 24:
            return None
        tmp_hash = pcapng + ".22000"
        if os.path.exists(tmp_hash):
            os.remove(tmp_hash)
        _, _, code = run(["hcxpcapngtool", "-o", tmp_hash, pcapng], timeout=30)
        if code != 0 or not os.path.exists(tmp_hash) or os.path.getsize(tmp_hash) == 0:
            return None
        bssid_target = ap.bssid.replace(":", "").lower()
        pairs: list[tuple[str, str]] = []
        with open(tmp_hash) as f:
            for line in f:
                line = line.strip()
                if not line.startswith("WPA*"):
                    continue
                parts = line.split("*")
                if len(parts) >= 4 and parts[3].lower().replace(":", "") == bssid_target:
                    mac = parts[3]
                    if len(mac) == 12 and ":" not in mac:
                        mac = ":".join(mac[i:i + 2] for i in range(0, 12, 2)).upper()
                    pairs.append((mac.upper(), line))
        picked = select_hash_line(
            pairs,
            prefer_wpa2=prefer_wpa2,
            allow_wpa3_fallback=True,
        )
        return picked[1] if picked else None

    @staticmethod
    def cap_to_hash(capfile: str, bssid: str, essid: str | None) -> str | None:
        from .handshake_detect import extract_hash
        return extract_hash(capfile, bssid)


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


PASS_TIMEOUT = 3600
_benchmark_cache: dict[str, int] = {}
_device_info_cache: list[dict] | None = None


def list_hashcat_devices(*, refresh: bool = False) -> list[dict]:
    """
    Parse ``hashcat -I`` into device dicts:

    ``{"id": "1", "type": "GPU"|"CPU"|..., "name": "..."}``
    """
    global _device_info_cache
    if _device_info_cache is not None and not refresh:
        return list(_device_info_cache)
    if not which("hashcat"):
        _device_info_cache = []
        return []
    stdout, _, code = run(["hashcat", "-I"], timeout=60)
    devices: list[dict] = []
    current_id: str | None = None
    current_type = ""
    current_name = ""
    for line in (stdout or "").splitlines():
        m_id = re.search(r"Backend Device ID\s*#\s*0*(\d+)", line, re.I)
        if m_id:
            if current_id is not None:
                devices.append({
                    "id": current_id,
                    "type": (current_type or "Unknown").upper(),
                    "name": current_name or f"Device {current_id}",
                })
            current_id = m_id.group(1)
            current_type = ""
            current_name = ""
            continue
        m_type = re.search(r"Type\.+:\s*(\w+)", line, re.I)
        if m_type and current_id is not None:
            current_type = m_type.group(1)
            continue
        m_name = re.search(r"Name\.+:\s*(.+)", line, re.I)
        if m_name and current_id is not None:
            current_name = m_name.group(1).strip()
            continue
    if current_id is not None:
        devices.append({
            "id": current_id,
            "type": (current_type or "Unknown").upper(),
            "name": current_name or f"Device {current_id}",
        })
    _device_info_cache = devices
    return list(devices)


def hashcat_backend_args(
    *,
    backend: str = "auto",
    devices: str = "",
    workload: int = 3,
    force: bool = True,
) -> tuple[list[str], str]:
    """
    Build hashcat device / workload CLI flags.

    Returns ``(args, human_summary)`` e.g. ``(["-D", "2", "-w", "3"], "GPU only")``.
    """
    args: list[str] = []
    summary = "default devices"
    backend = (backend or "auto").strip().lower()
    devices = (devices or "").strip()

    infos = list_hashcat_devices()
    gpu_ids = [d["id"] for d in infos if "GPU" in d.get("type", "")]
    cpu_ids = [d["id"] for d in infos if "CPU" in d.get("type", "")]

    if devices:
        args.extend(["-d", devices])
        summary = f"devices -d {devices}"
    elif backend == "gpu":
        # Prefer concrete GPU IDs from hashcat -I; else OpenCL type 2 = GPU.
        if gpu_ids:
            args.extend(["-d", ",".join(gpu_ids)])
            names = ", ".join(d["name"] for d in infos if d["id"] in gpu_ids)
            summary = f"GPU ({names or ','.join(gpu_ids)})"
        else:
            args.extend(["-D", "2"])
            summary = "GPU only (-D 2; none listed by hashcat -I)"
    elif backend == "cpu":
        if cpu_ids:
            args.extend(["-d", ",".join(cpu_ids)])
            summary = f"CPU ({','.join(cpu_ids)})"
        else:
            args.extend(["-D", "1"])
            summary = "CPU only (-D 1)"
    elif backend == "all":
        summary = "all devices"
    else:
        # auto: prefer GPU when present, else CPU
        if gpu_ids:
            args.extend(["-d", ",".join(gpu_ids)])
            names = ", ".join(d["name"] for d in infos if d["id"] in gpu_ids)
            summary = f"auto GPU ({names or ','.join(gpu_ids)})"
        elif cpu_ids:
            args.extend(["-d", ",".join(cpu_ids)])
            summary = "auto CPU (no GPU detected)"
        else:
            summary = "auto (hashcat default devices)"

    wl = workload if 1 <= int(workload or 0) <= 4 else 3
    args.extend(["-w", str(wl)])
    if force:
        args.append("--force")
    return args, summary


class Hashcat:
    @staticmethod
    def backend_args_from_cfg(cfg=None) -> tuple[list[str], str]:
        """Resolve device flags from WifluxConfig.attack (or defaults)."""
        backend = "auto"
        devices = ""
        workload = 3
        force = True
        if cfg is not None:
            attack = getattr(cfg, "attack", cfg)
            backend = getattr(attack, "hashcat_backend", "auto") or "auto"
            devices = getattr(attack, "hashcat_devices", "") or ""
            workload = int(getattr(attack, "hashcat_workload", 3) or 3)
            force = bool(getattr(attack, "hashcat_force", True))
        return hashcat_backend_args(
            backend=backend, devices=devices, workload=workload, force=force,
        )

    @staticmethod
    def benchmark_wpa_speed(wpa3: bool = False, cfg=None) -> int:
        """Return cached WPA hash rate (H/s) from hashcat -b, or 0 if unavailable."""
        mode = "22001" if wpa3 else "22000"
        backend_args, _ = Hashcat.backend_args_from_cfg(cfg)
        cache_key = f"{mode}:{','.join(backend_args)}"
        if cache_key in _benchmark_cache:
            return _benchmark_cache[cache_key]
        if not which("hashcat"):
            return 0
        cmd = ["hashcat", "-b", "-m", mode, *backend_args]
        stdout, _, code = run(cmd, timeout=120)
        if code != 0:
            return 0
        speed = 0
        for line in stdout.splitlines():
            match = re.search(
                r"Speed\.#\d+\.+:\s+([\d.]+)\s+([kMG]?H/s)",
                line,
            )
            if not match:
                continue
            val = float(match.group(1))
            unit = match.group(2)
            if unit.startswith("M"):
                speed = int(val * 1_000_000)
            elif unit.startswith("k"):
                speed = int(val * 1_000)
            else:
                speed = int(val)
            break
        _benchmark_cache[cache_key] = speed
        return speed

    @staticmethod
    def crack_hash(
        hash_line: str,
        wordlist: str,
        wpa3: bool = False,
        *,
        rules: str | None = None,
        on_progress: Optional[Callable[[CrackProgress], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
        session: str | None = None,
        restore: bool = False,
        restore_file_path: str | None = None,
        hash_file: str | None = None,
        potfile_path: str | None = None,
        keep_hash_file: bool = False,
        cfg=None,
        backend_args: list[str] | None = None,
    ) -> str | None:
        if not which("hashcat") or not wordlist or not os.path.isfile(wordlist):
            return None

        owns_hash_file = False
        if hash_file:
            # Ensure durable hash file has current line when provided.
            try:
                with open(hash_file, "w", encoding="utf-8") as fh:
                    fh.write(hash_line.strip() + "\n")
            except OSError:
                return None
        else:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".22000", delete=False) as f:
                f.write(hash_line.strip() + "\n")
                hash_file = f.name
            owns_hash_file = True

        reader: _WordlistReader | None = None
        proc: subprocess.Popen | None = None
        try:
            mode = "22001" if wpa3 else "22000"
            if backend_args is None:
                backend_args, _ = Hashcat.backend_args_from_cfg(cfg)
            use_restore = bool(
                restore
                and session
                and restore_file_path
                and os.path.isfile(restore_file_path)
                and os.path.getsize(restore_file_path) > 0
            )
            if use_restore:
                # Restore mode reloads attack state from the restore file.
                cmd = [
                    "hashcat",
                    "--session", session,
                    "--restore",
                    "--restore-file-path", restore_file_path,
                    *backend_args,
                    "--status", "--status-json", "--status-timer=1",
                ]
            else:
                cmd = [
                    "hashcat", "-m", mode, hash_file, wordlist,
                    *backend_args,
                    "--status", "--status-json", "--status-timer=1",
                ]
                if session:
                    cmd.extend(["--session", session])
                if restore_file_path:
                    cmd.extend(["--restore-file-path", restore_file_path])
                if rules and os.path.isfile(rules):
                    cmd.extend(["-r", rules])
            if potfile_path:
                cmd.extend(["--potfile-path", potfile_path])

            popen_kwargs: dict = {"stdout": subprocess.PIPE, "stderr": subprocess.STDOUT}
            if on_progress:
                popen_kwargs.update(text=True, encoding="utf-8", errors="replace", bufsize=1)
            else:
                popen_kwargs["stdout"] = subprocess.DEVNULL
                popen_kwargs["stderr"] = subprocess.DEVNULL

            proc = subprocess.Popen(cmd, **popen_kwargs)
            # Prefer SIGINT so hashcat writes a restore checkpoint before exit.
            hc_proc = _HashcatProcess(proc, graceful_interrupt=bool(session or restore_file_path))
            ProcessPool().register(hc_proc)
            deadline = time.time() + PASS_TIMEOUT

            try:
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
                            # With -r rules, restore_point is a global candidate index
                            # (wordlist × rules), not a wordlist line — do not seek.
                            if rules:
                                candidate = os.path.basename(rules)
                            else:
                                pos = int(data.get("restore_point") or current or 0)
                                if pos < 500_000:
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
                            if time.time() >= deadline:
                                hc_proc.kill()
                                break
                            if should_stop and should_stop():
                                hc_proc.kill()
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

                if proc.poll() is None:
                    remaining = max(1.0, deadline - time.time())
                    try:
                        proc.wait(timeout=remaining)
                    except subprocess.TimeoutExpired:
                        hc_proc.kill()
                return Hashcat._read_cracked_key(mode, hash_file, potfile_path=potfile_path)
            finally:
                ProcessPool().unregister(hc_proc)
        except subprocess.TimeoutExpired:
            if proc:
                wrapper = _HashcatProcess(
                    proc, graceful_interrupt=bool(session or restore_file_path),
                )
                wrapper.kill()
            return None
        finally:
            if reader:
                reader.close()
            if owns_hash_file and hash_file and not keep_hash_file:
                try:
                    os.unlink(hash_file)
                except OSError:
                    pass

    @staticmethod
    def _read_cracked_key(
        mode: str,
        hash_file: str,
        *,
        potfile_path: str | None = None,
    ) -> str | None:
        cmd = ["hashcat", "-m", mode, hash_file, "--show"]
        if potfile_path:
            cmd.extend(["--potfile-path", potfile_path])
        stdout, _, _ = run(cmd)
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
        from .handshake_detect import check_handshake as detect_handshake
        return detect_handshake(capfile, bssid, essid)


class _HashcatProcess:
    """Thin wrapper so ProcessPool can terminate hashcat."""

    def __init__(self, proc: subprocess.Popen, *, graceful_interrupt: bool = False):
        self.proc = proc
        self.graceful_interrupt = graceful_interrupt

    def running(self) -> bool:
        return self.proc.poll() is None

    def kill(self) -> None:
        if self.running():
            # SIGINT makes hashcat write a restore checkpoint (Ctrl+C path).
            if self.graceful_interrupt:
                try:
                    self.proc.send_signal(signal.SIGINT)
                    self.proc.wait(timeout=5)
                except Exception:
                    pass
            if self.running():
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
        ProcessPool().unregister(self)