"""Subprocess management with reliable cleanup."""

from __future__ import annotations

import atexit
import os
import signal
import subprocess
import threading
from typing import Optional


class ProcessPool:
    _instance: Optional[ProcessPool] = None
    _lock = threading.Lock()

    def __new__(cls) -> ProcessPool:
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._procs: set[ManagedProcess] = set()
                atexit.register(cls._instance.cleanup_all)
            return cls._instance

    def register(self, proc: ManagedProcess) -> None:
        self._procs.add(proc)

    def unregister(self, proc: ManagedProcess) -> None:
        self._procs.discard(proc)

    def cleanup_all(self) -> None:
        for proc in list(self._procs):
            try:
                proc.kill()
            except Exception:
                pass
        self._procs.clear()


class ManagedProcess:
    def __init__(
        self,
        cmd: list[str] | str,
        *,
        cwd: Optional[str] = None,
        shell: bool = False,
        devnull: bool = True,
    ):
        self.cmd = cmd
        self.shell = shell or (isinstance(cmd, str) and " " in cmd)
        kwargs: dict = {"cwd": cwd}
        if devnull:
            kwargs["stdout"] = subprocess.DEVNULL
            kwargs["stderr"] = subprocess.DEVNULL
        self.proc = subprocess.Popen(
            cmd,
            shell=self.shell,
            preexec_fn=os.setsid if os.name != "nt" else None,
            **kwargs,
        )
        ProcessPool().register(self)

    def poll(self) -> Optional[int]:
        return self.proc.poll()

    def running(self) -> bool:
        return self.proc.poll() is None

    def wait(self, timeout: Optional[float] = None) -> int:
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.kill()
            return -1

    def kill(self) -> None:
        if not self.running():
            ProcessPool().unregister(self)
            return
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            else:
                self.proc.terminate()
            self.proc.wait(timeout=3)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                if os.name != "nt":
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                else:
                    self.proc.kill()
            except ProcessLookupError:
                pass
        ProcessPool().unregister(self)

    def __enter__(self) -> ManagedProcess:
        return self

    def __exit__(self, *_) -> None:
        self.kill()


def run(cmd: list[str] | str, *, shell: bool = False, timeout: int = 60) -> tuple[str, str, int]:
    """Run command and return (stdout, stderr, returncode)."""
    use_shell = shell or (isinstance(cmd, str) and " " in cmd)
    result = subprocess.run(
        cmd,
        shell=use_shell,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return result.stdout, result.stderr, result.returncode


def which(name: str) -> bool:
    _, _, code = run(["which", name])
    return code == 0