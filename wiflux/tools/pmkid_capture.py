"""Extended PMKID capture — passive dwell and multi-band rotation."""

from __future__ import annotations

import os
import time
from typing import Callable, Optional

from ..config import WifluxConfig
from ..models import AccessPoint
from .band_siblings import band_sibling_aps
from .hashcat import HcxTools
from .interface import recover_interface, set_channel


def capture_pmkid_extended(
    cfg: WifluxConfig,
    ap: AccessPoint,
    pool: list[AccessPoint],
    outfile: str,
    timeout: int,
    *,
    on_tick: Optional[Callable[[float, int], None]] = None,
    on_log: Optional[Callable[[str], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
    prefer_wpa2: bool = False,
) -> str | None:
    """Passive-first PMKID capture with optional band-sibling rotation."""
    passive_ratio = max(0.2, min(0.75, cfg.attack.pmkid_passive_ratio))
    passive_budget = max(30, int(timeout * passive_ratio))
    rotate = cfg.attack.pmkid_band_rotate

    if on_log:
        on_log(
            f"PMKID passive phase [yellow]{passive_budget}s[/] "
            f"({int(passive_ratio * 100)}% of timeout)",
        )

    hash_line = HcxTools.capture_pmkid(
        ap,
        cfg.scan.interface,
        outfile,
        passive_budget,
        on_tick=on_tick,
        on_log=on_log,
        should_stop=should_stop,
        prefer_wpa2=prefer_wpa2,
    )
    if hash_line or should_stop and should_stop():
        return hash_line

    if not rotate:
        remain = max(0, timeout - passive_budget)
        if remain < 15:
            return None
        return HcxTools.capture_pmkid(
            ap,
            cfg.scan.interface,
            outfile,
            remain,
            on_tick=on_tick,
            on_log=on_log,
            should_stop=should_stop,
            prefer_wpa2=prefer_wpa2,
        )

    siblings = band_sibling_aps(ap, pool)
    elapsed = passive_budget
    for sibling in siblings[:3]:
        if should_stop and should_stop():
            break
        remain_total = timeout - elapsed
        if remain_total < 20:
            break
        slice_timeout = min(60, max(25, remain_total // max(1, len(siblings))))
        if on_log:
            on_log(
                f"PMKID band rotate → [cyan]{sibling.display_name}[/] "
                f"ch{sibling.channel} ({sibling.band_label}, {slice_timeout}s)",
            )
        iface = recover_interface(
            cfg.scan.interface, sibling.channel, band=sibling.radio_band,
        )
        cfg.scan.interface = iface
        set_channel(iface, sibling.channel, band=sibling.radio_band)
        if os.path.exists(outfile):
            try:
                os.remove(outfile)
            except OSError:
                pass
        hash_line = HcxTools.capture_pmkid(
            sibling,
            iface,
            outfile,
            slice_timeout,
            on_tick=on_tick,
            on_log=on_log,
            should_stop=should_stop,
            prefer_wpa2=prefer_wpa2,
        )
        elapsed += slice_timeout
        if hash_line:
            return hash_line

    remain = max(0, timeout - elapsed)
    if remain < 15:
        return None
    iface = recover_interface(cfg.scan.interface, ap.channel, band=ap.radio_band)
    cfg.scan.interface = iface
    if on_log:
        on_log(f"PMKID final listen on target band ({remain}s)")
    return HcxTools.capture_pmkid(
        ap,
        iface,
        outfile,
        remain,
        on_tick=on_tick,
        on_log=on_log,
        should_stop=should_stop,
        prefer_wpa2=prefer_wpa2,
    )