"""Network scanner with live Rich display."""

from __future__ import annotations

import threading
import time

from .config import WifluxConfig
from .display import console, print_info, print_targets, safe_markup, supports_live
from .models import AccessPoint, EncryptionType, rank_targets
from .progress import ProgressTracker, get_tracker
from .results import ResultStore
from .tools.airodump import Airodump
from .tools.decloak import DecloakManager
from .tools.wash import Wash


class Scanner:
    def __init__(self, cfg: WifluxConfig, store: ResultStore, tracker: ProgressTracker | None = None):
        self.cfg = cfg
        self.store = store
        self.tracker = tracker or get_tracker()
        self.targets: list[AccessPoint] = []
        self._decloak = DecloakManager(cfg)

    def scan(self) -> list[AccessPoint]:
        scan_limit = self.cfg.scan.scan_time
        use_live = (
            not self.cfg.output.quiet
            and not self.cfg.output.json_output
            and supports_live()
        )

        self.tracker.begin_scan(scan_limit)

        try:
            if use_live:
                with self.tracker.live(refresh=8):
                    wps_cache = self._probe_wps()
                    with Airodump(self.cfg, wps_cache=wps_cache) as dump:
                        self.tracker.set_scan_status("Searching")
                        self._scan_loop(dump, scan_limit)
            else:
                wps_cache = self._probe_wps_quiet()
                with Airodump(self.cfg, wps_cache=wps_cache) as dump:
                    self._scan_loop(dump, scan_limit)
        except KeyboardInterrupt:
            pass  # keep whatever we collected

        self.targets = rank_targets(self.targets)
        return self.targets

    def _probe_wps(self) -> dict:
        if not Wash.available():
            return {}
        self.tracker.set_scan_status("Probing WPS")
        self.tracker.log("Probing WPS (10s)...", tag="scan")
        self.tracker.refresh()

        result: dict = {}
        thread = threading.Thread(
            target=lambda: result.update({
                "cache": Wash.scan_live(
                    self.cfg.scan.interface,
                    timeout=10,
                    band_2ghz=self.cfg.scan.band_2ghz,
                    band_5ghz=self.cfg.scan.band_5ghz,
                ),
            }),
            daemon=True,
        )
        thread.start()
        while thread.is_alive():
            self.tracker.tick_scan()
            self.tracker.refresh()
            time.sleep(0.125)
        thread.join()

        cache = result.get("cache", {})
        if cache:
            self.tracker.log(f"WPS probe: {len(cache)} APs", tag="scan")
        return cache

    def _probe_wps_quiet(self) -> dict:
        if not Wash.available():
            return {}
        return Wash.scan_live(
            self.cfg.scan.interface,
            timeout=10,
            band_2ghz=self.cfg.scan.band_2ghz,
            band_5ghz=self.cfg.scan.band_5ghz,
        )

    def _scan_loop(self, dump: Airodump, scan_limit: int) -> None:
        start = time.time()
        while True:
            prev_map = {a.bssid: a for a in self.targets}
            raw = dump.parse_targets(self.targets)
            self._decloak.decloak_hidden(
                raw, dump.interface,
                on_log=lambda msg: self.tracker.log(msg, tag="decloak"),
            )
            for ap in raw:
                if ap.decloaked and ap.essid_known:
                    prev = prev_map.get(ap.bssid)
                    if prev and not prev.essid_known:
                        self.tracker.log(
                            f"[green]Revealed:[/] [cyan]{safe_markup(ap.essid or '')}[/] "
                            f"[dim]({safe_markup(ap.bssid)})[/]",
                            tag="decloak",
                        )
            self.targets = self._filter(raw)
            self.tracker.update_scan(self.targets, decloaking=self._decloak.active)
            self.tracker.refresh()

            if scan_limit and time.time() - start >= scan_limit:
                break
            if self._found_specific_target():
                break
            if not dump.alive():
                break
            time.sleep(0.25)

    def _filter(self, targets: list[AccessPoint]) -> list[AccessPoint]:
        cracked = (
            self.store.get_cracked_bssids()
            if self.cfg.scan.ignore_cracked
            else set()
        )
        result = []
        for ap in targets:
            if ap.bssid in cracked:
                continue
            if not self._passes_enc_filter(ap):
                continue
            if ap.power < self.cfg.scan.min_power:
                continue
            if self.cfg.scan.clients_only and not ap.clients:
                continue
            if self.cfg.scan.target_bssid and ap.bssid.lower() != self.cfg.scan.target_bssid.lower():
                continue
            if self.cfg.scan.target_essid and (not ap.essid_known or ap.essid != self.cfg.scan.target_essid):
                continue
            if any(ign.lower() in (ap.essid or "").lower() for ign in self.cfg.scan.ignore_essids):
                continue
            if ap.encryption == EncryptionType.OPEN:
                continue
            result.append(ap)
        return result

    def _passes_enc_filter(self, ap: AccessPoint) -> bool:
        s = self.cfg.scan
        if not any((s.filter_wep, s.filter_wpa, s.filter_wpa3, s.filter_owe, s.filter_wps)):
            return True
        from .models import EncryptionType, WPSState
        if s.filter_wep and ap.encryption == EncryptionType.WEP:
            return True
        if s.filter_wpa and ap.encryption in (EncryptionType.WPA, EncryptionType.WPA2):
            return True
        if s.filter_wpa3 and ap.encryption == EncryptionType.WPA3:
            return True
        if s.filter_owe and ap.encryption == EncryptionType.OWE:
            return True
        if s.filter_wps and ap.wps in (WPSState.UNLOCKED, WPSState.LOCKED):
            return True
        return False

    def _found_specific_target(self) -> bool:
        if self.cfg.scan.target_bssid or self.cfg.scan.target_essid:
            return len(self.targets) > 0
        return False

    def select_targets(self, targets: list[AccessPoint]) -> list[AccessPoint]:
        if not targets:
            return []

        # Single ranked list drives both the table numbers AND selection indices
        ranked = rank_targets(targets)

        if self.cfg.auto_mode:
            if self.cfg.attack.attack_max:
                return ranked[: self.cfg.attack.attack_max]
            return ranked

        print_targets(ranked)
        console.print()
        console.print(
            "[dim]Selection:[/] [cyan]N[/] single  "
            "[cyan]1,3,5[/] multiple  "
            "[cyan]all[/] everything  "
            "[cyan]q[/] quit"
        )
        try:
            choice = input("Targets> ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            return []

        if choice in ("q", "quit", ""):
            return []

        if choice == "all":
            selected = ranked
        elif "," in choice:
            indices = []
            for part in choice.split(","):
                try:
                    indices.append(int(part.strip()) - 1)
                except ValueError:
                    pass
            selected = [ranked[i] for i in indices if 0 <= i < len(ranked)]
        else:
            try:
                idx = int(choice) - 1
                selected = [ranked[idx]] if 0 <= idx < len(ranked) else []
            except ValueError:
                selected = []

        if self.cfg.attack.attack_max:
            selected = selected[: self.cfg.attack.attack_max]

        for ap in selected:
            print_info(
                f"Selected: [cyan]{safe_markup(ap.display_name)}[/] "
                f"[dim]({safe_markup(ap.bssid)})[/] ch{ap.channel}"
            )

        return selected