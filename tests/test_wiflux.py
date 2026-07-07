#!/usr/bin/env python3
"""Wiflux unit and integration tests (no live radio required)."""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wiflux.attacks.handshake import HandshakeAttack
from wiflux.attacks.pmkid import PMKIDAttack
from wiflux.attacks.wps import WPSPixieAttack
from wiflux.config import WifluxConfig, find_wordlist
from wiflux.models import AccessPoint, Client, EncryptionType, WPSState, rank_targets
from wiflux.orchestrator import Orchestrator
from wiflux.progress import ProgressTracker
from wiflux.results import ResultStore
from wiflux.tools.airodump import Airodump
from wiflux.tools.client_filter import (
    active_clients,
    filter_clients,
    is_heard_client,
    is_valid_client,
)
from wiflux.tools.capture_health import CaptureHealth, reset_health_cache
from wiflux.tools.handshake_detect import check_handshake, reset_check_cache
from wiflux.tools.hashcat import hcx_channel
from wiflux.tools.radio import (
    airodump_band_args,
    hcx_channel as radio_hcx_channel,
    infer_band,
    six_ghz_mhz,
    tag_band_for_ap,
)
from wiflux.tools.smart_wordlist import (
    DEFAULT_SMART_CANDIDATES,
    MAX_SMART_CANDIDATES,
    clamp_wordlist_size,
    generate_candidates,
    select_preview_examples,
)
from wiflux.input import (
    prompt_smart_wordlist,
    resolve_capture_health,
    should_offer_smart_wordlist,
    should_prompt_cached_handshake,
)


class TestClientFilter(unittest.TestCase):
    def test_blocks_multicast(self):
        self.assertFalse(is_valid_client("01:80:C2:00:00:00", "AA:BB:CC:DD:EE:FF"))

    def test_blocks_ap_bssid(self):
        self.assertFalse(is_valid_client("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"))

    def test_active_clients_skip_stale(self):
        clients = ["FE:32:E8:12:1E:0A", "EE:D7:16:FD:EC:18"]
        power = {"FE:32:E8:12:1E:0A": -42, "EE:D7:16:FD:EC:18": -1}
        heard = active_clients(clients, power, "92:B4:74:3A:F1:92")
        self.assertEqual(heard, ["FE:32:E8:12:1E:0A"])

    def test_is_heard_client(self):
        self.assertFalse(is_heard_client("AA:BB:CC:DD:EE:00", {"AA:BB:CC:DD:EE:00": -1}))
        self.assertTrue(is_heard_client("AA:BB:CC:DD:EE:00", {"AA:BB:CC:DD:EE:00": -50}))


class TestModels(unittest.TestCase):
    def test_enterprise_skipped(self):
        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF", channel=6, encryption=EncryptionType.WPA2,
            auth="MGT", power=50, essid="Corp", essid_known=True,
        )
        self.assertTrue(ap.is_enterprise)

    def test_rank_targets_by_score(self):
        strong = AccessPoint(
            bssid="11:11:11:11:11:11", channel=1, encryption=EncryptionType.WPA2,
            auth="PSK", power=80, essid="A", essid_known=True,
            clients=[Client("22:22:22:22:22:22", -40)],
        )
        weak = AccessPoint(
            bssid="22:22:22:22:22:22", channel=6, encryption=EncryptionType.WPA2,
            auth="PSK", power=30, essid="B", essid_known=True,
        )
        ranked = rank_targets([weak, strong])
        self.assertEqual(ranked[0].bssid, strong.bssid)


class TestHandshakeLogic(unittest.TestCase):
    def setUp(self):
        self.tracker = ProgressTracker()
        self.tracker.discovered_targets = [
            AccessPoint(
                bssid="92:B4:74:3A:F1:92", channel=44, encryption=EncryptionType.WPA2,
                auth="PSK", power=79, essid="Yaxley 5ghz", essid_known=True,
            ),
            AccessPoint(
                bssid="3C:A6:2F:7E:AF:D0", channel=11, encryption=EncryptionType.WPA2,
                auth="PSK", power=60, essid="Yaxley24ghz", essid_known=True,
            ),
        ]
        self.cfg = WifluxConfig()
        self.ap_5 = self.tracker.discovered_targets[0]

    def test_essid_root(self):
        self.assertEqual(HandshakeAttack._essid_root("Yaxley 5ghz"), "yaxley")
        self.assertEqual(HandshakeAttack._essid_root("Yaxley24ghz"), "yaxley")

    def test_sibling_band_ap(self):
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        sib = attack._sibling_band_ap()
        self.assertIsNotNone(sib)
        self.assertEqual(sib.bssid, "3C:A6:2F:7E:AF:D0")

    def test_sibling_without_discovered_still_finds_hs_cap(self):
        """-b filter leaves tracker.targets empty of 2.4GHz — hs/ scan must still work."""
        self.tracker.discovered_targets = []
        self.tracker.targets = [self.ap_5]
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        cap = attack._existing_cap()
        hs = Path(self.cfg.output.handshake_dir)
        if list(hs.glob("handshake_*3C-A6-2F-7E-AF-D0*.cap")):
            self.assertIsNotNone(cap)
        else:
            self.skipTest("no Yaxley24ghz cap in hs/")

    def test_merge_clients_skips_stale(self):
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        clients: list[str] = []
        power: dict[str, int] = {}
        added = attack._merge_clients(
            clients, power,
            [("FE:32:E8:12:1E:0A", -42), ("EE:D7:16:FD:EC:18", -1)],
        )
        self.assertEqual(added, ["FE:32:E8:12:1E:0A"])
        self.assertEqual(clients, ["FE:32:E8:12:1E:0A"])

    def test_new_handshake_skips_hs_cache(self):
        self.cfg.attack.new_handshake = True
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        self.assertIsNone(attack._existing_cap())

    def test_new_handshake_blocks_passive_candidate(self):
        cap = "/root/hs/handshake_Yaxley5ghz_3C-A6-2F-7E-AF-D1_2026-06-21T14-33-34.cap"
        if not os.path.exists(cap):
            self.skipTest("cap missing")
        ap = AccessPoint(
            bssid="3C:A6:2F:7E:AF:D1", channel=44, encryption=EncryptionType.WPA2,
            auth="PSK", power=-50, essid="Yaxley5ghz", essid_known=True,
        )
        self.cfg.attack.new_handshake = True
        attack = HandshakeAttack(self.cfg, ap, self.tracker)
        attack._min_candidate_time = 0
        blocked = attack._try_handshake(
            cap,
            clients=1,
            deauth_rounds=0,
            cap_kb=64,
            started=0,
            timeout=300,
            capture_phase="passive",
        )
        self.assertIsNone(blocked)
        allowed = attack._try_handshake(
            cap,
            clients=1,
            deauth_rounds=1,
            cap_kb=64,
            started=0,
            timeout=300,
            capture_phase="deauth_listen",
        )
        self.assertIsNotNone(allowed)

    def test_existing_cap_for_5ghz(self):
        self.cfg.auto_mode = True
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        cap = attack._existing_cap()
        hs_caps = list(Path(self.cfg.output.handshake_dir).glob("*.cap"))
        if not hs_caps:
            self.skipTest("no caps in hs/")
        self.assertIsNotNone(cap)
        result = attack.run()
        self.assertTrue(result.success)

    def test_hash_from_sibling_cap_any_router(self):
        """Must extract hash from cap's real BSSID, not the 5 GHz target."""
        cap = Path("/root/hs/handshake_Yaxley5ghz_3C-A6-2F-7E-AF-D1_2026-06-21T14-33-34.cap")
        if not cap.exists():
            self.skipTest("AF:D1 cap missing")
        self.tracker.discovered_targets = []
        self.tracker.targets = [self.ap_5]
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        result = attack._hash_from_cap(str(cap))
        self.assertIsNotNone(result)
        bssid, line = result
        self.assertEqual(bssid, "3C:A6:2F:7E:AF:D1")
        self.assertTrue(line.startswith("WPA*"))

    def test_hash_from_cap_without_tracker_sibling(self):
        """Works even when scan only has the 5 GHz AP (-b filter)."""
        cap = Path("/root/hs/handshake_Yaxley24ghz_3C-A6-2F-7E-AF-D0_2026-06-30T19-11-43.cap")
        if not cap.exists():
            cap = Path("/root/wiflux/hs/handshake_Yaxley24ghz_3C-A6-2F-7E-AF-D0_20260704T085728.cap")
        if not cap.exists():
            self.skipTest("AF:D0 cap missing")
        self.tracker.discovered_targets = []
        self.tracker.targets = [self.ap_5]
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        result = attack._hash_from_cap(str(cap))
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "3C:A6:2F:7E:AF:D0")


class TestAirodump(unittest.TestCase):
    def test_restart_preserves_caps(self):
        cfg = WifluxConfig()
        cfg.scan.interface = "wlan0mon"
        dump = Airodump(cfg, channel=6, prefix="t")
        cap_path = os.path.join(dump.temp_dir, "t-01.cap")
        with open(cap_path, "wb") as f:
            f.write(b"\x00" * 128)
        dump.restart()
        self.assertTrue(os.path.exists(cap_path))

    def test_build_cmd_5ghz_band(self):
        cfg = WifluxConfig()
        cfg.scan.interface = "wlan0mon"
        dump = Airodump(cfg, channel=44, bssid="92:B4:74:3A:F1:92")
        cmd = dump._build_cmd()
        self.assertIn("--band", cmd)
        self.assertIn("a", cmd)
        self.assertIn("44", cmd)

    def test_parse_client_row(self):
        clients_map: dict = {}
        probing: list = []
        row = ["FE:32:E8:12:1E:0A", "", "", "-42", "8", "92:B4:74:3A:F1:92"]
        Airodump._parse_client_row(row, clients_map, probing)
        self.assertEqual(len(clients_map["92:B4:74:3A:F1:92"]), 1)
        self.assertEqual(clients_map["92:B4:74:3A:F1:92"][0].power, -42)
        self.assertEqual(clients_map["92:B4:74:3A:F1:92"][0].packets, 8)
        self.assertEqual(probing, [])

    def test_probing_clients_attached_by_essid(self):
        clients_map: dict = {}
        probing: list = []
        Airodump._parse_client_row(
            ["D8:3B:DA:86:63:24", "", "", "-91", "2", "(not associated) ", "Workshop"],
            clients_map,
            probing,
        )
        self.assertEqual(clients_map, {})
        self.assertEqual(len(probing), 1)
        aps = [
            AccessPoint(
                bssid="C0:06:C3:1A:44:8A", channel=7, encryption=EncryptionType.WPA2,
                auth="PSK", power=21, essid="Workshop", essid_known=True,
            ),
        ]
        Airodump._attach_probing_clients(aps, clients_map, probing)
        self.assertEqual(len(clients_map["C0:06:C3:1A:44:8A"]), 1)
        self.assertEqual(clients_map["C0:06:C3:1A:44:8A"][0].station, "D8:3B:DA:86:63:24")


class TestOrchestrator(unittest.TestCase):
    def test_attack_plan_includes_handshake(self):
        cfg = WifluxConfig()
        ap = AccessPoint(
            bssid="92:B4:74:3A:F1:92", channel=44, encryption=EncryptionType.WPA2,
            auth="PSK", power=79, essid="Test", essid_known=True,
        )
        orch = Orchestrator(cfg, ResultStore(tempfile.mkdtemp()))
        plan = orch._build_attack_plan(ap)
        names = [c.name for c in plan]
        self.assertIn("handshake", names)

    def test_enterprise_no_plan(self):
        cfg = WifluxConfig()
        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF", channel=6, encryption=EncryptionType.WPA2,
            auth="MGT", power=50, essid="Corp", essid_known=True,
        )
        orch = Orchestrator(cfg, ResultStore(tempfile.mkdtemp()))
        self.assertFalse(orch._attack_one(ap))


class TestConfig(unittest.TestCase):
    def test_hcx_channel(self):
        self.assertEqual(hcx_channel(11), "11a")
        self.assertEqual(hcx_channel(44), "44b")
        self.assertEqual(hcx_channel(37, band="6"), "37c")
        self.assertEqual(radio_hcx_channel(37, band="6"), "37c")

    def test_infer_band_6ghz(self):
        self.assertEqual(infer_band(37, scan_6ghz=True, scan_5ghz=False, scan_2ghz=False), "6")
        self.assertEqual(infer_band(20), "6")
        self.assertEqual(infer_band(44), "5")

    def test_six_ghz_mhz(self):
        self.assertEqual(six_ghz_mhz(1), 5955)
        self.assertEqual(six_ghz_mhz(37), 6135)

    def test_airodump_6ghz_cmd(self):
        cfg = WifluxConfig()
        cfg.scan.interface = "wlan0mon"
        cfg.scan.band_6ghz = True
        cfg.scan.band_2ghz = False
        cfg.scan.band_5ghz = False
        dump = Airodump(cfg, channel=37, band="6")
        cmd = dump._build_cmd()
        self.assertIn("-C", cmd)
        self.assertIn(str(six_ghz_mhz(37)), cmd)

    def test_airodump_scan_6ghz_hop(self):
        cfg = WifluxConfig()
        cfg.scan.band_6ghz = True
        cfg.scan.band_2ghz = False
        cfg.scan.band_5ghz = False
        args = airodump_band_args(cfg)
        self.assertIn("-C", args)
        self.assertIn("5955", ",".join(args))

    def test_tag_band_for_ap(self):
        cfg = WifluxConfig()
        cfg.scan.band_6ghz = True
        cfg.scan.band_5ghz = False
        cfg.scan.band_2ghz = False
        self.assertEqual(tag_band_for_ap(37, cfg), "6")
        self.assertEqual(tag_band_for_ap(20, cfg), "6")

    def test_config_dirs_created(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = WifluxConfig()
            cfg.output.data_dir = os.path.join(tmp, "data")
            cfg.output.handshake_dir = os.path.join(tmp, "hs")
            cfg.__post_init__()
            self.assertTrue(os.path.isdir(cfg.output.handshake_dir))


class TestHandshakeDetect(unittest.TestCase):
    def test_extract_hash_preferred(self):
        from wiflux.tools.handshake_detect import extract_hash_preferred
        cap = "/root/hs/handshake_Yaxley5ghz_3C-A6-2F-7E-AF-D1_2026-06-21T14-33-34.cap"
        if not os.path.exists(cap):
            self.skipTest("cap missing")
        # Wrong target first — must still return AF:D1 from inside the cap
        result = extract_hash_preferred(cap, ["92:B4:74:3A:F1:92", "3C:A6:2F:7E:AF:D1"])
        self.assertIsNotNone(result)
        self.assertEqual(result[0], "3C:A6:2F:7E:AF:D1")

    def test_known_cap(self):
        hs = Path(ROOT) / "hs"
        caps = list(hs.glob("handshake_*.cap"))
        if not caps:
            self.skipTest("no handshake caps")
        cap = str(caps[0])
        bssid = HandshakeAttack._cap_bssid_from_name(caps[0].name)
        self.assertIsNotNone(bssid)
        reset_check_cache()
        self.assertTrue(check_handshake(cap, bssid, min_interval=0))


class TestCanAttack(unittest.TestCase):
    def test_pmkid_wpa2(self):
        cfg = WifluxConfig()
        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF", channel=6, encryption=EncryptionType.WPA2,
            auth="PSK", power=50, essid="X", essid_known=True,
        )
        self.assertTrue(PMKIDAttack(cfg, ap).can_attack())

    def test_handshake_disabled(self):
        cfg = WifluxConfig()
        cfg.attack.handshake = False
        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF", channel=6, encryption=EncryptionType.WPA2,
            auth="PSK", power=50, essid="X", essid_known=True,
        )
        self.assertFalse(HandshakeAttack(cfg, ap).can_attack())


class TestCLI(unittest.TestCase):
    def test_import_cli(self):
        from wiflux.cli import build_parser, args_to_config
        parser = build_parser()
        args = parser.parse_args(["--no-handshake", "-q"])
        cfg = args_to_config(args)
        self.assertFalse(cfg.attack.handshake)
        self.assertTrue(cfg.output.quiet)

    def test_capture_health_flags(self):
        from wiflux.cli import build_parser, args_to_config
        parser = build_parser()
        cfg = args_to_config(parser.parse_args(["--capture-health"]))
        self.assertTrue(cfg.attack.capture_health)
        cfg = args_to_config(parser.parse_args(["--no-capture-health"]))
        self.assertFalse(cfg.attack.capture_health)

    def test_smart_wordlist_flags(self):
        from wiflux.cli import build_parser, args_to_config
        parser = build_parser()
        cfg = args_to_config(parser.parse_args(["--smart-wordlist", "--yes-smart-wordlist"]))
        self.assertTrue(cfg.attack.smart_wordlist)
        self.assertTrue(cfg.attack.yes_smart_wordlist)

    def test_6ghz_flag(self):
        from wiflux.cli import build_parser, args_to_config
        parser = build_parser()
        cfg = args_to_config(parser.parse_args(["--6ghz"]))
        self.assertTrue(cfg.scan.band_6ghz)
        self.assertTrue(cfg.scan.band_2ghz)


class TestSmartWordlist(unittest.TestCase):
    def test_generate_essid_candidates(self):
        words = generate_candidates("Yaxley5ghz", "3C:A6:2F:7E:AF:D0")
        folded = {w.casefold() for w in words}
        self.assertIn("yaxley5ghz", folded)
        self.assertIn("yaxley5ghz123", folded)
        self.assertTrue(all(8 <= len(w) <= 63 for w in words))
        self.assertGreater(len(words), 100)

    def test_workshop_reaches_default_candidates(self):
        words = generate_candidates(
            "Workshop", "C0:06:C3:1A:44:8A",
            max_candidates=DEFAULT_SMART_CANDIDATES,
        )
        self.assertEqual(len(words), DEFAULT_SMART_CANDIDATES)
        folded = {w.casefold() for w in words}
        self.assertIn("workshop123", folded)

    def test_workshop_can_scale_to_max(self):
        words = generate_candidates(
            "Workshop", "C0:06:C3:1A:44:8A",
            max_candidates=MAX_SMART_CANDIDATES,
        )
        self.assertEqual(len(words), MAX_SMART_CANDIDATES)

    def test_clamp_wordlist_size(self):
        self.assertEqual(clamp_wordlist_size(500), 500)
        self.assertEqual(clamp_wordlist_size(999_999), MAX_SMART_CANDIDATES)
        self.assertEqual(clamp_wordlist_size(0), DEFAULT_SMART_CANDIDATES)

    def test_preview_examples_subset(self):
        words = generate_candidates("Workshop", "C0:06:C3:1A:44:8A")
        sample = select_preview_examples(words, count=8)
        self.assertEqual(len(sample), 8)
        self.assertLess(len(sample), len(words))

    def test_vendor_defaults_tp_link(self):
        words = generate_candidates(
            "HomeNet", "AA:BB:CC:DD:EE:FF", "TP-Link Technologies",
            max_candidates=DEFAULT_SMART_CANDIDATES,
        )
        self.assertEqual(len(words), DEFAULT_SMART_CANDIDATES)
        self.assertIn("tplink123", words)

    def test_should_prompt_cached_handshake_auto_skips(self):
        cfg = WifluxConfig()
        cfg.auto_mode = True
        self.assertFalse(should_prompt_cached_handshake(cfg))

    def test_should_offer_smart_wordlist_auto_skips(self):
        cfg = WifluxConfig()
        cfg.auto_mode = True
        self.assertFalse(should_offer_smart_wordlist(cfg))

    def test_should_offer_smart_wordlist_disabled(self):
        cfg = WifluxConfig()
        cfg.attack.smart_wordlist = False
        self.assertFalse(should_offer_smart_wordlist(cfg))

    def test_prompt_smart_wordlist_yes_flag(self):
        cfg = WifluxConfig()
        cfg.attack.yes_smart_wordlist = True
        ap = AccessPoint(
            bssid="C0:06:C3:1A:44:8A", channel=7, encryption=EncryptionType.WPA2,
            auth="PSK", power=50, essid="Workshop", essid_known=True,
        )
        result = prompt_smart_wordlist(cfg, ap, ProgressTracker())
        self.assertIsNotNone(result)
        self.assertGreater(result[1], 0)

    def test_resolve_capture_health_explicit(self):
        cfg = WifluxConfig()
        cfg.attack.capture_health = True
        self.assertTrue(resolve_capture_health(cfg))


class TestLogMarkup(unittest.TestCase):
    def test_deauth_ineffective_log_is_valid_markup(self):
        from rich.markup import render as render_markup

        adapt_line = (
            "[cyan]Adaptive next:[/] probing with slightly stronger bursts "
            "[dim]|[/] tool [cyan]mdk4[/]"
        )
        pmkid_tip = "[dim]Tip:[/] PMKID works without clients ([yellow]--pmkid[/])"
        msg = (
            f"[yellow]Deauth ineffective[/] after 2 round(s) on 2.4 GHz — no "
            f"reconnect/EAPOL in capture. Client may use PMF, ignore deauth, or "
            f"roam bands. {adapt_line}. {pmkid_tip}"
        )
        render_markup(msg)

    def test_progress_sanitizes_broken_log(self):
        tracker = ProgressTracker()
        tracker.log("broken [yellow]open[/] tag [/] orphan", tag="test")
        panel = tracker._render_logs()
        self.assertIsNotNone(panel)


class TestTransitionMode(unittest.TestCase):
    def test_detect_transition_from_privacy(self):
        from wiflux.tools.transition import detect_transition_mode

        self.assertTrue(detect_transition_mode("WPA2 WPA3"))
        self.assertTrue(detect_transition_mode("WPA3 WPA2"))
        self.assertFalse(detect_transition_mode("WPA2"))
        self.assertFalse(detect_transition_mode("WPA3"))

    def test_detect_transition_from_auth(self):
        from wiflux.tools.transition import detect_transition_mode

        self.assertTrue(detect_transition_mode("WPA2", "PSK SAE"))
        self.assertFalse(detect_transition_mode("WPA2", "PSK"))

    def test_select_hash_prefers_wpa2(self):
        from wiflux.tools.transition import select_hash_line

        pairs = [
            ("AA:BB:CC:DD:EE:FF", "WPA*01*hash*wpa3*mac"),
            ("AA:BB:CC:DD:EE:FF", "WPA*02*hash*wpa2*mac"),
        ]
        picked = select_hash_line(pairs, prefer_wpa2=True)
        self.assertEqual(picked[1].split("*")[1], "02")

    def test_ap_crack_use_wpa3_transition(self):
        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF", channel=36, encryption=EncryptionType.WPA3,
            auth="PSK SAE", power=50, essid="Mixed", essid_known=True,
            transition_mode=True,
        )
        self.assertTrue(ap.is_wpa3_sae)
        self.assertFalse(ap.crack_use_wpa3)
        self.assertEqual(ap.encryption_label, "WPA2/3-T")

    def test_airodump_parse_transition_row(self):
        cfg = WifluxConfig()
        dump = Airodump(cfg)
        row = [
            "AA:BB:CC:DD:EE:FF", "", "", "36", "", "WPA2 WPA3", "", "PSK SAE",
            "-42", "10", "0", "0", "8", "MixedNet",
        ]
        ap = dump._parse_ap_row(row)
        self.assertIsNotNone(ap)
        assert ap is not None
        self.assertTrue(ap.transition_mode)
        self.assertEqual(ap.encryption_label, "WPA2/3-T")

    def test_transition_downgrade_cli_flag(self):
        from wiflux.cli import build_parser, args_to_config

        cfg = args_to_config(build_parser().parse_args(["--no-transition-downgrade"]))
        self.assertFalse(cfg.attack.transition_downgrade)


class TestHandshakeValidation(unittest.TestCase):
    def test_validate_known_cap(self):
        from wiflux.tools.handshake_detect import validate_handshake_capture

        cap = "/root/hs/handshake_Yaxley5ghz_3C-A6-2F-7E-AF-D1_2026-06-21T14-33-34.cap"
        if not os.path.exists(cap):
            self.skipTest("cap missing")
        result = validate_handshake_capture(cap, ["3C:A6:2F:7E:AF:D1"])
        self.assertTrue(result.valid)
        self.assertTrue(result.hash_line.startswith("WPA"))

    def test_validate_rejects_empty(self):
        from wiflux.tools.handshake_detect import validate_handshake_capture

        result = validate_handshake_capture("/nonexistent.cap", ["AA:BB:CC:DD:EE:FF"])
        self.assertFalse(result.valid)

    def test_prompt_space_to_continue_defined(self):
        from wiflux.input import prompt_space_to_continue

        self.assertTrue(callable(prompt_space_to_continue))

    def test_validation_screens_render(self):
        from io import StringIO

        from wiflux.display import (
            console,
            show_handshake_validated,
            show_handshake_validating,
        )
        from wiflux.models import AccessPoint, EncryptionType

        ap = AccessPoint(
            bssid="08:B6:57:1B:92:B3", channel=6, encryption=EncryptionType.WPA2,
            auth="PSK", power=50, essid="WiFiMi", essid_known=True,
        )
        buf = StringIO()
        old = console.file
        try:
            console.file = buf
            show_handshake_validating(ap, "hs/test.cap")
            show_handshake_validated(ap, "Complete 4-way handshake", bssid=ap.bssid)
        finally:
            console.file = old
        out = buf.getvalue()
        self.assertIn("HANDSHAKE CAPTURED", out)
        self.assertIn("Checking capture", out)
        self.assertIn("HANDSHAKE VALIDATED", out)


class TestPmkidCaptureScreens(unittest.TestCase):
    def test_pmkid_screens_render(self):
        from io import StringIO

        from wiflux.display import (
            console,
            show_pmkid_captured,
            show_pmkid_captured_banner,
        )
        from wiflux.models import AccessPoint, EncryptionType, PMKIDCaptureInfo

        ap = AccessPoint(
            bssid="C0:06:C3:1A:44:8A", channel=7, encryption=EncryptionType.WPA2,
            auth="PSK", power=50, essid="Workshop", essid_known=True,
        )
        info = PMKIDCaptureInfo(
            summary="Clientless PMKID captured via hcxdumptool (passive AP probe)",
            hash_file="hs/pmkid_Workshop_C0-06-C3-1A-44-8A_20260704.22000",
            channel=7,
            bssid=ap.bssid,
            essid="Workshop",
            hash_type="wpa2",
            source="live",
        )
        buf = StringIO()
        old = console.file
        try:
            console.file = buf
            show_pmkid_captured(ap, info)
            show_pmkid_captured_banner(ap, info)
        finally:
            console.file = old
        out = buf.getvalue()
        self.assertIn("PMKID CAPTURED", out)
        self.assertIn("PMKID RECOVERED", out)
        self.assertIn("Workshop", out)

    def test_build_pmkid_capture_info_cached(self):
        from wiflux.attacks.pmkid import PMKIDAttack
        from wiflux.config import WifluxConfig
        from wiflux.models import AccessPoint, EncryptionType

        cfg = WifluxConfig()
        ap = AccessPoint(
            bssid="3C:A6:2F:7E:AF:D0", channel=11, encryption=EncryptionType.WPA2,
            auth="PSK", power=60, essid="Yaxley 2.4ghz", essid_known=True,
        )
        attack = PMKIDAttack(cfg, ap, ProgressTracker())
        info = attack._build_capture_info(
            "WPA*02*hash*essid*mac*essid***",
            "cached",
            source="cached",
        )
        self.assertEqual(info.source, "cached")
        self.assertIn("Recovered existing", info.summary)
        self.assertTrue(info.show_banner)


class TestHandshakeCaptureBanner(unittest.TestCase):
    def test_build_live_capture_info_no_banner_when_deauth_worked(self):
        from wiflux.attacks.handshake import HandshakeAttack
        from wiflux.config import WifluxConfig
        from wiflux.models import AccessPoint, EncryptionType

        cfg = WifluxConfig()
        ap = AccessPoint(
            bssid="04:70:56:60:5F:54", channel=11, encryption=EncryptionType.WPA2,
            auth="PSK", power=60, essid="BT-W3F6K9", essid_known=True,
        )
        attack = HandshakeAttack(cfg, ap, ProgressTracker())
        attack._deauth_tools_used = ["mdk4"]
        attack._deauth_adaptive_exhausted = False
        attack._live_capture_meta = {"passive": False, "sibling_fallback": False}
        info = attack._build_live_capture_info(
            "/tmp/hs/handshake_BT.cap",
            "04:70:56:60:5F:54",
            deauth_rounds=2,
            clients=1,
            cap_kb=128,
            capture_phase="deauth_listen",
        )
        self.assertFalse(info.show_banner)
        self.assertIn("2 deauth round", info.summary)

    def test_build_live_capture_info_banner_after_adaptive_exhausted(self):
        from wiflux.attacks.handshake import HandshakeAttack
        from wiflux.config import WifluxConfig
        from wiflux.models import AccessPoint, EncryptionType

        cfg = WifluxConfig()
        ap = AccessPoint(
            bssid="04:70:56:60:5F:54", channel=11, encryption=EncryptionType.WPA2,
            auth="PSK", power=60, essid="BT-W3F6K9", essid_known=True,
        )
        attack = HandshakeAttack(cfg, ap, ProgressTracker())
        attack._deauth_tools_used = ["mdk4", "aireplay", "bettercap"]
        attack._deauth_adaptive_exhausted = True
        attack._live_capture_meta = {"passive": False, "sibling_fallback": False}
        info = attack._build_live_capture_info(
            "/tmp/hs/handshake_BT.cap",
            "04:70:56:60:5F:54",
            deauth_rounds=5,
            clients=1,
            cap_kb=128,
            capture_phase="final_sweep",
        )
        self.assertTrue(info.show_banner)
        self.assertIn("ineffective after all adaptive cycles", info.summary)
        self.assertIn("final sweep", info.summary)

    def test_show_handshake_captured_banner_renders(self):
        from io import StringIO

        from rich.console import Console

        from wiflux.display import console, show_handshake_captured_banner
        from wiflux.models import AccessPoint, EncryptionType, HandshakeCaptureInfo

        ap = AccessPoint(
            bssid="04:70:56:60:5F:54", channel=11, encryption=EncryptionType.WPA2,
            auth="PSK", power=60, essid="BT-W3F6K9", essid_known=True,
        )
        info = HandshakeCaptureInfo(
            summary="WPA 4-way handshake captured after 2 deauth round(s) using mdk4 on channel 11",
            capture_file="hs/handshake_BT.cap",
            channel=11,
            hash_bssid="04:70:56:60:5F:54",
            target_bssid="04:70:56:60:5F:54",
            essid="BT-W3F6K9",
            deauth_rounds=2,
            deauth_tools="mdk4",
            clients=1,
            cap_size_kb=96,
        )
        buf = StringIO()
        old = console.file
        try:
            console.file = buf
            show_handshake_captured_banner(ap, info)
        finally:
            console.file = old
        out = buf.getvalue()
        self.assertIn("HANDSHAKE RECOVERED", out)
        self.assertIn("BT-W3F6K9", out)
        self.assertIn("mdk4", out)


class TestDeauthBackends(unittest.TestCase):
    def test_parse_deauth_tools(self):
        from wiflux.tools.deauth_backends import DeauthTool, parse_deauth_tools

        tools = parse_deauth_tools("mdk4,aireplay,bettercap")
        self.assertEqual(tools, [DeauthTool.MDK4, DeauthTool.AIREPLAY, DeauthTool.BETTERCAP])

    def test_dispatcher_rotates_tools(self):
        from unittest.mock import patch

        from wiflux.config import WifluxConfig
        from wiflux.tools.deauth_backends import (
            DeauthRoundRequest,
            DeauthTool,
            HandshakeDeauthDispatcher,
        )

        cfg = WifluxConfig()
        cfg.attack.deauth_tools = ["mdk4", "aireplay"]
        with patch("wiflux.tools.deauth_backends.tool_available", return_value=True):
            dispatcher = HandshakeDeauthDispatcher(cfg, rotate=True, combo=False)
            req = DeauthRoundRequest(bssid="AA:BB:CC:DD:EE:FF", clients=[])
            with patch("wiflux.tools.deauth_backends.run_backend") as mock_run:
                dispatcher.run_round(cfg, req)
                first = mock_run.call_args[0][1]
                dispatcher.run_round(cfg, req)
                second = mock_run.call_args[0][1]
        self.assertEqual(first, DeauthTool.MDK4)
        self.assertEqual(second, DeauthTool.AIREPLAY)

    def test_dispatcher_combo_runs_all(self):
        from unittest.mock import patch

        from wiflux.config import WifluxConfig
        from wiflux.tools.deauth_backends import (
            DeauthRoundRequest,
            DeauthTool,
            HandshakeDeauthDispatcher,
        )

        cfg = WifluxConfig()
        cfg.attack.deauth_combo = True
        cfg.attack.deauth_tools = ["mdk4", "aireplay"]
        with patch("wiflux.tools.deauth_backends.tool_available", return_value=True):
            dispatcher = HandshakeDeauthDispatcher(cfg, combo=True)
            req = DeauthRoundRequest(bssid="AA:BB:CC:DD:EE:FF", clients=[])
            with patch("wiflux.tools.deauth_backends.run_backend") as mock_run:
                dispatcher.run_round(cfg, req)
        self.assertEqual(mock_run.call_count, 2)
        used = [call[0][1] for call in mock_run.call_args_list]
        self.assertEqual(used, [DeauthTool.MDK4, DeauthTool.AIREPLAY])


class TestAdaptiveDeauth(unittest.TestCase):
    def test_classify_responsive_on_eapol_gain(self):
        from wiflux.tools.adaptive_deauth import DeauthSnapshot, classify_outcome, DeauthOutcome

        before = DeauthSnapshot(eapol=0)
        after = DeauthSnapshot(eapol=2, reconnect=True)
        self.assertEqual(classify_outcome(before, after), DeauthOutcome.RESPONSIVE)

    def test_classify_silent_when_no_change(self):
        from wiflux.tools.adaptive_deauth import DeauthSnapshot, classify_outcome, DeauthOutcome

        snap = DeauthSnapshot(eapol=0, deauth_rx=0)
        self.assertEqual(classify_outcome(snap, snap), DeauthOutcome.SILENT)

    def test_engine_shortens_gap_after_responsive_round(self):
        from wiflux.tools.adaptive_deauth import AdaptiveDeauthEngine, DeauthSnapshot

        engine = AdaptiveDeauthEngine(deauth_listen=12, deauth_burst=5, channel=44)
        initial = engine.initial_params()
        after = engine.record_outcome(
            DeauthSnapshot(),
            DeauthSnapshot(eapol=1, reconnect=True),
        )
        self.assertLess(after.interval, initial.interval)
        self.assertGreater(after.listen_window, initial.listen_window)
        self.assertEqual(after.strategy, "responsive")

    def test_engine_backoff_after_repeated_silence(self):
        from wiflux.tools.adaptive_deauth import AdaptiveDeauthEngine, DeauthSnapshot

        engine = AdaptiveDeauthEngine(deauth_listen=12, deauth_burst=5, channel=6)
        snap = DeauthSnapshot()
        params = engine.initial_params()
        for _ in range(5):
            params = engine.record_outcome(snap, snap)
        self.assertGreater(params.interval, 20.0)
        self.assertEqual(params.packet_count, 2)
        self.assertEqual(params.strategy, "passive-heavy")
        self.assertGreater(params.passive_extension, 0.0)

    def test_ineffective_warning_detail(self):
        from wiflux.tools.adaptive_deauth import AdaptiveDeauthEngine, DeauthSnapshot

        engine = AdaptiveDeauthEngine(deauth_listen=12, deauth_burst=5, channel=6)
        snap = DeauthSnapshot()
        engine.record_outcome(snap, snap)
        engine.record_outcome(snap, snap)
        detail = engine.ineffective_warning_detail()
        self.assertIn("probing", detail)

    def test_engine_disabled_keeps_baseline(self):
        from wiflux.tools.adaptive_deauth import AdaptiveDeauthEngine, DeauthSnapshot

        engine = AdaptiveDeauthEngine(deauth_listen=10, deauth_burst=4, channel=11, enabled=False)
        initial = engine.initial_params()
        after = engine.record_outcome(DeauthSnapshot(), DeauthSnapshot(eapol=3))
        self.assertEqual(after.interval, initial.interval)
        self.assertEqual(after.packet_count, initial.packet_count)


class TestWpsPin(unittest.TestCase):
    def test_pin_checksum(self):
        from wiflux.tools.wps_pin import format_wps_pin, wps_pin_checksum

        self.assertEqual(wps_pin_checksum(1234567), 0)
        self.assertEqual(len(format_wps_pin(1234567)), 8)

    def test_algorithmic_pins_from_bssid(self):
        from wiflux.tools.wps_pin import algorithmic_wps_pins

        pins = algorithmic_wps_pins("3C:A6:2F:7E:AF:D1", "ASUSTek")
        self.assertGreater(len(pins), 0)
        self.assertTrue(all(len(p) == 8 and p.isdigit() for p in pins))
        self.assertEqual(len(pins), len(set(pins)))


class TestBandSiblings(unittest.TestCase):
    def test_finds_dual_band_siblings(self):
        from wiflux.tools.band_siblings import band_sibling_aps

        ap5 = AccessPoint(
            bssid="92:B4:74:3A:F1:92", channel=44, encryption=EncryptionType.WPA2,
            auth="PSK", power=79, essid="Yaxley 5ghz", essid_known=True,
        )
        ap24 = AccessPoint(
            bssid="3C:A6:2F:7E:AF:D0", channel=11, encryption=EncryptionType.WPA2,
            auth="PSK", power=60, essid="Yaxley24ghz", essid_known=True,
        )
        siblings = band_sibling_aps(ap5, [ap5, ap24])
        self.assertEqual(len(siblings), 1)
        self.assertEqual(siblings[0].bssid, ap24.bssid)

    def test_no_siblings_without_essid_match(self):
        from wiflux.tools.band_siblings import band_sibling_aps

        ap5 = AccessPoint(
            bssid="92:B4:74:3A:F1:92", channel=44, encryption=EncryptionType.WPA2,
            auth="PSK", power=79, essid="NetworkA", essid_known=True,
        )
        other = AccessPoint(
            bssid="3C:A6:2F:7E:AF:D0", channel=11, encryption=EncryptionType.WPA2,
            auth="PSK", power=60, essid="NetworkB", essid_known=True,
        )
        self.assertEqual(band_sibling_aps(ap5, [ap5, other]), [])


class TestCrackLadder(unittest.TestCase):
    def test_vendor_defaults_include_essid_suffix(self):
        from wiflux.tools.crack_ladder import generate_vendor_defaults

        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF", channel=6, encryption=EncryptionType.WPA2,
            auth="PSK", power=50, essid="CafeWiFi", essid_known=True,
            manufacturer="TP-Link",
        )
        cfg = WifluxConfig()
        words = generate_vendor_defaults(ap, cfg, max_candidates=50)
        self.assertGreater(len(words), 0)
        self.assertTrue(any("CafeWiFi" in w for w in words))

    def test_write_vendor_wordlist(self):
        from wiflux.tools.crack_ladder import write_vendor_wordlist

        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF", channel=6, encryption=EncryptionType.WPA2,
            auth="PSK", power=50, essid="TestNet", essid_known=True,
            manufacturer="Netgear",
        )
        cfg = WifluxConfig()
        result = write_vendor_wordlist(ap, cfg)
        self.assertIsNotNone(result)
        path, count = result
        try:
            self.assertGreater(count, 0)
            self.assertTrue(os.path.isfile(path))
        finally:
            os.remove(path)

    def test_discover_hashcat_rules_returns_list(self):
        from wiflux.tools.crack_ladder import discover_hashcat_rules

        rules = discover_hashcat_rules()
        self.assertIsInstance(rules, list)


class TestHandshakeBandStalk(unittest.TestCase):
    def setUp(self):
        self.tracker = ProgressTracker()
        self.tracker.discovered_targets = [
            AccessPoint(
                bssid="92:B4:74:3A:F1:92", channel=44, encryption=EncryptionType.WPA2,
                auth="PSK", power=79, essid="Yaxley 5ghz", essid_known=True,
            ),
            AccessPoint(
                bssid="3C:A6:2F:7E:AF:D0", channel=11, encryption=EncryptionType.WPA2,
                auth="PSK", power=60, essid="Yaxley24ghz", essid_known=True,
            ),
        ]
        self.cfg = WifluxConfig()
        self.ap_5 = self.tracker.discovered_targets[0]

    def test_band_stalk_targets(self):
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        targets = attack._band_stalk_targets()
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].radio_band, "2")

    def test_stalk_disabled_returns_none(self):
        self.cfg.attack.client_band_stalk = False
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        self.assertIsNone(
            attack._client_band_stalk_round(
                ["FE:32:E8:12:1E:0A"],
                started=0,
                timeout=300,
                deauth_rounds=1,
                deadline=time.time() + 60,
            ),
        )

    def test_stalk_listen_seconds_scales_with_deauth_listen(self):
        attack = HandshakeAttack(self.cfg, self.ap_5, self.tracker)
        self.cfg.attack.deauth_listen = 8
        self.assertEqual(attack._stalk_listen_seconds(), 16)
        self.cfg.attack.deauth_listen = 20
        self.assertEqual(attack._stalk_listen_seconds(), 28)


class TestWpsOffline(unittest.TestCase):
    def test_offline_pixie_without_tools(self):
        from wiflux.tools.wps_offline import try_offline_pixie

        with patch("wiflux.tools.wps_offline.which", return_value=None):
            pin, key = try_offline_pixie("/tmp/fake.cap", "AA:BB:CC:DD:EE:FF")
        self.assertIsNone(pin)
        self.assertIsNone(key)

    def test_wps_offline_success_path_sets_capfile(self):
        cfg = WifluxConfig()
        ap = AccessPoint(
            bssid="AA:BB:CC:DD:EE:FF", channel=6, encryption=EncryptionType.WPA2,
            auth="PSK", power=50, essid="Test", essid_known=True,
        )
        ap.wps = WPSState.UNLOCKED
        tracker = ProgressTracker()
        with tempfile.NamedTemporaryFile(suffix=".cap", delete=False) as tmp:
            cap_path = tmp.name
        try:
            tracker.wps_scan_caps[ap.bssid.upper()] = cap_path
            attack = WPSPixieAttack(cfg, ap, tracker)
            with patch("wiflux.attacks.wps.try_offline_pixie", return_value=(None, "secret123")):
                result = attack.run()
            self.assertTrue(result.success)
            self.assertEqual(result.crack.key, "secret123")
            self.assertEqual(result.crack.capture_file, cap_path)
        finally:
            os.remove(cap_path)


class TestNewCliFlags(unittest.TestCase):
    def test_no_crack_ladder_flag(self):
        from wiflux.cli import args_to_config, build_parser

        args = build_parser().parse_args(["--no-crack-ladder", "--auto"])
        cfg = args_to_config(args)
        self.assertFalse(cfg.attack.crack_ladder)

    def test_pmkid_passive_ratio_clamped(self):
        from wiflux.cli import args_to_config, build_parser

        args = build_parser().parse_args(["--pmkid-passive-ratio", "0.9", "--auto"])
        cfg = args_to_config(args)
        self.assertEqual(cfg.attack.pmkid_passive_ratio, 0.75)


class TestCaptureHealth(unittest.TestCase):
    def test_capture_health_dataclass(self):
        health = CaptureHealth(eapol=2, deauth=5, auth=1, assoc=0, reconnect=True)
        stats = health.as_stats()
        self.assertEqual(stats["eapol"], 2)
        self.assertEqual(stats["deauth_rx"], 5)
        self.assertTrue(stats["reconnect"])

    def test_analyze_known_cap(self):
        from wiflux.tools.capture_health import analyze_cap_health
        cap = "/root/hs/handshake_Yaxley5ghz_3C-A6-2F-7E-AF-D1_2026-06-21T14-33-34.cap"
        if not os.path.exists(cap):
            self.skipTest("cap missing")
        reset_health_cache()
        health = analyze_cap_health(cap, "3C:A6:2F:7E:AF:D1", min_interval=0)
        self.assertGreaterEqual(health.eapol, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)