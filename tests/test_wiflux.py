#!/usr/bin/env python3
"""Wiflux unit and integration tests (no live radio required)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wiflux.attacks.handshake import HandshakeAttack
from wiflux.attacks.pmkid import PMKIDAttack
from wiflux.attacks.wps import WPSPixieAttack
from wiflux.config import WifluxConfig, find_wordlist
from wiflux.models import AccessPoint, Client, EncryptionType, rank_targets
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

    def test_existing_cap_for_5ghz(self):
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