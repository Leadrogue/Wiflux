"""Command-line interface."""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .config import WifluxConfig, find_wordlist
from .dependencies import missing_required, run_startup_dependency_check
from .display import banner, console, print_error, print_info, safe_markup, supports_live
from .splash import show_splash
from .utilities import check_handshakes, show_crack_commands, show_ignored, update_oui_database
from .orchestrator import Orchestrator
from .process import ProcessPool, which
from .progress import reset_tracker
from .results import ResultStore
from .scanner import Scanner
from .tools.airmon import Airmon


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wiflux",
        description="Modern wireless security auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo wiflux                          Interactive scan & attack
  sudo wiflux --auto -p 30             Auto-attack all targets after 30s scan
  sudo wiflux -i wlan0mon -b AA:BB:CC  Attack specific AP
  sudo wiflux --5ghz --auto -c 36,40   5GHz channel scan
  sudo wiflux --cracked                 Show previously cracked networks
  sudo wiflux --export results.json     Export crack database
        """,
    )

    g = p.add_argument_group("Interface")
    g.add_argument("-i", "--interface", help="Wireless interface (monitor or managed)")
    g.add_argument("--kill", action="store_true", help="Kill conflicting processes (airmon-ng check kill)")
    g.add_argument("--restore", action="store_true", help="Restore managed mode on exit")
    g.add_argument("--random-mac", action="store_true", help="Randomize MAC before scan")

    g = p.add_argument_group("Scan")
    g.add_argument("-c", "--channel", dest="channels", help="Channel(s) e.g. 1,6,11 or 36-48")
    g.add_argument("-2", "--2ghz", action="store_true", default=True, help="Scan 2.4GHz (default)")
    g.add_argument("-5", "--5ghz", action="store_true", help="Scan 5GHz")
    g.add_argument("-p", "--pillage", dest="scan_time", type=int, default=0,
                   help="Auto-attack after N seconds of scanning")
    g.add_argument("--min-power", type=int, default=0, help="Minimum signal strength")
    g.add_argument("--clients-only", action="store_true", help="Only show APs with clients")
    g.add_argument("-b", "--bssid", help="Target specific BSSID")
    g.add_argument("-e", "--essid", help="Target specific ESSID")
    g.add_argument("-E", "--ignore-essid", action="append", default=[], help="Ignore ESSIDs matching text")
    g.add_argument("--nodecloak", action="store_true", help="Don't deauth hidden APs to reveal ESSIDs during scan")
    g.add_argument("--ignore-cracked", action="store_true", default=True, help="Skip previously cracked APs")
    g.add_argument("--no-ignore-cracked", action="store_false", dest="ignore_cracked")
    g.add_argument("--wep", action="store_true", help="Show only WEP networks")
    g.add_argument("--wpa", action="store_true", help="Show only WPA/WPA2 networks")
    g.add_argument("--wpa3", action="store_true", help="Show only WPA3 networks")
    g.add_argument("--owe", action="store_true", help="Show only OWE networks")
    g.add_argument("--wps", action="store_true", help="Show only WPS-enabled networks")

    g = p.add_argument_group("Attack")
    g.add_argument("--auto", action="store_true", help="Non-interactive: attack all targets automatically")
    g.add_argument("--wps-only", action="store_true", help="Only WPS attacks")
    g.add_argument("--no-wps", action="store_true", help="Disable WPS attacks")
    g.add_argument("--pixie", action="store_true", help="WPS Pixie-Dust only (no PIN)")
    g.add_argument("--no-pixie", action="store_true", help="WPS PIN only (no Pixie-Dust)")
    g.add_argument("--ignore-locks", action="store_true", help="Continue WPS when AP locks")
    g.add_argument("--pmkid", action="store_true", help="PMKID capture only")
    g.add_argument("--no-pmkid", action="store_true", help="Disable PMKID capture")
    g.add_argument("--no-handshake", action="store_true", help="Disable handshake capture")
    g.add_argument("--new-hs", action="store_true", help="Ignore existing handshakes in hs/")
    g.add_argument("--wept", type=int, default=600, help="WEP attack timeout (seconds)")
    g.add_argument("--no-deauth", action="store_true", help="Passive mode (no deauth)")
    g.add_argument("--deauth-burst", type=int, default=10,
                   help="Seconds of continuous deauth blitz during handshake capture (default: 10)")
    g.add_argument("--deauth-listen", type=int, default=20,
                   help="Seconds to listen between deauth blitzes (default: 20)")
    g.add_argument("--skip-crack", action="store_true", help="Capture only, don't crack")
    g.add_argument("--dict", dest="wordlist", help="Wordlist for cracking")
    g.add_argument("--first", dest="attack_max", type=int, default=0, help="Attack first N targets")
    g.add_argument("--bully", action="store_true", help="Use bully for WPS")
    g.add_argument("--wpa-timeout", type=int, default=300)
    g.add_argument("--pmkid-timeout", type=int, default=120)
    g.add_argument("--wps-timeout", type=int, default=300)


    g = p.add_argument_group("Output")
    g.add_argument("-v", "--verbose", action="count", default=0)
    g.add_argument("-q", "--quiet", action="store_true")
    g.add_argument("--json", action="store_true", help="JSON-friendly output")
    g.add_argument("--data-dir", default="wiflux-data", help="Data directory")
    g.add_argument("--config", help="Load config from JSON file")

    g = p.add_argument_group("Commands")
    g.add_argument("--cracked", action="store_true", help="Show cracked networks")
    g.add_argument("--ignored", action="store_true", help="Show ignored access points")
    g.add_argument("--export", metavar="FILE", help="Export cracks to JSON")
    g.add_argument("--check", nargs="?", const="<all>", metavar="FILE", help="Check .cap for handshake")
    g.add_argument("--crack", action="store_true", help="Show hashcat/aircrack commands for captures")
    g.add_argument("--update-db", action="store_true", help="Update IEEE OUI vendor database")
    g.add_argument("--infinite", action="store_true", help="Continuous scan/attack loop")
    g.add_argument("--no-splash", action="store_true", help="Skip Matrix welcome screen")

    return p


def args_to_config(args: argparse.Namespace) -> WifluxConfig:
    if args.config:
        cfg = WifluxConfig.from_file(args.config)
    else:
        cfg = WifluxConfig()

    cfg.scan.interface = args.interface
    cfg.scan.channels = args.channels
    cfg.scan.band_2ghz = args.__dict__.get("2ghz", True) or not args.__dict__.get("5ghz", False)
    cfg.scan.band_5ghz = args.__dict__.get("5ghz", False)
    if args.__dict__.get("5ghz"):
        cfg.scan.band_2ghz = True
        cfg.scan.band_5ghz = True
    cfg.scan.scan_time = args.scan_time
    cfg.scan.min_power = args.min_power
    cfg.scan.clients_only = args.clients_only
    cfg.scan.target_bssid = args.bssid
    cfg.scan.target_essid = args.essid
    cfg.scan.ignore_essids = args.ignore_essid or []
    cfg.scan.decloak = not args.nodecloak
    cfg.scan.ignore_cracked = args.ignore_cracked
    cfg.scan.filter_wep = args.wep
    cfg.scan.filter_wpa = args.wpa
    cfg.scan.filter_wpa3 = args.wpa3
    cfg.scan.filter_owe = args.owe
    cfg.scan.filter_wps = args.wps

    cfg.attack.wps = not args.no_wps
    cfg.attack.wps_pixie_only = args.pixie
    cfg.attack.wps_no_pixie = args.no_pixie
    cfg.attack.wps_ignore_locks = args.ignore_locks
    cfg.attack.pmkid_only = args.pmkid
    if args.wps_only:
        cfg.attack.pmkid = False
        cfg.attack.handshake = False
    if args.pmkid:
        cfg.attack.wps = False
        cfg.attack.handshake = False
        cfg.attack.pmkid = True
    else:
        cfg.attack.pmkid = not args.no_pmkid and not args.wps_only
        cfg.attack.handshake = not args.no_handshake and not args.wps_only
    cfg.attack.new_handshake = args.new_hs
    cfg.attack.wep_timeout = args.wept
    cfg.attack.no_deauth = args.no_deauth
    cfg.attack.deauth_burst = args.deauth_burst
    cfg.attack.deauth_listen = args.deauth_listen
    cfg.attack.skip_crack = args.skip_crack
    cfg.attack.wordlist = find_wordlist(args.wordlist)
    cfg.attack.attack_max = args.attack_max
    cfg.attack.use_bully = args.bully
    cfg.attack.wpa_timeout = args.wpa_timeout
    cfg.attack.pmkid_timeout = args.pmkid_timeout
    cfg.attack.wps_timeout = args.wps_timeout
    cfg.output.data_dir = args.data_dir
    cfg.output.verbose = args.verbose
    cfg.output.quiet = args.quiet
    cfg.output.json_output = args.json

    cfg.auto_mode = args.auto or args.scan_time > 0
    cfg.kill_conflicting = args.kill
    cfg.random_mac = args.random_mac
    cfg.restore_managed = args.restore
    cfg.infinite = args.infinite

    return cfg


def check_requirements() -> None:
    if os.name == "nt":
        print_error("Wiflux requires Linux")
        sys.exit(1)
    if os.getuid() != 0:
        print_error("Wiflux must run as root (sudo)")
        sys.exit(1)
    req = missing_required()
    if req:
        print_error(f"Missing required tools: {', '.join(d.binary for d in req)}")
        sys.exit(1)


def _is_command_mode(args: argparse.Namespace) -> bool:
    return bool(
        args.cracked or args.export or args.ignored
        or args.check is not None or args.crack or args.update_db
    )


def setup_interface(cfg: WifluxConfig) -> str:
    iface = cfg.scan.interface
    if not iface:
        iface = Airmon.ask()
    if Airmon.is_monitor(iface):
        print_info(f"Using {iface} (already in monitor mode)")
    else:
        print_info(f"Enabling monitor mode on {iface}...")
        mon_iface = Airmon.start(iface, kill_conflicts=cfg.kill_conflicting)
        if mon_iface != iface:
            print_info(f"Monitor interface: {mon_iface}")
        iface = mon_iface
    cfg.scan.interface = iface
    return iface


def run_commands(cfg: WifluxConfig, args: argparse.Namespace) -> bool:
    store = ResultStore(cfg.output.data_dir)
    if args.cracked:
        cracks = store.list_cracks()
        if not cracks:
            print_info("No cracked networks in database.")
        for c in cracks:
            console.print(
                f"  [cyan]{safe_markup(c.essid)}[/] [dim]{safe_markup(c.bssid)}[/] "
                f"→ [yellow]{safe_markup(c.key)}[/] [{c.method}]"
            )
        return True
    if args.export:
        store.export_json(args.export)
        print_info(f"Exported to {args.export}")
        return True
    if args.ignored:
        show_ignored(cfg)
        return True
    if args.check is not None:
        check_handshakes(args.check, cfg)
        return True
    if args.crack:
        show_crack_commands(cfg)
        return True
    if args.update_db:
        update_oui_database(cfg)
        return True
    return False


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    cfg = args_to_config(args)

    command_mode = _is_command_mode(args)

    if not command_mode and not cfg.output.quiet and not cfg.output.json_output:
        if supports_live() and not args.no_splash:
            show_splash(__version__)
            run_startup_dependency_check()
        banner(__version__)
    elif command_mode:
        banner(__version__)

    if run_commands(cfg, args):
        return 0

    check_requirements()
    tracker = reset_tracker()
    store = ResultStore(cfg.output.data_dir)
    mon_iface = None

    try:
        mon_iface = setup_interface(cfg)
        session_id = store.start_session(mon_iface)

        while True:
            scanner = Scanner(cfg, store, tracker)
            if cfg.output.quiet:
                print_info("Scanning for wireless networks...")
            try:
                targets = scanner.scan()
            except KeyboardInterrupt:
                from .models import rank_targets
                targets = rank_targets(scanner.targets)
                if cfg.output.quiet:
                    print_info(f"Scan stopped. {len(targets)} targets found.")

            if not targets:
                print_error("No targets found.")
                break

            selected = scanner.select_targets(targets)
            if not selected:
                print_info("No targets selected.")
                break

            store.update_session(session_id, targets_found=len(targets))
            orch = Orchestrator(cfg, store, tracker)
            cracked = orch.attack_all(selected)
            store.update_session(session_id, targets_attacked=len(selected), cracks=cracked)
            print_info(f"Finished. {cracked}/{len(selected)} cracked.")

            if not cfg.infinite:
                break
            print_info("Infinite mode: rescanning...")

    except KeyboardInterrupt:
        print_info("Interrupted.")
    finally:
        ProcessPool().cleanup_all()
        if cfg.restore_managed and mon_iface:
            print_info("Restoring managed mode...")
            Airmon.stop(mon_iface)

    return 0


if __name__ == "__main__":
    sys.exit(main())