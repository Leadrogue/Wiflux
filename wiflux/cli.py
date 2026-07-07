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
from rich.markup import escape as rich_escape


_SECTION_STYLE = "bold bright_cyan"
_SECTION_DESC_STYLE = "dim"
_EPILOG_HEADER_STYLE = "bold bright_yellow"
_EPILOG_HEADERS = frozenset({"Quick start", "Band scans", "Utilities"})
_LONG_ONLY_OPTS = frozenset({"--2ghz", "--5ghz"})


class RichHelpAction(argparse.Action):
    """Print help through Rich so section titles get color and emphasis."""

    def __init__(
        self,
        option_strings: list[str],
        dest: str = argparse.SUPPRESS,
        default: str = argparse.SUPPRESS,
        help: str | None = None,
    ) -> None:
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            default=default,
            nargs=0,
            help=help,
        )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | None,
        option_string: str | None = None,
    ) -> None:
        console.print(
            parser.format_help(),
            markup=True,
            soft_wrap=True,
            highlight=False,
        )
        parser.exit()


class WifluxHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Wider, section-oriented help without the giant usage banner."""

    def __init__(self, prog: str) -> None:
        try:
            width = min(100, max(88, os.get_terminal_size().columns))
        except OSError:
            width = 88
        super().__init__(prog, max_help_position=30, width=width)

    def _format_usage(self, usage, actions, groups, prefix) -> str:
        return ""

    def _format_action_invocation(self, action) -> str:
        if not action.option_strings:
            return super()._format_action_invocation(action)
        opts = action.option_strings
        long_opt = next((o for o in opts if o.startswith("--")), opts[-1])
        if long_opt in _LONG_ONLY_OPTS:
            return long_opt
        if len(opts) == 1:
            return opts[0]
        short = next((o for o in opts if o.startswith("-") and not o.startswith("--")), None)
        return f"{short}, {long_opt}" if short else long_opt

    def _get_help_string(self, action) -> str | None:
        help_text = super()._get_help_string(action)
        return rich_escape(help_text) if help_text else help_text


def _style_help_text(plain: str, *, section_titles: set[str]) -> str:
    """Apply Rich styles only to known headings; escape everything else."""
    lines_out: list[str] = []
    in_description = True

    for line in plain.splitlines():
        stripped = line.strip()
        if not stripped:
            lines_out.append("")
            continue

        if in_description:
            if stripped == "Modern wireless security auditor.":
                lines_out.append(f"[bold white]{rich_escape(stripped)}[/]")
                continue
            if not line.startswith(" ") and stripped.endswith(":"):
                in_description = False
            else:
                lines_out.append(rich_escape(line))
                continue

        if not line.startswith(" ") and stripped.endswith(":"):
            title = stripped[:-1]
            if title in section_titles:
                lines_out.append(f"[{_SECTION_STYLE}]{rich_escape(title)}[/]:")
                continue
            if title in _EPILOG_HEADERS:
                lines_out.append(f"[{_EPILOG_HEADER_STYLE}]{rich_escape(title)}[/]:")
                continue

        if (
            line.startswith("  ")
            and not line.startswith("   ")
            and not stripped.startswith("-")
            and not stripped.endswith(":")
        ):
            lines_out.append(f"  [{_SECTION_DESC_STYLE}]{rich_escape(stripped)}[/]")
            continue

        lines_out.append(rich_escape(line))

    return "\n".join(lines_out)


class WifluxArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that renders Rich-styled section headings in --help."""

    def format_help(self) -> str:
        formatter = self._get_formatter()

        if self.description:
            formatter.add_text(self.description)

        section_titles: set[str] = set()
        for action_group in self._action_groups:
            if action_group.title:
                section_titles.add(action_group.title)
                formatter.start_section(action_group.title)
            else:
                formatter.start_section(action_group.title)
            if action_group.description:
                formatter.add_text(action_group.description)
            formatter.add_arguments(action_group._group_actions)
            formatter.end_section()

        if self.epilog:
            formatter.add_text(self.epilog)

        return _style_help_text(formatter.format_help(), section_titles=section_titles)


def build_parser() -> argparse.ArgumentParser:
    p = WifluxArgumentParser(
        prog="wiflux",
        add_help=False,
        description=(
            "Modern wireless security auditor.\n\n"
            "Run without options for interactive scan and attack. "
            "Use --auto or -p for unattended operation."
        ),
        formatter_class=WifluxHelpFormatter,
        epilog="""
Quick start:
  sudo wiflux                         Interactive scan and attack
  sudo wiflux --auto -p 30            Auto-attack after 30s scan
  sudo wiflux -i wlan0mon -b AA:BB:CC Attack one access point

Band scans:
  sudo wiflux --5ghz --auto -c 36,40  5 GHz channels
  sudo wiflux --6ghz --auto -c 37,53  6 GHz (Wi-Fi 6E)

Utilities:
  sudo wiflux --cracked               List cracked networks
  sudo wiflux --export results.json   Export crack database
  sudo wiflux --check handshake.cap   Validate a capture file
        """,
    )

    p.add_argument_group("General").add_argument(
        "-h", "--help", action=RichHelpAction,
        help="Show this help message and exit",
    )

    g = p.add_argument_group("Interface", "Monitor mode and radio setup")
    g.add_argument("-i", "--interface", metavar="IFACE",
                   help="Wireless interface (monitor or managed)")
    g.add_argument("--kill", action="store_true",
                   help="Kill conflicting processes before monitor mode")
    g.add_argument("--restore", action="store_true",
                   help="Restore managed mode on exit")
    g.add_argument("--random-mac", action="store_true",
                   help="Randomize interface MAC before scan")

    g = p.add_argument_group("Scan", "Bands, channels, and target selection")
    g.add_argument("-c", "--channel", dest="channels", metavar="CH",
                   help="Comma-separated channels (e.g. ch1,ch6 or ch36-ch48)")
    g.add_argument("-2", "--2ghz", action="store_true", default=True,
                   help="Include 2.4GHz band (default: on)")
    g.add_argument("-5", "--5ghz", action="store_true",
                   help="Include 5GHz band")
    g.add_argument("--6ghz", action="store_true",
                   help="Include 6GHz band (Wi-Fi 6E)")
    g.add_argument("-p", "--pillage", dest="scan_time", type=int, default=0, metavar="SEC",
                   help="Auto-attack after SEC seconds of scanning")
    g.add_argument("-b", "--bssid", metavar="MAC",
                   help="Target a single BSSID")
    g.add_argument("-e", "--essid", metavar="NAME",
                   help="Target a single ESSID")
    g.add_argument("-E", "--ignore-essid", action="append", default=[], metavar="TEXT",
                   help="Skip ESSIDs containing TEXT (repeatable)")

    g = p.add_argument_group("Scan filters", "Narrow the target list")
    g.add_argument("--min-power", type=int, default=0, metavar="DBM",
                   help="Minimum signal strength (dBm)")
    g.add_argument("--clients-only", action="store_true",
                   help="Only APs with associated clients")
    g.add_argument("--nodecloak", action="store_true",
                   help="Do not deauth hidden APs during scan")
    g.add_argument("--ignore-cracked", action="store_true", default=True,
                   help="Skip previously cracked APs (default: on)")
    g.add_argument("--no-ignore-cracked", action="store_false", dest="ignore_cracked",
                   help="Re-attack previously cracked APs")
    g.add_argument("--wep", action="store_true", help="Show WEP networks only")
    g.add_argument("--wpa", action="store_true", help="Show WPA/WPA2 networks only")
    g.add_argument("--wpa3", action="store_true", help="Show WPA3 networks only")
    g.add_argument("--owe", action="store_true", help="Show OWE networks only")
    g.add_argument("--wps", action="store_true", help="Show WPS-enabled networks only")

    g = p.add_argument_group("Attack mode", "Which attacks run and how sessions behave")
    g.add_argument("--auto", action="store_true",
                   help="Non-interactive: attack all selected targets")
    g.add_argument("--first", dest="attack_max", type=int, default=0, metavar="N",
                   help="Attack only the first N targets")
    g.add_argument("--infinite", action="store_true",
                   help="Loop: rescan and attack continuously")
    g.add_argument("--wps-only", action="store_true",
                   help="WPS attacks only (disable PMKID and handshake)")
    g.add_argument("--pmkid", action="store_true",
                   help="PMKID capture only (disable WPS and handshake)")
    g.add_argument("--no-wps", action="store_true", help="Disable WPS attacks")
    g.add_argument("--no-pmkid", action="store_true", help="Disable PMKID capture")
    g.add_argument("--no-handshake", action="store_true", help="Disable handshake capture")
    g.add_argument("--skip-crack", action="store_true",
                   help="Capture hashes only; do not run hashcat")

    g = p.add_argument_group("WPS", "Pixie-Dust, PIN brute force, and WPS tooling")
    g.add_argument("--pixie", action="store_true",
                   help="Pixie-Dust only (skip PIN brute force)")
    g.add_argument("--no-pixie", action="store_true",
                   help="PIN brute force only (skip Pixie-Dust)")
    g.add_argument("--bully", action="store_true",
                   help="Use bully instead of reaver")
    g.add_argument("--ignore-locks", action="store_true",
                   help="Continue WPS after AP lockout")
    g.add_argument("--no-algorithmic-wps", action="store_true",
                   help="Skip MAC/vendor PIN pre-pass")
    g.add_argument("--no-offline-pixie", action="store_true",
                   help="Skip offline pixiewps from scan captures")

    g = p.add_argument_group("PMKID", "Clientless PMKID capture tuning")
    g.add_argument("--no-pmkid-band-rotate", action="store_true",
                   help="Disable dual-band sibling rotation")
    g.add_argument("--pmkid-passive-ratio", type=float, default=0.45, metavar="0.2-0.75",
                   help="Passive capture fraction of PMKID timeout (default: 0.45)")

    g = p.add_argument_group(
        "Handshake capture",
        "4-way handshake, deauth backends, and band roaming",
    )
    g.add_argument("--new-hs", action="store_true",
                   help="Ignore saved handshakes in hs/")
    g.add_argument("--no-deauth", action="store_true",
                   help="Passive capture only (no deauth)")
    g.add_argument("--no-transition-downgrade", action="store_true",
                   help="Do not prefer WPA2 on WPA2+WPA3 transition APs")
    g.add_argument("--no-client-band-stalk", action="store_true",
                   help="Disable post-deauth band-hop client listen")
    g.add_argument("--deauth-burst", type=int, default=5, metavar="PKT",
                   help="Baseline deauth packets per burst (default: 5)")
    g.add_argument("--deauth-listen", type=int, default=8, metavar="SEC",
                   help="Baseline listen window after deauth (default: 8)")
    g.add_argument("--no-adaptive-deauth", action="store_true",
                   help="Disable adaptive deauth timing")
    g.add_argument("--deauth-tools", default="auto", metavar="LIST",
                   help="Deauth backends: mdk4,aireplay,bettercap,mdk3 (default: auto)")
    g.add_argument("--deauth-combo", action="store_true",
                   help="Run every backend each deauth round")
    g.add_argument("--no-deauth-rotate", action="store_true",
                   help="Keep the first working deauth backend")
    g.add_argument("--capture-health", action="store_true",
                   help="Show live capture health panel")
    g.add_argument("--no-capture-health", action="store_true",
                   help="Disable capture health panel")
    g.add_argument("--yes-capture-health", action="store_true",
                   help="Enable capture health without prompting")

    g = p.add_argument_group("Cracking", "Wordlists, smart candidates, and hashcat stages")
    g.add_argument("--dict", dest="wordlist", metavar="FILE",
                   help="Wordlist for hashcat (default: auto-detect)")
    g.add_argument("--no-crack-ladder", action="store_true",
                   help="Skip vendor defaults and hashcat rules")
    g.add_argument("--smart-wordlist", action="store_true",
                   help="Offer ESSID-smart wordlist before full dictionary")
    g.add_argument("--no-smart-wordlist", action="store_true",
                   help="Never offer ESSID-smart wordlist")
    g.add_argument("--yes-smart-wordlist", action="store_true",
                   help="Use smart wordlist immediately")
    g.add_argument("--smart-wordlist-size", type=int, default=0, metavar="N",
                   help="Smart wordlist size (default: prompt, max 100000)")

    g = p.add_argument_group("Timeouts", "Per-attack time limits in seconds")
    g.add_argument("--wpa-timeout", type=int, default=300, metavar="SEC",
                   help="Handshake capture timeout (default: 300)")
    g.add_argument("--pmkid-timeout", type=int, default=120, metavar="SEC",
                   help="PMKID capture timeout (default: 120)")
    g.add_argument("--wps-timeout", type=int, default=300, metavar="SEC",
                   help="WPS attack timeout (default: 300)")
    g.add_argument("--wept", type=int, default=600, metavar="SEC",
                   help="WEP attack timeout (default: 600)")

    g = p.add_argument_group("Output", "Logging, paths, and display")
    g.add_argument("-v", "--verbose", action="count", default=0,
                   help="Increase verbosity (-v, -vv)")
    g.add_argument("-q", "--quiet", action="store_true",
                   help="Minimal output (no live UI)")
    g.add_argument("--json", action="store_true",
                   help="Machine-readable JSON output")
    g.add_argument("--data-dir", default="wiflux-data", metavar="DIR",
                   help="Database and session directory")
    g.add_argument("--config", metavar="FILE",
                   help="Load settings from JSON config file")
    g.add_argument("--no-splash", action="store_true",
                   help="Skip welcome splash screen")

    g = p.add_argument_group("Utility commands", "Inspect data without scanning")
    g.add_argument("--cracked", action="store_true",
                   help="List cracked networks from database")
    g.add_argument("--ignored", action="store_true",
                   help="List ignored access points")
    g.add_argument("--export", metavar="FILE",
                   help="Export crack database to JSON")
    g.add_argument("--check", nargs="?", const="<all>", metavar="FILE",
                   help="Validate .cap file(s) for handshake")
    g.add_argument("--crack", action="store_true",
                   help="Print hashcat/aircrack commands for captures")
    g.add_argument("--update-db", action="store_true",
                   help="Update IEEE OUI vendor database")

    return p


def args_to_config(args: argparse.Namespace) -> WifluxConfig:
    if args.config:
        cfg = WifluxConfig.from_file(args.config)
    else:
        cfg = WifluxConfig()

    if args.interface is not None:
        cfg.scan.interface = args.interface
    if args.channels is not None:
        cfg.scan.channels = args.channels
    cfg.scan.band_5ghz = bool(args.__dict__.get("5ghz", False))
    cfg.scan.band_6ghz = bool(args.__dict__.get("6ghz", False))
    has_high_band = cfg.scan.band_5ghz or cfg.scan.band_6ghz
    cfg.scan.band_2ghz = args.__dict__.get("2ghz", True) or not has_high_band
    if cfg.scan.band_5ghz:
        cfg.scan.band_2ghz = True
        cfg.scan.band_5ghz = True
    if cfg.scan.band_6ghz:
        cfg.scan.band_2ghz = True
    cfg.scan.scan_time = args.scan_time
    cfg.scan.min_power = args.min_power
    cfg.scan.clients_only = args.clients_only
    if args.bssid is not None:
        cfg.scan.target_bssid = args.bssid
    if args.essid is not None:
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
    cfg.attack.transition_downgrade = not args.no_transition_downgrade
    cfg.attack.algorithmic_wps = not args.no_algorithmic_wps
    cfg.attack.offline_pixie = not args.no_offline_pixie
    cfg.attack.crack_ladder = not args.no_crack_ladder
    cfg.attack.client_band_stalk = not args.no_client_band_stalk
    cfg.attack.pmkid_band_rotate = not args.no_pmkid_band_rotate
    cfg.attack.pmkid_passive_ratio = max(0.2, min(0.75, args.pmkid_passive_ratio))
    cfg.attack.wep_timeout = args.wept
    cfg.attack.no_deauth = args.no_deauth
    cfg.attack.deauth_burst = args.deauth_burst
    cfg.attack.deauth_listen = args.deauth_listen
    cfg.attack.adaptive_deauth = not args.no_adaptive_deauth
    if args.deauth_tools and args.deauth_tools != "auto":
        cfg.attack.deauth_tools = [
            part.strip() for part in args.deauth_tools.split(",") if part.strip()
        ]
    cfg.attack.deauth_combo = args.deauth_combo
    cfg.attack.deauth_rotate = not args.no_deauth_rotate
    cfg.attack.skip_crack = args.skip_crack
    cfg.attack.wordlist = find_wordlist(args.wordlist)
    if args.capture_health:
        cfg.attack.capture_health = True
    elif args.no_capture_health:
        cfg.attack.capture_health = False
    cfg.attack.yes_capture_health = args.yes_capture_health
    if args.smart_wordlist:
        cfg.attack.smart_wordlist = True
    elif args.no_smart_wordlist:
        cfg.attack.smart_wordlist = False
    cfg.attack.yes_smart_wordlist = args.yes_smart_wordlist
    if args.smart_wordlist_size > 0:
        from .tools.smart_wordlist import clamp_wordlist_size
        cfg.attack.smart_wordlist_size = clamp_wordlist_size(args.smart_wordlist_size)
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