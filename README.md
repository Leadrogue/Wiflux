# Wiflux

**Modern wireless security auditor** with a live terminal UI, smart attack orchestration, and built-in dependency management.

```
██╗    ██╗██╗███████╗██╗     ██╗   ██╗██╗  ██╗
██║    ██║██║██╔════╝██║     ██║   ██║╚██╗██╔╝
██║ █╗ ██║██║█████╗  ██║     ██║   ██║ ╚███╔╝
██║███╗██║██║██╔══╝  ██║     ██║   ██║ ██╔██╗
╚███╔███╔╝██║██║     ███████╗╚██████╔╝██╔╝ ██╗
 ╚══╝╚══╝ ╚═╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝
```

> **For authorized security testing only.** Only use Wiflux on networks you own or have explicit permission to audit.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## Features

- **Live Rich UI** — Real-time scan table with signal, encryption, WPS status, clients, and priority scoring
- **Matrix welcome screen** — Optional splash with dependency check on startup
- **Smart attack order** — WEP → WPS Pixie → WPS PIN → PMKID → Handshake, skipping irrelevant methods
- **Multi-factor target ranking** — SCORE combines signal, clients, encryption, and WPS state
- **WPS detection** — Background `wash` probing during scan with lock/status display
- **Hidden SSID decloak** — Deauth probe to reveal cloaked ESSIDs during scan
- **SQLite results store** — Track cracked networks, ignores, and export to JSON
- **Dependency manager** — Detects missing tools and offers one-shot `apt` install
- **Full automation** — `--auto`, timed scan (`-p` / `--pillage`), and filter flags
- **Skip controls** — Press `Space` to skip the current attack mid-run

### Supported attacks

| Attack | Tools | Notes |
|--------|-------|-------|
| WEP | `aireplay-ng`, `aircrack-ng` | ARP replay with configurable timeout |
| WPS Pixie-Dust | `reaver` / `bully` | Early bail on repeated timeouts |
| WPS PIN | `reaver` / `bully` | Optional lock ignoring |
| PMKID | `hcxdumptool`, `hcxpcapngtool` | Clientless capture |
| WPA handshake | `aireplay-ng`, `aircrack-ng` | Burst/listen deauth rhythm |

---

## Quick start

```bash
# Clone and install
git clone https://github.com/Leadrogue/wiflux.git
cd wiflux
pip install -e . --break-system-packages

# Interactive audit
sudo wiflux --kill --restore

# Auto-attack after 30s scan
sudo wiflux --auto -p 30
```

See the full [Installation Guide](INSTALL.md) and [Tutorial](docs/TUTORIAL.md).

---

## Documentation

| Document | Description |
|----------|-------------|
| [INSTALL.md](INSTALL.md) | Requirements, adapter setup, wordlists, troubleshooting |
| [docs/TUTORIAL.md](docs/TUTORIAL.md) | Step-by-step walkthrough from first run to attacks |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup and pull request guidelines |

---

## Usage examples

```bash
# Show all options
wiflux --help

# 5 GHz scan, auto-attack
sudo wiflux --5ghz --auto -p 45

# Target a specific network
sudo wiflux -b AA:BB:CC:DD:EE:FF --auto

# WPS Pixie-Dust only on WPS networks
sudo wiflux --wps --wps-only --pixie --auto

# Capture handshakes without cracking
sudo wiflux --skip-crack --auto -p 30

# Utility commands (no sudo needed)
wiflux --cracked
wiflux --check capture.cap
wiflux --export results.json
```

### Key options

| Flag | Description |
|------|-------------|
| `-i INTERFACE` | Wireless interface (e.g. `wlan0mon`) |
| `--kill` / `--restore` | Kill interfering processes / restore managed mode |
| `-p SECONDS` | Auto-attack after N seconds of scanning |
| `--auto` | Non-interactive mode |
| `--5ghz` | Include 5 GHz channels |
| `--wps` / `--wpa` / `--wep` | Filter scan results |
| `--pixie` / `--no-pixie` | Control WPS attack mode |
| `--pmkid` / `--no-pmkid` | Control PMKID capture |
| `--deauth-burst` / `--deauth-listen` | Handshake deauth timing (default 10s / 20s) |
| `--dict FILE` | Custom wordlist |
| `--no-splash` | Skip welcome screen |

---

## Architecture

```
wiflux/
├── cli.py           # Entry point, argument parsing
├── scanner.py       # AP discovery, WPS probe, decloak
├── orchestrator.py  # Attack sequencing
├── progress.py      # Live Rich UI
├── results.py       # SQLite persistence
├── dependencies.py  # Tool detection + apt install
├── attacks/         # WEP, WPS, PMKID, handshake
└── tools/           # Wrappers for aircrack-ng, reaver, hashcat, etc.
```

Configuration uses **dataclasses** (`WifluxConfig`) instead of global singletons — easy to test, extend, and serialize to JSON.

---

## Requirements

- Linux (Kali, Parrot, etc.)
- Python 3.10+
- Wi-Fi adapter with monitor mode + injection
- [aircrack-ng](https://www.aircrack-ng.org/) suite (required)
- [reaver](https://github.com/t6x/reaver-wps-fork-t6x), [hcxdumptool](https://github.com/ZerBea/hcxdumptool), [hashcat](https://hashcat.net/hashcat/) (optional, recommended)

---

## Legal disclaimer

This tool is provided for educational and authorized penetration testing purposes only. Unauthorized access to computer networks is illegal. The authors and contributors are not responsible for misuse of this software.

---

## License

[MIT License](LICENSE) — Copyright (c) 2026 Wiflux Contributors