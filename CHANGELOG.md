# Changelog

All notable changes to **Wiflux** are documented here.

## [Unreleased]

_(nothing yet)_

## [1.0.3] — 2026-07-07

### Highlights

- **Attack enhancements** — Algorithmic WPS PIN pre-pass, offline pixiewps from scan caps, extended PMKID capture with band rotation, client band-stalk listen, and multi-stage crack ladder (vendor defaults → hashcat rules → full dictionary)
- **WPA2/WPA3 transition mode** — Prefer WPA2 handshake/PMKID capture and hashcat mode 22000 on mixed networks (`--no-transition-downgrade` to disable)
- **6 GHz scanning** — `--6ghz` for Wi-Fi 6E targets (with supported adapters)
- **PMKID success screen** — Cyan confirmation panel and banner before smart wordlist (matches handshake validation flow)
- **Improved `--help`** — Grouped sections, colored headings, scan/scan-filters split; 89 automated tests

### Added

- **Adaptive deauth engine** — Tunes deauth burst, interval, and listen window from capture-health feedback. `--no-adaptive-deauth` to disable.
- **Multi-backend deauth** — Rotate mdk4, aireplay-ng, bettercap, mdk3 (`--deauth-tools`, `--deauth-combo`, `--no-deauth-rotate`)
- **Algorithmic WPS PIN** — MAC/vendor-derived PIN candidates before live reaver (`--no-algorithmic-wps`)
- **Offline pixiewps** — Parse WPS from scan caps before live attacks (`--no-offline-pixie`; needs `pixiewps`, `tshark`)
- **PMKID extended capture** — Passive-first timeout ratio and dual-band sibling rotation (`--pmkid-passive-ratio`, `--no-pmkid-band-rotate`)
- **Client band-stalk** — Post-deauth listen on sibling bands for roaming clients (`--no-client-band-stalk`)
- **Crack ladder** — Vendor default passwords and hashcat rules before rockyou (`--no-crack-ladder`)
- **Handshake validation UI** — Full hcxpcapngtool validation with on-screen confirm before cracking
- **`--new-hs`** — Force fresh handshake capture; requires deauth round before accepting passive candidate
- **`--no-ignore-cracked`** — Re-show and re-attack networks already in the crack database
- **CLI help overhaul** — Sectioned, colorized `-h` output (General, Scan, Scan filters, WPS, PMKID, Handshake capture, Cracking, Timeouts, …)

### Fixes

- **WPS offline path** — `capfile` initialized correctly on offline pixie success
- **Help output** — Rich number highlighter disabled so channel/default values are not bolded
- **Band flags** — Help shows `--2ghz` / `--5ghz` long form (short `-2`/`-5` still work)

### Install

```bash
curl -LO https://github.com/Leadrogue/Wiflux/releases/download/v1.0.3/wiflux-1.0.3-linux-installer.tar.gz
tar -xzf wiflux-1.0.3-linux-installer.tar.gz
cd wiflux-1.0.3-linux-installer
./install.sh
```

---

## [1.0.2] — 2026-07-04

### Fixes

- **Installer banner** — `install.sh` now detects the bundled wheel version instead of printing a hardcoded `1.0.0`
- **sudo PATH on Kali/Debian** — installer post-install hints and docs explain that `sudo wiflux` may fail because `/usr/local/bin` is not in sudo's `PATH`; use `sudo env PATH="/usr/local/bin:$PATH" wiflux` or `sudo /usr/local/bin/wiflux`

### Install

```bash
curl -LO https://github.com/Leadrogue/Wiflux/releases/download/v1.0.2/wiflux-1.0.2-linux-installer.tar.gz
tar -xzf wiflux-1.0.2-linux-installer.tar.gz
cd wiflux-1.0.2-linux-installer
./install.sh
```

---

## [1.0.1] — 2026-07-04

### Highlights

- **ESSID-smart wordlist** — targeted password candidates generated from the network name, vendor OUI, and common Wi‑Fi patterns before falling back to rockyou
- **Live capture health panel** — real-time EAPOL / deauth / reconnect counters during handshake capture
- **Reactive handshake capture** — per-client deauth rounds with mdk4/aireplay instead of blind continuous blasting
- **Probing client detection** — scan table now counts stations probing an ESSID, not only associated clients
- **40 automated tests** — parser, orchestration, smart wordlist, capture health, and handshake logic

---

### ✨ New features

#### ESSID-smart wordlist

Before hashcat runs against the full rockyou dictionary, Wiflux can generate a **targeted wordlist** from the target AP:

- **ESSID mutations** — case variants, separators, years (`Workshop2024`), suffixes (`Workshop123`, `Workshop!`), leet (`W0rkshop`), prefixes (`myWorkshop`, `wifiWorkshop`)
- **Vendor defaults** — TP-Link, Netgear, BT, Sky, TalkTalk, Vodafone, and others via IEEE OUI lookup
- **BSSID-derived candidates** — fragments of the MAC address as password guesses
- **Interactive flow** — preview **8 examples**, Y/N prompt, then choose word count (default **1,000**, max **100,000**) with a generation animation
- **Two-pass crack** — smart list first; if no hit, Activity logs *"password not found"* and continues with rockyou

**Example preview** for ESSID `Workshop` (TP-Link router):

```
Workshop
workshop
Workshop123
Workshop2024
Workshop!
myWorkshop
wifiWorkshop
W0rkshop123
```

**CLI usage:**

```bash
# Interactive (default) — preview + Y/N + word count prompt
sudo wiflux --kill

# Skip prompts; use smart list immediately (1,000 passwords)
sudo wiflux --yes-smart-wordlist

# Fixed size, no prompts
sudo wiflux --yes-smart-wordlist --smart-wordlist-size 5000

# Disable smart wordlist entirely
sudo wiflux --no-smart-wordlist
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--smart-wordlist` | Force offer in non-default cases |
| `--no-smart-wordlist` | Never offer; rockyou only |
| `--yes-smart-wordlist` | Accept immediately, no preview |
| `--smart-wordlist-size N` | Generate N candidates (max 100,000) |

#### Live capture health

Optional panel during handshake capture showing EAPOL frames, deauth activity, auth/assoc, and reconnect detection.

```bash
sudo wiflux --yes-capture-health    # enable without prompt
sudo wiflux --no-capture-health     # disable
```

#### Improved handshake capture

- Passive listen window before first deauth (12s on 2.4 GHz, 20s on 5 GHz)
- Per-client deauth via **mdk4** (fallback: aireplay-ng) on a configurable interval
- Post-deauth RX window (default 8s) to catch EAPOL
- **Band-block** deauth on 2.4 GHz sibling when attacking 5 GHz (shared PSK)
- **2.4 GHz fallback** when 5 GHz deauth is ineffective
- Uses existing captures in `hs/` unless `--new-hs`
- `hcxpcapngtool`-based handshake detection (more reliable than aircrack alone on airodump caps)

#### Scan improvements

- **Probing clients** — stations listed as `(not associated)` in airodump but probing a visible ESSID are now linked to that AP in the **CL** column
- Client packet counts parsed from CSV

---

### 🐛 Bug fixes

| Area | Fix |
|------|-----|
| **Smart wordlist prompt** | Y/N keys were consumed by the Space-skip listener; prompts now suspend the live UI and register correctly |
| **Smart wordlist declined** | Pressing Y no longer incorrectly logged as "declined" |
| **Capture health prompt** | Hidden tty prompt blocked handshake at "Preparing..."; now uses the same visible panel flow as smart wordlist |
| **Handshake hang (init)** | Status shows `Checking cached handshakes...` before any blocking prompt |
| **PMKID → handshake** | Interface is always restored after hcxdumptool so handshake capture can start |
| **Hidden ESSIDs** | Scan table no longer mislabels all networks as `(BSSID)` when beacons lack ESSID IE (mesh/virtual APs) |
| **Activity logging** | Clear message when smart wordlist misses: *"password not found, continuing with full dictionary rockyou.txt"* |
| **Config file merge** | Omitting `--interface` / `--channels` / `-b` / `-e` no longer wipes saved config values |
| **Client filtering** | Multicast and bogus MACs filtered; stale PWR `-1` clients ignored for deauth targeting |

---

### 🔧 Changes

- Default `--deauth-listen` reduced from 20s to **8s** (reactive model)
- Default `num_deauths` increased to **8**
- Handshake attack logs deauth tool used (mdk4 vs aireplay), target client, and band-block actions
- Crack phase logs hashcat pass `1/2` (smart) and `2/2` (rockyou) in Activity

---

### 📦 Install (v1.0.1)

```bash
# Recommended — installer bundle
curl -LO https://github.com/Leadrogue/Wiflux/releases/download/v1.0.1/wiflux-1.0.1-linux-installer.tar.gz
tar -xzf wiflux-1.0.1-linux-installer.tar.gz
cd wiflux-1.0.1-linux-installer
./install.sh

# Or pip from wheel
pip install https://github.com/Leadrogue/Wiflux/releases/download/v1.0.1/wiflux-1.0.1-py3-none-any.whl --break-system-packages
```

---

## [1.0.0] — 2026-06-17

Initial public release.

- Live Rich terminal UI with scan and attack progress tables
- Attack orchestration: WEP → WPS pixie → WPS PIN → PMKID → handshake
- Hidden ESSID decloak during scan
- WPS detection via wash
- WPA handshake capture and hashcat cracking
- PMKID capture via hcxdumptool
- SQLite crack result storage
- GitHub release packaging (wheel, sdist, linux installer)

> For authorized security testing only.

[1.0.3]: https://github.com/Leadrogue/Wiflux/compare/v1.0.2...v1.0.3
[1.0.2]: https://github.com/Leadrogue/Wiflux/compare/v1.0.1...v1.0.2
[1.0.1]: https://github.com/Leadrogue/Wiflux/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/Leadrogue/Wiflux/releases/tag/v1.0.0