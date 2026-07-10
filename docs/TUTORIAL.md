# Wiflux Tutorial

A hands-on guide to scanning, selecting targets, and running attacks with Wiflux.

> **Reminder:** Use Wiflux only on networks you own or are authorized to test. Unauthorized access is illegal.

---

## Table of contents

1. [First run](#1-first-run)
2. [The welcome screen](#2-the-welcome-screen)
3. [Scanning for targets](#3-scanning-for-targets)
4. [Understanding the live table](#4-understanding-the-live-table)
5. [Selecting targets](#5-selecting-targets)
6. [Attack phase](#6-attack-phase)
7. [Common workflows](#7-common-workflows)
8. [Utility commands](#8-utility-commands)
9. [Tips and best practices](#9-tips-and-best-practices)

---

## 1. First run

After [installing Wiflux](../INSTALL.md), start an interactive session:

```bash
sudo env PATH="/usr/local/bin:$PATH" wiflux --kill --restore
```

> **Kali/Debian:** `sudo` often excludes `/usr/local/bin` from `PATH`. If `sudo wiflux` fails with "command not found", use the command above or `sudo /usr/local/bin/wiflux`. See [INSTALL.md — Running with sudo](../INSTALL.md#running-with-sudo).

| Flag | What it does |
|------|--------------|
| `--kill` | Stops NetworkManager and other processes that block monitor mode |
| `--restore` | Returns your interface to managed mode when you exit |

On first launch, Wiflux may prompt you to install missing dependencies via `apt`. Accept the prompt on Kali/Debian systems to install `aircrack-ng`, `reaver`, `hcxdumptool`, and related tools.

---

## 2. The welcome screen

Wiflux opens with a Matrix-style rain animation and the Wiflux logo.

**Press `Space`** to continue to the scan phase.

Skip the splash on future runs:

```bash
sudo wiflux --no-splash
```

### Dependency check

After the welcome screen (or immediately with `--no-splash`), Wiflux shows a **dependency check** panel:

1. Verifies aircrack-ng tools, hashcat, hcx tools, reaver/wash, etc.
2. Checks for **`/usr/share/wordlists/rockyou.txt`**
3. If only **`rockyou.txt.gz`** is present, **unpacks it automatically** (needs sudo write access)

Press **Space** when the check finishes. Missing packages can be installed via apt when offered.

---

## 3. Scanning for targets

Once scanning begins, Wiflux:

1. Puts your wireless interface into **monitor mode** (unless already in monitor mode)
2. Runs `airodump-ng` across 2.4 GHz channels (and 5 GHz if requested)
3. Probes **WPS** status in the background via `wash`
4. Optionally **decloaks** hidden networks by sending deauth frames

### While waiting for results

Before the first access points appear, you'll see a **Searching** panel with a pulsing indicator. This is normal — Wi-Fi scanning takes a few seconds.

**Space** pauses the live scan (freezes the table so you can select/copy text) and **Space** again resumes. The status line shows `Space pause` / `Space resume`. Pause time does not count toward `-p` / `--pillage` scan limits.

### Scan options

```bash
# Include 5 GHz (also scans 2.4 GHz by default)
sudo wiflux --5ghz

# 6 GHz Wi-Fi 6E (adapter must support it)
sudo wiflux --6ghz

# Limit to specific channels
sudo wiflux -c 1,6,11

# Only show networks with connected clients
sudo wiflux --clients-only

# Minimum signal strength (dBm)
sudo wiflux --min-power -70

# Filter by encryption
sudo wiflux --wpa
sudo wiflux --wep
sudo wiflux --wps
```

### Auto-attack after a timed scan

```bash
# Scan for 30 seconds, then attack all targets automatically
sudo wiflux --auto -p 30
```

`-p` alone only **times** the scan; you still pick targets interactively unless you also pass `--auto`.

### Band selection (v1.0.5+)

```bash
sudo wiflux --5ghz          # 5 GHz only
sudo wiflux --6ghz          # 6 GHz only
sudo wiflux --5ghz -2       # 2.4 + 5 GHz
sudo wiflux -c 1,6,11       # fixed channels (ch prefix optional: ch36,ch40)
```

### Hashcat GPU / CPU (v1.0.5+)

By default Wiflux **auto-prefers a GPU** when `hashcat -I` lists one; otherwise CPU.

```bash
sudo wiflux --gpu                 # GPU only
sudo wiflux --cpu-only            # CPU only
hashcat -I                        # list device IDs
sudo wiflux --hashcat-devices 1   # pin device(s)
```

> **Credit:** [Murlocdouche](https://github.com/Murlocdouche) reported that hashcat could not be directed to use the GPU; device selection was added in 1.0.5.

---

## 4. Understanding the live table

The scan view is a live-updating Rich table. Key columns:

| Column | Meaning |
|--------|---------|
| **#** | Row number for target selection |
| **ESSID** | Network name (`<hidden>` if not yet decloaked) |
| **BSSID** | Access point MAC address |
| **GHz** | Band: `2.4`, `5`, or `6` (same cyan style as CH) |
| **CH** | Channel |
| **PWR** | Signal strength (higher is better on the 0–100 airodump scale) |
| **ENC** | Encryption: WEP, WPA, WPA2, WPA3, OWE, WPA2/3-T (transition) |
| **WPS** | `yes` / `no` / `lock` / `n/a` |
| **CL** | Number of associated clients |
| **SCORE** | Attack priority score (higher = more promising) |

> **Credit:** The **GHz** column was suggested by [Murlocdouche](https://github.com/Murlocdouche).

### SCORE explained

Wiflux ranks targets using multiple factors:

- **Signal strength** — stronger signals capture faster
- **Client activity** — clients make handshake and PMKID capture easier
- **Encryption type** — WEP and WPS-enabled networks may be quicker wins
- **WPS lock status** — locked WPS is deprioritized
- **Previous results** — already-cracked networks are skipped by default

---

## 5. Selecting targets

When scanning finishes (or you press `Ctrl+C` once enough APs are visible), you enter target selection.

### Interactive mode (default)

```
Select targets (e.g. 1,3-5 or 'all'):
```

| Input | Action |
|-------|--------|
| `1` | Attack AP #1 only |
| `1,3,5` | Attack APs 1, 3, and 5 |
| `1-5` | Attack APs 1 through 5 |
| `all` | Attack every visible target |
| `Enter` | Attack the highest-scored target |

### Non-interactive mode

```bash
# Attack all targets without prompting
sudo wiflux --auto

# Attack only the first 3 targets
sudo wiflux --auto --first 3

# Attack a specific BSSID
sudo wiflux --auto -b AA:BB:CC:DD:EE:FF
```

---

## 6. Attack phase

Wiflux runs attacks in smart priority order for each target:

```
WEP → WPS Pixie-Dust → WPS PIN → PMKID → Handshake capture
```

Only applicable attacks run (e.g., WPA2 networks skip WEP).

### Live attack view

During attacks you'll see:

- Current target and progress
- Per-attack status log
- Elapsed time and heartbeat for long operations

### Controls during attacks

| Key | Action |
|-----|--------|
| `Space` | Skip the current attack and move to the next method |
| `Ctrl+C` | Stop the current operation (graceful exit) |

### Attack-specific notes

**WEP** — Uses ARP replay injection. Timeout defaults to 600 seconds (`--wept`).

**WPS Pixie-Dust** — Fast offline attack when the AP is vulnerable. Wiflux bails early on repeated timeouts.

**WPS PIN** — Online brute force; can take hours. Use `--ignore-locks` to continue after WPS lockouts.

**PMKID** — Captures PMKID from AP beacon without clients. Requires `hcxdumptool`.

**Handshake** — Deauth clients, then capture the 4-way handshake. Default rhythm: 10s deauth burst, 20s listen (`--deauth-burst` / `--deauth-listen`).

### Limiting attack types

```bash
# WPS only
sudo wiflux --wps-only

# Pixie-Dust only (skip PIN)
sudo wiflux --pixie

# PIN only (skip Pixie)
sudo wiflux --no-pixie

# PMKID only
sudo wiflux --pmkid

# Capture only — no cracking
sudo wiflux --skip-crack

# Passive — no deauth
sudo wiflux --no-deauth
```

---

## 7. Common workflows

### Quick audit (auto everything)

```bash
sudo wiflux --kill --restore --auto -p 45
```

Scans for 45 seconds, then attacks all discovered targets.

### Hunt WPS networks

```bash
sudo wiflux --wps --wps-only --pixie --auto -p 60
```

### Capture handshakes for later cracking

```bash
sudo wiflux --skip-crack --no-pmkid --auto -p 30
```

Handshakes are saved to `wiflux-data/hs/`.

### Crack an existing capture

```bash
# Check if a .cap file contains a handshake
wiflux --check capture.cap

# Show hashcat/aircrack commands for saved captures
wiflux --crack
```

### Review past results

```bash
wiflux --cracked
wiflux --ignored
wiflux --export results.json
```

---

## 8. Utility commands

These commands do not require monitor mode:

```bash
wiflux --help              # Full CLI reference
wiflux --check file.cap    # Validate handshake in capture
wiflux --crack             # Print cracking commands
wiflux --cracked           # Show cracked networks from database
wiflux --ignored           # Show ignored BSSIDs
wiflux --export out.json   # Export database to JSON
wiflux --update-db         # Refresh IEEE OUI vendor list
```

---

## 9. Tips and best practices

1. **Use a dedicated adapter** — An external Alfa or similar adapter with monitor mode avoids disrupting your primary connection.

2. **Start with `--kill --restore`** — Prevents "interface busy" errors from NetworkManager.

3. **Let the scan run** — More time means better client detection and WPS probing. Try `-p 60` or longer in busy areas.

4. **Decloak hidden SSIDs** — Enabled by default. Disable with `--nodecloak` if you want zero deauth during scan.

5. **Skip cracked networks** — Default behavior. Re-attack with `--no-ignore-cracked`.

6. **Use `--new-hs`** — Force fresh handshake capture even if one exists in `hs/`.

7. **PMKID success screen** — After PMKID capture, a confirmation panel appears before the smart wordlist step (like handshake validation).

8. **Attack tuning** — See `wiflux --help` for `--no-crack-ladder`, `--no-algorithmic-wps`, `--no-offline-pixie`, `--pmkid-passive-ratio`, and related flags.

9. **GPU cracking** — Wiflux runs hashcat inline with crack ladder stages; use `wiflux --crack` for manual commands.

10. **JSON output for scripting** — Add `--json` for machine-readable logs.

---

## Getting help

- [Installation Guide](../INSTALL.md)
- [README](../README.md)
- `wiflux --help`

Report issues on GitHub with your adapter model, OS version, and the command you ran.