# Installation Guide

Wiflux is designed for Linux distributions used in wireless security auditing (Kali Linux, Parrot OS, BlackArch, etc.). It requires a wireless adapter capable of **monitor mode** and **packet injection**.

> **Legal notice:** Only install and use Wiflux on networks you own or have explicit written permission to test.

---

## Requirements

| Category | Details |
|----------|---------|
| OS | Linux with wireless tools (tested on Kali Linux) |
| Python | 3.10 or newer |
| Privileges | `root` or `sudo` (required for monitor mode and injection) |
| Hardware | Wi-Fi adapter with monitor mode + injection support |

### Required tools

These are installed automatically on Debian-based systems when you accept the startup dependency prompt, or manually via:

```bash
sudo apt update
sudo apt install -y aircrack-ng iw iproute2
```

| Binary | Package | Purpose |
|--------|---------|---------|
| `airodump-ng` | aircrack-ng | AP/client scanning |
| `aireplay-ng` | aircrack-ng | Deauth and WEP injection |
| `airmon-ng` | aircrack-ng | Monitor mode |
| `aircrack-ng` | aircrack-ng | WEP/WPA cracking |
| `iw` | iw | Interface control |
| `ip` | iproute2 | Network interface management |

### Optional tools (recommended)

```bash
sudo apt install -y reaver bully hcxdumptool hcxtools hashcat
```

| Binary | Package | Purpose |
|--------|---------|---------|
| `wash` | reaver | WPS detection |
| `reaver` | reaver | WPS Pixie-Dust / PIN |
| `bully` | bully | Alternative WPS tool |
| `hcxdumptool` | hcxdumptool | PMKID capture |
| `hcxpcapngtool` | hcxtools | PMKID conversion |
| `hashcat` | hashcat | GPU cracking |
| `packetforge-ng` | aircrack-ng | WEP ARP replay |

Wiflux checks for missing dependencies at startup and can offer to install them via `apt`.

---

## Install from source

### 1. Clone the repository

```bash
git clone https://github.com/Leadrogue/Wiflux.git
cd wiflux
```

### 2. Install the Python package

**Debian / Kali (system Python):**

```bash
pip install -e . --break-system-packages
```

**Virtual environment (recommended for development):**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3. Verify installation

```bash
wiflux --help
wiflux --check
```

---

## Wireless adapter setup

### Put interface in monitor mode

Wiflux can do this automatically, or you can prepare the interface manually:

```bash
# Kill processes that interfere with monitor mode
sudo airmon-ng check kill

# Enable monitor mode (replace wlan0 with your interface)
sudo airmon-ng start wlan0

# Verify — you should see wlan0mon (or similar)
iw dev
```

### Specify an interface

```bash
sudo wiflux -i wlan0mon
```

If you omit `-i`, Wiflux selects a suitable wireless interface automatically.

### Restore managed mode on exit

```bash
sudo wiflux --restore
```

Use `--kill` to stop conflicting processes before scanning:

```bash
sudo wiflux --kill --restore
```

---

## Wordlists

Wiflux searches common wordlist locations automatically:

- `/usr/share/wordlists/rockyou.txt`
- `/usr/share/wordlists/fern-wifi/common.txt`
- `/usr/share/dict/wordlist-probable.txt`
- `/usr/share/john/password.lst`

Install rockyou on Kali if needed:

```bash
sudo apt install -y wordlists
sudo gunzip /usr/share/wordlists/rockyou.txt.gz
```

Or specify a custom wordlist:

```bash
sudo wiflux --dict /path/to/wordlist.txt
```

---

## Data directory

By default, Wiflux stores captures, handshakes, and crack history in `./wiflux-data/`:

```
wiflux-data/
├── wiflux.db      # SQLite crack/ignore database
└── hs/            # Captured handshakes (.cap)
```

Change the location with:

```bash
sudo wiflux --data-dir /var/lib/wiflux
```

---

## Uninstall

```bash
pip uninstall wiflux
rm -rf wiflux-data/   # optional — removes local captures and database
```

---

## Troubleshooting

### `airodump-ng: command not found`

Install the aircrack-ng suite: `sudo apt install aircrack-ng`

### No wireless interfaces found

- Confirm your adapter supports monitor mode: `iw list | grep -A5 "Supported interface modes"`
- Check `rfkill`: `sudo rfkill unblock wifi`
- Ensure the driver is loaded: `lsusb` / `dmesg | tail`

### WPS shows `n/a` for all networks

Ensure `wash` is installed (`sudo apt install reaver`). Wiflux probes WPS in the background during scanning.

### Permission denied

Wiflux must run as root for monitor mode and packet injection:

```bash
sudo wiflux
```

### Rich live display issues over SSH

Use a full TTY (`ssh -t`) or run with `--json` for machine-readable output.

---

## Next steps

- [Tutorial](docs/TUTORIAL.md) — step-by-step walkthrough
- [README](README.md) — feature overview and quick reference