# GitHub Releases

Pre-built downloads are published at:

**https://github.com/Leadrogue/Wiflux/releases**

Latest: **[v1.0.3](https://github.com/Leadrogue/Wiflux/releases/tag/v1.0.3)**

---

## Recommended: Linux installer bundle

Download `wiflux-1.0.3-linux-installer.tar.gz`, then:

```bash
curl -LO https://github.com/Leadrogue/Wiflux/releases/download/v1.0.3/wiflux-1.0.3-linux-installer.tar.gz
tar -xzf wiflux-1.0.3-linux-installer.tar.gz
cd wiflux-1.0.3-linux-installer
./install.sh
```

The installer checks Python 3.10+, installs the bundled wheel, detects the version from the wheel filename, and prints next steps.

---

## Install from wheel (pip)

```bash
pip install wiflux-1.0.3-py3-none-any.whl --break-system-packages
```

Direct from GitHub:

```bash
pip install https://github.com/Leadrogue/Wiflux/releases/download/v1.0.3/wiflux-1.0.3-py3-none-any.whl --break-system-packages
```

On Kali/Debian with system Python, `--break-system-packages` is required.

---

## Install from source tarball

```bash
curl -LO https://github.com/Leadrogue/Wiflux/releases/download/v1.0.3/wiflux-1.0.3.tar.gz
tar -xzf wiflux-1.0.3.tar.gz
cd wiflux-1.0.3
pip install . --break-system-packages
```

---

## Verify downloads

Each release includes `wiflux-VERSION-checksums.sha256`:

```bash
curl -LO https://github.com/Leadrogue/Wiflux/releases/download/v1.0.3/wiflux-1.0.3-checksums.sha256
sha256sum -c wiflux-1.0.3-checksums.sha256
```

---

## After install

```bash
wiflux --help
sudo env PATH="/usr/local/bin:$PATH" wiflux --kill --restore
```

On Kali/Debian, `sudo` may omit `/usr/local/bin` from `PATH`. Use the `env PATH=...` form above, or `sudo /usr/local/bin/wiflux --kill --restore`.

See [INSTALL.md](../INSTALL.md) for wireless adapter setup and dependencies.