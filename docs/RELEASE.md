# GitHub Releases

Pre-built downloads are published at:

**https://github.com/Leadrogue/Wiflux/releases**

---

## Recommended: Linux installer bundle

Download `wiflux-VERSION-linux-installer.tar.gz`, then:

```bash
tar -xzf wiflux-1.0.0-linux-installer.tar.gz
cd wiflux-1.0.0-linux-installer
./install.sh
```

The installer script checks Python 3.10+, installs the bundled wheel, and prints next steps.

---

## Install from wheel (pip)

```bash
pip install wiflux-1.0.0-py3-none-any.whl --break-system-packages
```

On Kali/Debian with system Python, `--break-system-packages` is required.

Direct from GitHub:

```bash
pip install https://github.com/Leadrogue/Wiflux/releases/download/v1.0.0/wiflux-1.0.0-py3-none-any.whl --break-system-packages
```

---

## Install from source tarball

```bash
tar -xzf wiflux-1.0.0.tar.gz
cd wiflux-1.0.0
pip install . --break-system-packages
```

---

## Verify downloads

Each release includes `wiflux-VERSION-checksums.sha256`:

```bash
sha256sum -c wiflux-1.0.0-checksums.sha256
```

---

## After install

```bash
wiflux --help
sudo wiflux --kill --restore
```

See [INSTALL.md](../INSTALL.md) for wireless adapter setup and dependencies.