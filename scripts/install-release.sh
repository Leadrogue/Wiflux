#!/usr/bin/env bash
# Install Wiflux from a GitHub release bundle.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: python3 is required (3.10+)."
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    echo "Error: Python 3.10+ required (found ${PY_VER})."
    exit 1
fi

WHEEL="${WIFLUX_WHEEL:-}"
if [ -z "$WHEEL" ] || [ ! -f "$WHEEL" ]; then
    if [ -n "${WIFLUX_VERSION:-}" ]; then
        WHEEL=$(find "$SCRIPT_DIR" -maxdepth 1 -name "wiflux-${WIFLUX_VERSION}-*.whl" | head -1)
    fi
fi
if [ -z "$WHEEL" ] || [ ! -f "$WHEEL" ]; then
    WHEEL=$(find "$SCRIPT_DIR" -maxdepth 1 -name "wiflux-*.whl" | sort -V | tail -1)
fi

if [ -z "$WHEEL" ] || [ ! -f "$WHEEL" ]; then
    echo "Error: wheel file not found in ${SCRIPT_DIR}"
    exit 1
fi

VERSION=$(basename "$WHEEL" | sed -n 's/^wiflux-\([0-9][0-9.]*\)-.*/\1/p')
if [ -z "$VERSION" ]; then
    VERSION="unknown"
fi

echo "Wiflux ${VERSION} installer"
echo "==========================="
echo

PIP_BREAK=""
if python3 -m pip install --help 2>/dev/null | grep -q break-system-packages; then
    PIP_BREAK="--break-system-packages"
fi

echo "Installing from: $(basename "$WHEEL")"
python3 -m pip install --upgrade pip $PIP_BREAK >/dev/null 2>&1 || true
python3 -m pip install "$WHEEL" $PIP_BREAK

WIFLUX_BIN=$(command -v wiflux || true)
if [ -z "$WIFLUX_BIN" ]; then
    WIFLUX_BIN="/usr/local/bin/wiflux"
fi

echo
echo "Installation complete."
echo
echo "  wiflux --help"
echo "  sudo env PATH=\"/usr/local/bin:\$PATH\" wiflux --kill --restore"
echo "  # Kali/Debian: sudo often omits /usr/local/bin — use the line above, or:"
echo "  sudo ${WIFLUX_BIN} --kill --restore"
echo
echo "See INSTALL.md and docs/TUTORIAL.md for setup and usage."