#!/usr/bin/env bash
# Install Wiflux from a GitHub release bundle.
set -euo pipefail

VERSION="${WIFLUX_VERSION:-1.0.0}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHEEL=$(find "$SCRIPT_DIR" -maxdepth 1 -name "wiflux-${VERSION}-*.whl" | head -1)

echo "Wiflux ${VERSION} installer"
echo "==========================="
echo

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

if [ -z "$WHEEL" ] || [ ! -f "$WHEEL" ]; then
    WHEEL=$(find "$SCRIPT_DIR" -maxdepth 1 -name "wiflux-*.whl" | head -1)
fi

if [ -z "$WHEEL" ] || [ ! -f "$WHEEL" ]; then
    echo "Error: wheel file not found in ${SCRIPT_DIR}"
    exit 1
fi

PIP_BREAK=""
if python3 -m pip install --help 2>/dev/null | grep -q break-system-packages; then
    PIP_BREAK="--break-system-packages"
fi

echo "Installing from: $(basename "$WHEEL")"
python3 -m pip install --upgrade pip $PIP_BREAK >/dev/null 2>&1 || true
python3 -m pip install "$WHEEL" $PIP_BREAK

echo
echo "Installation complete."
echo
if command -v wiflux >/dev/null 2>&1; then
    echo "  wiflux --help"
    echo "  sudo wiflux --kill --restore"
else
    echo "  python3 -m wiflux --help"
    echo "  sudo python3 -m wiflux --kill --restore"
fi
echo
echo "See INSTALL.md and docs/TUTORIAL.md for setup and usage."