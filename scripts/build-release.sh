#!/usr/bin/env bash
# Build release artifacts for GitHub Releases.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VERSION=$(python3 -c "import pathlib, re; t=pathlib.Path('pyproject.toml').read_text(); m=re.search(r'^version = \"([^\"]+)\"', t, re.M); print(m.group(1) if m else '0.0.0')")
DIST="$ROOT/dist"
RELEASE_DIR="$DIST/release"
INSTALLER="wiflux-${VERSION}-linux-installer"

echo "Building Wiflux v${VERSION}..."

python3 -m pip install --quiet build twine 2>/dev/null || \
    python3 -m pip install --quiet build twine --break-system-packages

rm -rf "$DIST"
mkdir -p "$RELEASE_DIR"

python3 -m build --outdir "$DIST"

WHEEL=$(ls "$DIST"/wiflux-"${VERSION}"-py3-none-any.whl)
SDIST=$(ls "$DIST"/wiflux-"${VERSION}".tar.gz)

# Installer bundle: wheel + install script + docs
INSTALLER_DIR="$RELEASE_DIR/$INSTALLER"
mkdir -p "$INSTALLER_DIR"
cp "$WHEEL" "$INSTALLER_DIR/"
cp scripts/install-release.sh "$INSTALLER_DIR/install.sh"
chmod +x "$INSTALLER_DIR/install.sh"
cp README.md INSTALL.md LICENSE "$INSTALLER_DIR/"
mkdir -p "$INSTALLER_DIR/docs"
cp docs/TUTORIAL.md "$INSTALLER_DIR/docs/"

tar -czf "$RELEASE_DIR/${INSTALLER}.tar.gz" -C "$RELEASE_DIR" "$INSTALLER"

# Checksums
(
    cd "$DIST"
    sha256sum wiflux-"${VERSION}"-py3-none-any.whl wiflux-"${VERSION}".tar.gz > "wiflux-${VERSION}-checksums.sha256"
    cd "$RELEASE_DIR"
    sha256sum "${INSTALLER}.tar.gz" >> "$DIST/wiflux-${VERSION}-checksums.sha256"
)

echo
echo "Built artifacts:"
ls -lh "$DIST"/wiflux-"${VERSION}"* "$RELEASE_DIR"/"${INSTALLER}.tar.gz"
echo
echo "Release files ready in: $DIST"