#!/bin/bash
# ─────────────────────────────────────────────────────────
#  build_linux.sh
#  Builds Phantom binary for Linux
#  Run from project root: bash build_linux.sh
# ─────────────────────────────────────────────────────────

set -e

echo ""
echo "👻 Phantom — Linux Build Script"
echo "================================"

# ── Check libpcap ────────────────────────────────────────
echo "→ Checking libpcap..."
if ! dpkg -l libpcap-dev &> /dev/null 2>&1; then
    echo "→ Installing libpcap-dev..."
    sudo apt-get install -y libpcap-dev 2>/dev/null || \
    sudo yum install -y libpcap-devel 2>/dev/null || \
    echo "  (manual install may be needed: sudo apt install libpcap-dev)"
fi

# ── Activate venv if present ─────────────────────────────
if [ -d ".venv" ]; then
    echo "→ Activating virtual environment..."
    source .venv/bin/activate
fi

# ── Check PyInstaller ────────────────────────────────────
if ! command -v pyinstaller &> /dev/null; then
    echo "→ Installing PyInstaller..."
    pip install pyinstaller
fi

# ── Clean previous build ─────────────────────────────────
echo "→ Cleaning previous build..."
rm -rf build/ dist/ __pycache__/

# ── Run PyInstaller ──────────────────────────────────────
echo "→ Building Phantom binary..."
pyinstaller phantom.spec

# ── Set capabilities so it runs without sudo (optional) ──
if [ -f "dist/Phantom/Phantom" ]; then
    echo "→ Setting network capture capabilities..."
    sudo setcap cap_net_raw,cap_net_admin=eip dist/Phantom/Phantom 2>/dev/null || \
        echo "  (setcap skipped — run with sudo if capture fails)"
fi

# ── Result ───────────────────────────────────────────────
if [ -d "dist/Phantom" ]; then
    echo ""
    echo "✅ Build successful!"
    echo "   Binary location: dist/Phantom/Phantom"
    echo ""
    echo "→ Run it:"
    echo "   sudo dist/Phantom/Phantom"
    echo ""
    echo "→ To create a distributable tarball:"
    echo "   cd dist && tar -czf Phantom-Linux.tar.gz Phantom/"
else
    echo ""
    echo "❌ Build failed — check errors above"
    exit 1
fi