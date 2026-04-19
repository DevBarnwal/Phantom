#!/bin/bash
# ─────────────────────────────────────────────────────────
#  build_macos.sh
#  Builds Phantom.app for macOS
#  Run from project root: bash build_macos.sh
# ─────────────────────────────────────────────────────────

set -e   # Exit on any error

echo ""
echo "👻 Phantom — macOS Build Script"
echo "================================"

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
echo "→ Building Phantom.app..."
pyinstaller phantom.spec

# ── Result ───────────────────────────────────────────────
if [ -d "dist/Phantom.app" ]; then
    echo ""
    echo "✅ Build successful!"
    echo "   App location: dist/Phantom.app"
    echo ""
    echo "⚠️  Important — to run with packet capture:"
    echo "   sudo dist/Phantom.app/Contents/MacOS/Phantom"
    echo "   (macOS requires root for raw socket access)"
    echo ""
    echo "→ To create a distributable zip:"
    echo "   cd dist && zip -r Phantom-macOS.zip Phantom.app"
else
    echo ""
    echo "❌ Build failed — check errors above"
    exit 1
fi