@echo off
REM ─────────────────────────────────────────────────────────
REM  build_windows.bat
REM  Builds Phantom.exe for Windows
REM  Run as Administrator from project root
REM ─────────────────────────────────────────────────────────

echo.
echo 👻 Phantom — Windows Build Script
echo ===================================

REM ── Activate venv if present ─────────────────────────────
if exist ".venv\Scripts\activate.bat" (
    echo ^-^> Activating virtual environment...
    call .venv\Scripts\activate.bat
)

REM ── Check PyInstaller ────────────────────────────────────
pyinstaller --version >nul 2>&1
if errorlevel 1 (
    echo ^-^> Installing PyInstaller...
    pip install pyinstaller
)

REM ── Install Npcap reminder ───────────────────────────────
echo.
echo NOTE: Windows users need Npcap installed for packet capture.
echo Download from: https://npcap.com/#download
echo.

REM ── Clean previous build ─────────────────────────────────
echo ^-^> Cleaning previous build...
if exist "build" rmdir /s /q build
if exist "dist"  rmdir /s /q dist

REM ── Run PyInstaller ──────────────────────────────────────
echo ^-^> Building Phantom.exe...
pyinstaller phantom.spec

REM ── Result ───────────────────────────────────────────────
if exist "dist\Phantom\Phantom.exe" (
    echo.
    echo ✅ Build successful^^!
    echo    Exe location: dist\Phantom\Phantom.exe
    echo.
    echo NOTE: Run as Administrator for packet capture.
    echo.
    echo ^-^> To create a distributable zip:
    echo    powershell Compress-Archive dist\Phantom Phantom-Windows.zip
) else (
    echo.
    echo ❌ Build failed — check errors above
    exit /b 1
)