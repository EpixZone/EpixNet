@echo off
REM Build script for creating EpixNet installers on Windows

setlocal enabledelayedexpansion

echo.
echo === EpixNet Installer Builder ===
echo.

REM Check Python version
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python version: %PYTHON_VERSION%

REM Install build dependencies
echo.
echo Installing build dependencies...
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

REM Generate build info
echo.
echo Generating build info...
python build.py --type=installer --platform=windows

REM Create dist directory
if not exist "dist\installers" mkdir dist\installers

REM Build for Windows
echo.
echo Building for Windows...
pyinstaller epixnet.spec --distpath dist\windows

if errorlevel 1 (
    echo Error: PyInstaller build failed
    exit /b 1
)

REM Create ZIP archive
echo.
echo Creating ZIP archive...
cd dist\windows
7z a -r ..\installers\EpixNet-windows-x64.zip EpixNet\
cd ..\..

if errorlevel 1 (
    echo Error: Failed to create ZIP archive
    echo Make sure 7-Zip is installed and in PATH
    exit /b 1
)

echo.
echo === Build complete! ===
echo Installer location: dist\installers\EpixNet-windows-x64.zip
echo.
pause

