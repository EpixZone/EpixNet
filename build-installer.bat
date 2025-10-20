@echo off
REM Build script for creating EpixNet installers on Windows

setlocal enabledelayedexpansion

echo.
echo === EpixNet Installer Builder ===
echo.

REM Try to find Python in PATH first, then check common installation locations
set PYTHON_EXE=python
python --version >nul 2>&1
if errorlevel 1 (
    REM Try Python 3.11 installation
    if exist "C:\Program Files\Python311\python.exe" (
        set "PYTHON_EXE=C:\Program Files\Python311\python.exe"
    ) else if exist "C:\Program Files\Python310\python.exe" (
        set "PYTHON_EXE=C:\Program Files\Python310\python.exe"
    ) else if exist "C:\Program Files\Python39\python.exe" (
        set "PYTHON_EXE=C:\Program Files\Python39\python.exe"
    ) else (
        echo Error: Python is not installed or not in PATH
        exit /b 1
    )
)

for /f "tokens=2" %%i in ('"!PYTHON_EXE!" --version 2^>^&1') do set PYTHON_VERSION=%%i
echo Python version: %PYTHON_VERSION%
echo Python executable: %PYTHON_EXE%

REM Install build dependencies
echo.
echo Installing build dependencies...
"!PYTHON_EXE!" -m pip install --upgrade pip
"!PYTHON_EXE!" -m pip install -r requirements.txt
"!PYTHON_EXE!" -m pip install pyinstaller

REM Generate build info
echo.
echo Generating build info...
"!PYTHON_EXE!" build.py --type=installer --platform=windows

REM Create dist directory
if not exist "dist\installers" mkdir dist\installers

REM Build for Windows
echo.
echo Building for Windows...
"!PYTHON_EXE!" -m PyInstaller epixnet.spec --distpath dist\windows

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

