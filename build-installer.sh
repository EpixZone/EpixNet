#!/bin/bash
# Build script for creating EpixNet installers locally

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect OS
OS_TYPE=$(uname -s)
ARCH=$(uname -m)

echo -e "${GREEN}=== EpixNet Installer Builder ===${NC}"
echo "Detected OS: $OS_TYPE ($ARCH)"

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "Python version: $PYTHON_VERSION"

# Install build dependencies
echo -e "${YELLOW}Installing build dependencies...${NC}"
python3 -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

# Generate build info
echo -e "${YELLOW}Generating build info...${NC}"
python3 build.py --type=installer --platform="$OS_TYPE"

# Create dist directory
mkdir -p dist/installers

# Build based on OS
case "$OS_TYPE" in
  Linux)
    echo -e "${YELLOW}Building for Linux...${NC}"
    pyinstaller epixnet.spec --distpath dist/linux
    cd dist/linux
    tar -czf ../installers/EpixNet-linux-${ARCH}.tar.gz EpixNet/
    cd ../..
    echo -e "${GREEN}✓ Linux build complete: dist/installers/EpixNet-linux-${ARCH}.tar.gz${NC}"
    ;;
  Darwin)
    echo -e "${YELLOW}Building for macOS...${NC}"
    pyinstaller epixnet.spec --distpath dist/macos
    hdiutil create -volname "EpixNet" -srcfolder dist/macos/EpixNet.app -ov -format UDZO dist/installers/EpixNet-macos.dmg
    echo -e "${GREEN}✓ macOS build complete: dist/installers/EpixNet-macos.dmg${NC}"
    ;;
  MINGW64_NT*|MSYS_NT*|CYGWIN_NT*)
    echo -e "${YELLOW}Building for Windows...${NC}"
    pyinstaller epixnet.spec --distpath dist/windows
    cd dist/windows
    7z a -r ../installers/EpixNet-windows-x64.zip EpixNet/
    cd ../..
    echo -e "${GREEN}✓ Windows build complete: dist/installers/EpixNet-windows-x64.zip${NC}"
    ;;
  *)
    echo -e "${RED}Unsupported OS: $OS_TYPE${NC}"
    exit 1
    ;;
esac

echo -e "${GREEN}=== Build complete! ===${NC}"
echo "Installer location: dist/installers/"

