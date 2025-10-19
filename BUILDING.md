# Building EpixNet Installers

This document explains how to build standalone installers for EpixNet on Windows, macOS, and Linux.

## Overview

EpixNet uses **PyInstaller** to create standalone executables that bundle Python and all dependencies. This allows users to run EpixNet without installing Python separately.

### Build Artifacts

- **Windows**: `EpixNet-windows-x64.zip` (executable + dependencies)
- **macOS**: `EpixNet-macos.dmg` (disk image with app bundle)
- **Linux**: `EpixNet-linux-x64.tar.gz` (tarball with executable)

## Automated Builds (GitHub Actions)

The easiest way to build installers is using GitHub Actions, which automatically builds for all platforms when you create a release.

### Creating a Release

1. Push a tag to trigger the build:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

2. GitHub Actions will automatically:
   - Build Windows, macOS, and Linux installers
   - Create a GitHub Release with all artifacts
   - Upload the installers as release assets

3. Download installers from the [Releases page](https://github.com/EpixZone/EpixNet/releases)

### Manual Trigger

You can also manually trigger a build without creating a release:

1. Go to **Actions** → **Build Installers**
2. Click **Run workflow**
3. Optionally specify a version
4. Artifacts will be available for download

## Local Builds

### Prerequisites

All platforms require:
- Python 3.8+ (3.11+ recommended)
- Git
- Build tools (compiler, etc.)

#### Windows
- Visual Studio Build Tools or MinGW
- 7-Zip (for creating archives)

#### macOS
- Xcode Command Line Tools: `xcode-select --install`

#### Linux
```bash
sudo apt-get install build-essential python3-dev pkg-config libffi-dev
```

### Building Locally

#### Linux/macOS
```bash
chmod +x build-installer.sh
./build-installer.sh
```

#### Windows
```cmd
build-installer.bat
```

Or manually:
```cmd
python -m pip install -r requirements.txt
python -m pip install pyinstaller
pyinstaller epixnet.spec
```

### Output

Built installers are placed in `dist/installers/`:
- `EpixNet-windows-x64.zip`
- `EpixNet-macos.dmg`
- `EpixNet-linux-x64.tar.gz`

## Customization

### Modifying the PyInstaller Spec

Edit `epixnet.spec` to customize the build:

- **Icon**: Already configured to use `plugins/Trayicon/trayicon.ico`. To use a different icon, update the `icon` parameter in both the `EXE()` and `BUNDLE()` calls
- **Console**: Change `console=False` to `console=True` for a console window
- **Hidden imports**: Add missing modules to `hiddenimports` list
- **Data files**: Add additional files to `datas` list

### Code Signing (Optional)

For production releases, you may want to code sign the executables:

#### macOS
```bash
codesign -s "Developer ID Application" dist/macos/EpixNet.app
```

#### Windows
```cmd
signtool sign /f certificate.pfx /p password /t http://timestamp.server dist/windows/EpixNet.exe
```

## Troubleshooting

### PyInstaller Build Fails

**Issue**: `ModuleNotFoundError` for a specific module

**Solution**: Add the module to `hiddenimports` in `epixnet.spec`

### Missing Dependencies

**Issue**: Application crashes with import errors

**Solution**: 
1. Check `requirements.txt` is up to date
2. Add missing modules to `hiddenimports` in the spec file
3. Rebuild

### Large File Size

**Issue**: Installer is very large (>500MB)

**Solution**:
- Use `--onefile` option in PyInstaller (creates single executable)
- Remove unnecessary dependencies
- Use UPX compression (already enabled in spec)

### macOS DMG Creation Fails

**Issue**: `hdiutil` command not found

**Solution**: This is a macOS-only tool. Ensure you're building on macOS.

## Distribution

### GitHub Releases

Installers are automatically uploaded to GitHub Releases when you push a tag.

### Manual Distribution

1. Build locally: `./build-installer.sh` (or `.bat` on Windows)
2. Upload `dist/installers/*` to your distribution platform
3. Share download links with users

## First Run

After installation, users can run EpixNet:

- **Windows**: Double-click `EpixNet.exe`
- **macOS**: Open `EpixNet.app` from Applications
- **Linux**: Run `./EpixNet` from the extracted directory

## Support

For issues with building, see:
- [PyInstaller Documentation](https://pyinstaller.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [EpixNet Issues](https://github.com/EpixZone/EpixNet/issues)

