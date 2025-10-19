# EpixNet Installer Setup - Quick Reference

## What Was Set Up

✅ **PyInstaller Configuration** (`epixnet.spec`)
- Bundles Python + all dependencies into standalone executables
- Includes all plugins and data files
- Uses the EpixNet trayicon as the application icon
- Configured for Windows, macOS, and Linux

✅ **GitHub Actions Workflow** (`.github/workflows/build-installers.yml`)
- Automatically builds installers on every release
- Creates Windows (.zip), macOS (.dmg), and Linux (.tar.gz) packages
- Uploads artifacts to GitHub Releases

✅ **Local Build Scripts**
- `build-installer.sh` - For Linux/macOS
- `build-installer.bat` - For Windows

✅ **Documentation** (`BUILDING.md`)
- Complete guide for building, customizing, and distributing installers

---

## Quick Start

### Option 1: Automated Release Build (Recommended)

```bash
# Create a release tag
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions automatically builds all installers
# Download from: https://github.com/EpixZone/EpixNet/releases
```

### Option 2: Manual Local Build

**Linux/macOS:**
```bash
./build-installer.sh
```

**Windows:**
```cmd
build-installer.bat
```

---

## Files Created/Modified

### New Files
- `epixnet.spec` - PyInstaller configuration
- `.github/workflows/build-installers.yml` - GitHub Actions workflow
- `build-installer.sh` - Linux/macOS build script
- `build-installer.bat` - Windows build script
- `BUILDING.md` - Build documentation
- `INSTALLER_SETUP.md` - This file

### Modified Files
- None (all new files)

---

## Build Output

Built installers are placed in `dist/installers/`:
- `EpixNet-windows-x64.zip` - Windows executable + dependencies
- `EpixNet-macos.dmg` - macOS disk image with app bundle
- `EpixNet-linux-x64.tar.gz` - Linux tarball with executable

---

## Icon Configuration

The application icon is already configured:
- **Source**: `plugins/Trayicon/trayicon.ico`
- **Used in**: Windows .exe, macOS .app, Linux executable

To use a different icon, edit `epixnet.spec` and update the `icon` parameter in both the `EXE()` and `BUNDLE()` calls.

---

## Next Steps

1. **Test locally** (optional):
   ```bash
   ./build-installer.sh  # or build-installer.bat on Windows
   ```

2. **Create first release**:
   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

3. **Download installers** from GitHub Releases

4. **Distribute** to users

---

## Troubleshooting

### Build fails with "ModuleNotFoundError"
- Add the missing module to `hiddenimports` in `epixnet.spec`
- Rebuild

### Large installer size
- This is normal for PyInstaller bundles (typically 200-500MB)
- Consider using `--onefile` option for single executable

### macOS DMG creation fails
- Ensure you're building on macOS (hdiutil is macOS-only)
- Check that `dist/macos/EpixNet.app` was created successfully

### Windows build requires 7-Zip
- Install 7-Zip from https://www.7-zip.org/
- Ensure it's in your PATH

---

## Additional Resources

- [PyInstaller Documentation](https://pyinstaller.org/)
- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [BUILDING.md](BUILDING.md) - Detailed build guide
- [EpixNet Issues](https://github.com/EpixZone/EpixNet/issues)

---

## Support

For issues or questions:
1. Check [BUILDING.md](BUILDING.md) for detailed information
2. Review [GitHub Actions logs](https://github.com/EpixZone/EpixNet/actions)
3. Open an issue on [GitHub](https://github.com/EpixZone/EpixNet/issues)

