"""
PyInstaller runtime hook to add --open-browser flag when running from bundled app
This ensures the web browser opens automatically when the app is launched
"""
import sys
import os

# Only add --open-browser if:
# 1. We're running from a frozen/bundled app
# 2. The flag is not already present
# 3. We're not in silent mode
if getattr(sys, 'frozen', False) and '--open-browser' not in sys.argv and '--silent' not in sys.argv:
    # Add the flag to open browser by default
    sys.argv.insert(1, '--open-browser')
    print(f"[pyi_rth_open_browser] Added --open-browser flag. sys.argv: {sys.argv}")

