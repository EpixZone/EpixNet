; Epix Windows installer (NSIS / MUI2). Per-user install (no admin), bundles
; the launcher + native host + Firefox ESR, and registers the epix:// scheme.
; Compiled by build-windows.sh, which passes:
;   -DSTAGE_DIR=...  the assembled tree (epix-browser.exe, epix-nmh.exe, firefox\)
;   -DOUT_FILE=...   the installer .exe to produce
;   -DVERSION=...    the release version
;
; The native-messaging-host registry key is written by the launcher at first
; run (it also works for dev runs); the uninstaller removes it.

Unicode true
!include "MUI2.nsh"

!ifndef VERSION
  !define VERSION "0.0.0"
!endif
!ifndef OUT_FILE
  !define OUT_FILE "Epix-Setup.exe"
!endif

; Branding assets, prebuilt from the assets repo and committed next to this
; script: app.ico (images/icons/generated/windows/app.ico), welcome.bmp and
; header.bmp (scripts/generate-installer-bmps.py). Paths are relative to this
; script.
!define MUI_ICON "app.ico"
!define MUI_UNICON "app.ico"
!define MUI_WELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "header.bmp"
!define MUI_HEADERIMAGE_RIGHT
!define MUI_ABORTWARNING

Name "EpixNet"
OutFile "${OUT_FILE}"
InstallDir "$LOCALAPPDATA\Epix"
RequestExecutionLevel user
ShowInstDetails show
ShowUninstDetails show
BrandingText "EpixNet ${VERSION}"

; Version resource on the installer exe (Properties > Details). VIProductVersion
; needs a numeric x.x.x.x, so strip any pre-release suffix (1.2.3-rc1 -> 1.2.3)
; and append ".0". The display fields keep the full version string.
!searchparse /noerrors "${VERSION}-" "" VERSION_NUM "-"
VIProductVersion "${VERSION_NUM}.0"
VIAddVersionKey /LANG=1033 "ProductName"     "EpixNet"
VIAddVersionKey /LANG=1033 "CompanyName"     "Epix"
VIAddVersionKey /LANG=1033 "FileDescription" "EpixNet Installer"
VIAddVersionKey /LANG=1033 "FileVersion"     "${VERSION_NUM}.0"
VIAddVersionKey /LANG=1033 "ProductVersion"  "${VERSION}"
VIAddVersionKey /LANG=1033 "LegalCopyright"  "Copyright (c) Epix"

!define MUI_WELCOMEPAGE_TITLE "Welcome to EpixNet"
!define MUI_WELCOMEPAGE_TEXT "Setup will install EpixNet ${VERSION} on your computer.$\r$\n$\r$\nEpixNet installs for the current user only and does not require administrator rights.$\r$\n$\r$\nClick Next to continue."

; Finish page: offer to launch, checked by default.
!define MUI_FINISHPAGE_RUN "$INSTDIR\epix-browser.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch EpixNet"
!define MUI_FINISHPAGE_LINK "epix.zone"
!define MUI_FINISHPAGE_LINK_LOCATION "https://epix.zone"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Epix"

Section "EpixNet" SecMain
  SetOutPath "$INSTDIR"
  File /r "${STAGE_DIR}\*.*"

  ; Register the epix:// scheme (per-user).
  WriteRegStr HKCU "Software\Classes\epix" "" "URL:Epix Protocol"
  WriteRegStr HKCU "Software\Classes\epix" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\epix\DefaultIcon" "" "$INSTDIR\epix-browser.exe,0"
  WriteRegStr HKCU "Software\Classes\epix\shell\open\command" "" '"$INSTDIR\epix-browser.exe" "%1"'

  ; Shortcuts.
  CreateShortcut "$SMPROGRAMS\EpixNet.lnk" "$INSTDIR\epix-browser.exe"
  CreateShortcut "$DESKTOP\EpixNet.lnk" "$INSTDIR\epix-browser.exe"

  ; Uninstaller + Add/Remove Programs entry.
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr   HKCU "${UNINST_KEY}" "DisplayName"     "EpixNet"
  WriteRegStr   HKCU "${UNINST_KEY}" "DisplayVersion"  "${VERSION}"
  WriteRegStr   HKCU "${UNINST_KEY}" "Publisher"       "Epix"
  WriteRegStr   HKCU "${UNINST_KEY}" "DisplayIcon"     "$INSTDIR\epix-browser.exe"
  WriteRegStr   HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$SMPROGRAMS\EpixNet.lnk"
  Delete "$DESKTOP\EpixNet.lnk"
  ; The local-CA copy the launcher writes for the Firefox certificate policy
  ; (the policy itself lives in $INSTDIR\firefox\distribution, removed below).
  Delete "$LOCALAPPDATA\Mozilla\Certificates\epix-ca.pem"
  Delete "$APPDATA\Mozilla\Certificates\epix-ca.pem"
  DeleteRegKey HKCU "Software\Classes\epix"
  DeleteRegKey HKCU "Software\Mozilla\NativeMessagingHosts\zone.epix.nmh"
  DeleteRegKey HKCU "${UNINST_KEY}"
  RMDir /r "$INSTDIR"
SectionEnd
