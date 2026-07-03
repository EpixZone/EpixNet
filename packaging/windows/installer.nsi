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

Name "Epix"
OutFile "${OUT_FILE}"
InstallDir "$LOCALAPPDATA\Epix"
RequestExecutionLevel user
ShowInstDetails show
ShowUninstDetails show

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\Epix"

Section "Epix" SecMain
  SetOutPath "$INSTDIR"
  File /r "${STAGE_DIR}\*.*"

  ; Register the epix:// scheme (per-user).
  WriteRegStr HKCU "Software\Classes\epix" "" "URL:Epix Protocol"
  WriteRegStr HKCU "Software\Classes\epix" "URL Protocol" ""
  WriteRegStr HKCU "Software\Classes\epix\DefaultIcon" "" "$INSTDIR\epix-browser.exe,0"
  WriteRegStr HKCU "Software\Classes\epix\shell\open\command" "" '"$INSTDIR\epix-browser.exe" "%1"'

  ; Shortcuts.
  CreateShortcut "$SMPROGRAMS\Epix.lnk" "$INSTDIR\epix-browser.exe"
  CreateShortcut "$DESKTOP\Epix.lnk" "$INSTDIR\epix-browser.exe"

  ; Uninstaller + Add/Remove Programs entry.
  WriteUninstaller "$INSTDIR\uninstall.exe"
  WriteRegStr   HKCU "${UNINST_KEY}" "DisplayName"     "Epix"
  WriteRegStr   HKCU "${UNINST_KEY}" "DisplayVersion"  "${VERSION}"
  WriteRegStr   HKCU "${UNINST_KEY}" "Publisher"       "EpixNet"
  WriteRegStr   HKCU "${UNINST_KEY}" "DisplayIcon"     "$INSTDIR\epix-browser.exe"
  WriteRegStr   HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
SectionEnd

Section "Uninstall"
  Delete "$SMPROGRAMS\Epix.lnk"
  Delete "$DESKTOP\Epix.lnk"
  DeleteRegKey HKCU "Software\Classes\epix"
  DeleteRegKey HKCU "Software\Mozilla\NativeMessagingHosts\zone.epix.nmh"
  DeleteRegKey HKCU "${UNINST_KEY}"
  RMDir /r "$INSTDIR"
SectionEnd
