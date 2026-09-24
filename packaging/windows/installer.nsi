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
!include "LogicLib.nsh"

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
; A file that cannot be written (EpixNet still running and holding it) must
; never be skipped: a tree with a new firefox.exe next to an old xul.dll
; starts and exits at once ("Couldn't load XPCOM"). Retry or abort only.
AllowSkipFiles off
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

; --- Closing a running EpixNet ---------------------------------------------
; Everything runs per-user from $INSTDIR: the launcher (which owns the node),
; the native host and the bundled Firefox. Replacing or removing that tree
; while any of it runs leaves a half-updated browser behind, so setup closes
; EpixNet first - cleanly through the launcher's --quit when the running
; version understands it, else by stopping the processes - and refuses to go
; on while anything from $INSTDIR is still running. close-epixnet.ps1 (next to
; this script, extracted to $PLUGINSDIR at run time) does the work; its exit
; code is the only thing checked here: 0 = nothing running, 1 = still running.
; LAUNCHER is a launcher that understands --quit: the NEW one during install,
; the installed one during uninstall.
!macro EPIX_RUN_CLOSER MODE LAUNCHER
  nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\close-epixnet.ps1" -InstallDir "$INSTDIR" -Mode ${MODE} -Launcher "${LAUNCHER}"'
  Pop $0   ; exit code ("error"/"timeout" when powershell itself did not run)
  Pop $1   ; output (unused)
!macroend

!macro EPIX_ENSURE_CLOSED UN LAUNCHER
Function ${UN}EnsureEpixNetClosed
  Push $0
  Push $1
  check:
  !insertmacro EPIX_RUN_CLOSER detect "${LAUNCHER}"
  ${If} $0 == "0"
    Goto done
  ${EndIf}
  ${If} $0 != "1"
    ; PowerShell unavailable: cannot tell. The file copy still refuses to skip
    ; a locked file (AllowSkipFiles off), so a running EpixNet ends in a
    ; Retry/Abort prompt instead of a half-updated tree.
    DetailPrint "Could not check for a running EpixNet ($0); continuing"
    Goto done
  ${EndIf}
  MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON1 \
    "EpixNet is running.$\r$\n$\r$\nSetup needs to close it (the Epix Browser window and the background node) before it can update the files. Your data and identity stay in place.$\r$\n$\r$\nClose EpixNet now?" \
    /SD IDYES IDYES close
  Abort "Setup cannot continue while EpixNet is running."
  close:
  DetailPrint "Closing EpixNet..."
  !insertmacro EPIX_RUN_CLOSER close "${LAUNCHER}"
  ${If} $0 == "0"
    DetailPrint "EpixNet closed"
    Goto done
  ${EndIf}
  MessageBox MB_RETRYCANCEL|MB_ICONEXCLAMATION \
    "EpixNet is still running.$\r$\n$\r$\nQuit it from its tray icon (Quit EpixNet), close any Epix Browser window, then click Retry." \
    /SD IDCANCEL IDRETRY check
  Abort "Setup cannot continue while EpixNet is running."
  done:
  Pop $1
  Pop $0
FunctionEnd
!macroend
!insertmacro EPIX_ENSURE_CLOSED "" "$PLUGINSDIR\epix-browser.exe"
!insertmacro EPIX_ENSURE_CLOSED "un." "$INSTDIR\epix-browser.exe"

Section "EpixNet" SecMain
  ; The closer script and the new launcher (for a clean --quit of whatever
  ; version is running) go to the temp plugins dir, never into $INSTDIR ahead
  ; of the copy.
  InitPluginsDir
  File "/oname=$PLUGINSDIR\close-epixnet.ps1" "close-epixnet.ps1"
  File "/oname=$PLUGINSDIR\epix-browser.exe" "${STAGE_DIR}\epix-browser.exe"
  Call EnsureEpixNetClosed

  SetOutPath "$INSTDIR"
  File /r "${STAGE_DIR}\*.*"

  ; A tree that copied without the browser's core cannot start; say so here
  ; rather than at first launch. Only checked when the stage bundled Firefox
  ; (a local dev build may pack the launcher alone).
!if /FileExists "${STAGE_DIR}\firefox\xul.dll"
  IfFileExists "$INSTDIR\firefox\xul.dll" +2 0
    Abort "The bundled browser did not install completely (firefox\xul.dll is missing). Run Setup again."
!endif

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
  InitPluginsDir
  File "/oname=$PLUGINSDIR\close-epixnet.ps1" "close-epixnet.ps1"
  Call un.EnsureEpixNetClosed

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
