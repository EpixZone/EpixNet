; NSIS Installer Script for EpixNet
; This script creates a Windows installer (.exe) for EpixNet

!include "MUI2.nsh"

; Basic Settings
Name "EpixNet"
OutFile "dist\installers\EpixNet-windows-x64.exe"
InstallDir "$PROGRAMFILES\EpixNet"
InstallDirRegKey HKCU "Software\EpixNet" ""

; Set compression
SetCompressor /SOLID lzma

; MUI Settings
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; Installer sections
Section "Install"
  SetOutPath "$INSTDIR"

  ; Copy all files from the PyInstaller output directory
  ; This preserves the _internal directory structure required by PyInstaller
  File /r "dist\windows\EpixNet\*.*"
  
  ; Create Start Menu shortcuts
  CreateDirectory "$SMPROGRAMS\EpixNet"
  CreateShortcut "$SMPROGRAMS\EpixNet\EpixNet.lnk" "$INSTDIR\EpixNet.exe" "--open-browser"
  CreateShortcut "$SMPROGRAMS\EpixNet\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  ; Create Desktop shortcut
  CreateShortcut "$DESKTOP\EpixNet.lnk" "$INSTDIR\EpixNet.exe" "--open-browser"
  
  ; Write registry keys for uninstall
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\EpixNet" "DisplayName" "EpixNet"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\EpixNet" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\EpixNet" "DisplayIcon" "$INSTDIR\EpixNet.exe"
  
  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

; Uninstaller section
Section "Uninstall"
  ; Remove files
  RMDir /r "$INSTDIR"
  
  ; Remove shortcuts
  RMDir /r "$SMPROGRAMS\EpixNet"
  Delete "$DESKTOP\EpixNet.lnk"
  
  ; Remove registry keys
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\EpixNet"
  DeleteRegKey HKCU "Software\EpixNet"
SectionEnd

