; ==============================================================================
; UnForce Studio - Self-Extracting Zero-Install Portable Bootstrap
; Extracts complete Chromium forensics studio into subfolder on first launch,
; generates a root folder shortcut, and launches instantly.
; ==============================================================================

Unicode True
RequestExecutionLevel user
SetCompressor /SOLID lzma

Name "UnForce Studio"
Caption "UnForce Studio"
OutFile "..\release\UnForce-Portable.exe"
Icon "..\desktop\assets\icon.ico"

; Clean auto-closing window on first-run extraction
AutoCloseWindow True
ShowInstDetails nevershow
BrandingText "UnForce Forensics Studio"

!define APP_NAME "UnForce Studio"
!define APP_SUBDIR "UnForce Studio"
!define MAIN_EXE "UnForce.exe"

Section
  ; Fast path: If already unpacked, launch immediately without showing extraction UI
  IfFileExists "$EXEDIR\${APP_SUBDIR}\${MAIN_EXE}" launch_existing
  IfFileExists "$EXEDIR\app\${MAIN_EXE}" launch_app_dir

  ; First launch: Extract all internal application files into subfolder
  DetailPrint "Extracting UnForce Forensics Studio files..."
  CreateDirectory "$EXEDIR\${APP_SUBDIR}"
  SetOutPath "$EXEDIR\${APP_SUBDIR}"

  File /r "..\desktop\dist\win-unpacked\*.*"

  ; Create root directory shortcut
  CreateShortCut "$EXEDIR\${APP_NAME}.lnk" "$EXEDIR\${APP_SUBDIR}\${MAIN_EXE}" "" "$EXEDIR\${APP_SUBDIR}\${MAIN_EXE}" 0 "" "" "UnForce - Git Forensics & Commit Recovery Studio"

launch_existing:
  SetOutPath "$EXEDIR\${APP_SUBDIR}"
  Exec '"$EXEDIR\${APP_SUBDIR}\${MAIN_EXE}"'
  Quit

launch_app_dir:
  SetOutPath "$EXEDIR\app"
  Exec '"$EXEDIR\app\${MAIN_EXE}"'
  Quit
SectionEnd
