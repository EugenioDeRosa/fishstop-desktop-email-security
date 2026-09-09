; FishSTOP starts its bundled Ollama runtime as a background child process.
; If Windows force-closes the desktop app during an upgrade, that child can
; survive briefly and keep files in $INSTDIR locked. Stop the background
; executables before NSIS copies or removes application files. Ollama uses the
; same process name for managed and standalone runtimes, so a standalone Ollama
; session is also stopped during an upgrade and can be restarted afterwards.

!macro FISHSTOP_STOP_BACKGROUND_PROCESSES
  nsExec::ExecToLog 'taskkill.exe /F /T /IM fishstop-engine.exe'
  Pop $0
  nsExec::ExecToLog 'taskkill.exe /F /T /IM ollama.exe'
  Pop $0
  Sleep 1000
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro FISHSTOP_STOP_BACKGROUND_PROCESSES
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro FISHSTOP_STOP_BACKGROUND_PROCESSES
!macroend
