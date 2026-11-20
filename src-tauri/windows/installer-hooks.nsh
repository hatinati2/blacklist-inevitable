!define AGENT_HOOK_DIR "${__FILEDIR__}"

!macro NSIS_HOOK_PREINSTALL
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=agent-service.ps1 "${AGENT_HOOK_DIR}\agent-service.ps1"
  DetailPrint "Stopping an existing Blacklist Inevitable Agent service before replacing its binary..."
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\agent-service.ps1" -Mode PrepareUpgrade -AgentPath "$INSTDIR\blacklist-inevitable-agent.exe"' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The existing Agent service could not be stopped safely. Installation has been cancelled."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=agent-service.ps1 "${AGENT_HOOK_DIR}\agent-service.ps1"
  DetailPrint "Verifying signed Agent binaries and configuring the Windows service..."
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\agent-service.ps1" -Mode Install -AgentPath "$INSTDIR\blacklist-inevitable-agent.exe" -DesktopPath "$INSTDIR\blacklist-inevitable.exe"' $0
  ${If} $0 == 10
    IfSilent agent_unsigned_done
    MessageBox MB_ICONINFORMATION "The desktop app was installed, but the privileged Agent service was not registered because this package is unsigned. A trusted signed release is required."
    agent_unsigned_done:
  ${ElseIf} $0 != 0
    MessageBox MB_ICONSTOP "The Agent service could not be securely installed. Installation has been cancelled."
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=agent-service.ps1 "${AGENT_HOOK_DIR}\agent-service.ps1"
  DetailPrint "Stopping and removing the Blacklist Inevitable Agent service..."
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\agent-service.ps1" -Mode Uninstall -AgentPath "$INSTDIR\blacklist-inevitable-agent.exe"' $0
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The Agent service could not be removed safely. Uninstallation has been cancelled."
    Abort
  ${EndIf}
!macroend
