!define AGENT_HOOK_DIR "${__FILEDIR__}"

!macro NSIS_HOOK_PREINSTALL
  LogSet on
  LogText "Blacklist Inevitable: PREINSTALL hook entered"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=agent-service.ps1 "${AGENT_HOOK_DIR}\agent-service.ps1"
  DetailPrint "Agent PREINSTALL: invoking PrepareUpgrade helper..."
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\agent-service.ps1" -Mode PrepareUpgrade -AgentPath "$INSTDIR\blacklist-inevitable-agent.exe" -LogPath "$TEMP\BlacklistInevitableAgent-service.log"' $0
  DetailPrint "Agent PREINSTALL helper exit code: $0"
  LogText "Agent PREINSTALL helper exit code: $0"
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The existing Agent service could not be stopped safely. Installation has been cancelled." /SD IDOK
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  LogText "Blacklist Inevitable: POSTINSTALL hook entered"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=agent-service.ps1 "${AGENT_HOOK_DIR}\agent-service.ps1"
  DetailPrint "Agent POSTINSTALL: invoking signed-binary verification and service install..."
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\agent-service.ps1" -Mode Install -AgentPath "$INSTDIR\blacklist-inevitable-agent.exe" -DesktopPath "$INSTDIR\blacklist-inevitable.exe" -LogPath "$TEMP\BlacklistInevitableAgent-service.log"' $0
  DetailPrint "Agent POSTINSTALL helper exit code: $0"
  LogText "Agent POSTINSTALL helper exit code: $0"
  ${If} $0 == 10
    IfSilent agent_unsigned_done
    MessageBox MB_ICONINFORMATION "The desktop app was installed, but the privileged Agent service was not registered because this package is unsigned. A trusted signed release is required." /SD IDOK
    agent_unsigned_done:
  ${ElseIf} $0 != 0
    MessageBox MB_ICONSTOP "The Agent service could not be securely installed. Installation has been cancelled." /SD IDOK
    Abort
  ${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  LogText "Blacklist Inevitable: PREUNINSTALL hook entered"
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=agent-service.ps1 "${AGENT_HOOK_DIR}\agent-service.ps1"
  DetailPrint "Agent PREUNINSTALL: invoking service removal helper..."
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\agent-service.ps1" -Mode Uninstall -AgentPath "$INSTDIR\blacklist-inevitable-agent.exe" -LogPath "$TEMP\BlacklistInevitableAgent-service.log"' $0
  DetailPrint "Agent PREUNINSTALL helper exit code: $0"
  LogText "Agent PREUNINSTALL helper exit code: $0"
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The Agent service could not be removed safely. Uninstallation has been cancelled." /SD IDOK
    Abort
  ${EndIf}
!macroend
