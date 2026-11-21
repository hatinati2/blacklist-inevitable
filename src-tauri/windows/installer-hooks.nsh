!define AGENT_HOOK_DIR "${__FILEDIR__}"

!macro NSIS_HOOK_PREINSTALL
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=agent-service.ps1 "${AGENT_HOOK_DIR}\\agent-service.ps1"
  DetailPrint "Agent PREINSTALL: invoking PrepareUpgrade helper..."
  ExecWait '"$WINDIR\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\\agent-service.ps1" -Mode PrepareUpgrade -AgentPath "$INSTDIR\\blacklist-inevitable-agent.exe" -LogPath "$TEMP\\BlacklistInevitableAgent-service.log"' $0
  DetailPrint "Agent PREINSTALL helper exit code: $0"
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The existing Agent service could not be stopped safely. Installation has been cancelled." /SD IDOK
    Abort
  ${EndIf}
  SetOutPath "$INSTDIR"
!macroend

!macro NSIS_HOOK_POSTINSTALL
  InitPluginsDir
  SetOutPath "$PLUGINSDIR"
  File /oname=agent-service.ps1 "${AGENT_HOOK_DIR}\\agent-service.ps1"
  DetailPrint "Agent POSTINSTALL: invoking signed-binary verification and service install..."
  ExecWait '"$WINDIR\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\\agent-service.ps1" -Mode Install -AgentPath "$INSTDIR\\blacklist-inevitable-agent.exe" -DesktopPath "$INSTDIR\\blacklist-inevitable.exe" -LogPath "$TEMP\\BlacklistInevitableAgent-service.log"' $0
  DetailPrint "Agent POSTINSTALL helper exit code: $0"
  ${If} $0 == 10
    IfSilent agent_unsigned_done
    MessageBox MB_ICONINFORMATION "The desktop app was installed, but the privileged Agent service was not registered because this package is unsigned. A trusted signed release is required." /SD IDOK
    agent_unsigned_done:
  ${ElseIf} $0 != 0
    MessageBox MB_ICONSTOP "The Agent service could not be securely installed. Installation has been cancelled." /SD IDOK
    Abort
  ${EndIf}
  ; Persist the helper inside the install directory: the uninstaller must not
  ; depend on an installer-only $PLUGINSDIR payload.
  CopyFiles /SILENT "$PLUGINSDIR\\agent-service.ps1" "$INSTDIR"
  IfFileExists "$INSTDIR\\agent-service.ps1" helper_persisted
    MessageBox MB_ICONSTOP "The Agent service helper could not be staged for safe uninstallation." /SD IDOK
    Abort
  helper_persisted:
  SetOutPath "$INSTDIR"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  FileOpen $R9 "$TEMP\\BlacklistInevitableAgent-uninstall-hook.log" w
  FileWrite $R9 "PREUNINSTALL entered; helper=$INSTDIR\\agent-service.ps1"
  IfFileExists "$INSTDIR\\agent-service.ps1" helper_available
    FileWrite $R9 "ERROR: persisted helper is missing."
    FileClose $R9
    MessageBox MB_ICONSTOP "The Agent service helper is missing. Uninstallation has been cancelled to avoid leaving the service orphaned." /SD IDOK
    Abort
  helper_available:
  DetailPrint "Agent PREUNINSTALL: invoking persisted service removal helper..."
  ExecWait '"$WINDIR\\Sysnative\\WindowsPowerShell\\v1.0\\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\\agent-service.ps1" -Mode Uninstall -AgentPath "$INSTDIR\\blacklist-inevitable-agent.exe" -LogPath "$TEMP\\BlacklistInevitableAgent-service.log"' $0
  FileWrite $R9 "PREUNINSTALL helper exit code=$0"
  FileClose $R9
  DetailPrint "Agent PREUNINSTALL helper exit code: $0"
  ${If} $0 != 0
    MessageBox MB_ICONSTOP "The Agent service could not be removed safely. Uninstallation has been cancelled." /SD IDOK
    Abort
  ${EndIf}
  SetOutPath "$INSTDIR"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  Delete "$INSTDIR\\agent-service.ps1"
!macroend
