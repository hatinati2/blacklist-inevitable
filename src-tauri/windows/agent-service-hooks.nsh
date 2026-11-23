!macro NSIS_HOOK_PREINSTALL
  ; Stop the existing Agent before NSIS replaces its executable during upgrade.
  \${If} \${FileExists} "$INSTDIR\resources\windows-agent-service.ps1"
    ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\windows-agent-service.ps1" -Action Stop' $0
    \${If} $0 != 0
      MessageBox MB_ICONSTOP "The existing blacklist-inevitable Agent could not be stopped safely. The upgrade has been cancelled."
      Abort
    \${EndIf}
  \${EndIf}
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; The helper refuses to register an unsigned service or an unpinned publisher.
  ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\windows-agent-service.ps1" -Action Install -AgentPath "$INSTDIR\resources\blacklist-inevitable-agent.exe" -InstallerPath "$EXEPATH" -SignerThumbprintFile "$INSTDIR\resources\agent-publisher-thumbprint.txt"' $0
  \${If} $0 == 10
    MessageBox MB_ICONINFORMATION "The desktop application was installed. This build has no configured trusted publisher signature, so the privileged Agent was intentionally left unregistered. VPN connection operations remain unavailable."
  \${ElseIf} $0 != 0
    MessageBox MB_ICONEXCLAMATION "The desktop application was installed, but the privileged Agent could not be installed securely. The application will remain disconnected. Windows error code: $0"
  \${EndIf}
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; Remove the service before its executable is deleted. Preserve ProgramData state.
  \${If} \${FileExists} "$INSTDIR\resources\windows-agent-service.ps1"
    ExecWait '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$INSTDIR\resources\windows-agent-service.ps1" -Action Remove' $0
    \${If} $0 != 0
      MessageBox MB_ICONSTOP "The blacklist-inevitable Agent could not be removed safely. The application files have been retained."
      Abort
    \${EndIf}
  \${EndIf}
!macroend
