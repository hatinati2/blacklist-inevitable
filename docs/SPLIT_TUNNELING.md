# Windows split tunneling

The Windows TUN configuration supports five routing modes:

| Mode | Listed applications | All other applications |
| --- | --- | --- |
| Full Tunnel | VPN (default) | VPN |
| Direct Only | Direct | Direct |
| Include Selected | VPN | Direct |
| Exclude Selected | Direct | VPN |
| Custom | Each entry chooses VPN, Direct, or Block | Configurable VPN or Direct fallback |

Applications are identified by their exact absolute Win32 executable path, not by a process display name or a caller-supplied regular expression. This avoids accidental matches when unrelated applications use the same executable name. Paths are validated as drive-rooted or UNC .exe paths, normalized to Windows separators, checked for duplicates case-insensitively, and capped at 256 entries.

The generated sing-box rules use the Windows-supported process_path route matcher. VPN routes target the selected profile outbound, Direct routes target an explicit direct outbound, and Block rules use the sing-box reject action. Include/Exclude modes apply a stable fallback route to every process that is not selected.

DNS remains encrypted via the configured HTTPS resolver. Direct Only sends that resolver through the direct outbound; other modes keep DNS on the selected VPN outbound by default. Windows' DNS Client can issue shared DNS requests on behalf of multiple applications, so DNS cannot always be attributed to the originating EXE. The UI must disclose this behavior rather than promise fully per-process DNS routing.

This module only builds and validates policy JSON. It does not yet provide the Windows process picker, persist user selections, run an elevated agent, start the TUN, or apply the policy to live traffic. Those remain release-blocking integration work. The pinned sing-box validator is used in Windows CI to check every generated mode.
