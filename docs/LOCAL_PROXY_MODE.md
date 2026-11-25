# Local SOCKS5 proxy mode

This mode provides an immediately usable per-application proxy without changing Windows-wide networking.

## Start

1. Install the verified sing-box 1.14.4 engine from the desktop app.
2. Import a supported VLESS, VMess, Trojan, Shadowsocks, Hysteria2, TUIC, or Naive profile.
3. Select **Start local SOCKS5** on that profile.
4. Copy the displayed loopback host, port, username, and password into an application that supports manual SOCKS5 proxy settings.

The listener binds to `127.0.0.1` only. A fresh random username and password are generated for every session, and the app verifies a successful SOCKS5 username/password handshake before reporting the proxy as running. The proxy credentials are not the remote profile credentials.

## Stop and cleanup

Use **Stop local proxy** to terminate the contained sing-box child, confirm process exit, and remove its credential-bearing temporary configuration. The engine child is placed inside the desktop process's Windows Job Object before it is resumed. The job's kill-on-close behavior is the crash containment backstop. On the next launch, stale session configuration files are removed only from the recognized app-owned local-proxy directory; unexpected files or reparse points stop cleanup rather than being followed.

If process termination or configuration-file cleanup cannot be confirmed, engine work is marked unhealthy and new operations are blocked.

## Scope and limitations

This mode is **not a system-wide VPN**. It does not create a TUN interface, change Windows routes, change DNS settings, change the Windows system proxy, install or activate a firewall policy, or provide a kill switch. Only applications explicitly configured to use this authenticated SOCKS5 endpoint send their traffic through the selected profile. Applications that resolve names locally may still use the system DNS path; select remote DNS resolution in the client application where supported.

The privileged Windows Agent still rejects full Connect/Disconnect TUN operations. System-wide VPN activation remains gated on Agent-owned engine installation, TUN and WFP lifecycle, exact route and dual-stack DNS recovery, crash/reboot validation, and packet-level leak-prevention tests. A successful local SOCKS5 session must not be presented as proof of those capabilities.
