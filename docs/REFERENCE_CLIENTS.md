# Reference clients and design lessons

This project studies mature clients as product and engineering references. It does not copy source code, branding, UI assets, or engine binaries from these projects. Any future code reuse requires a separate dependency and license review.

## Karing

Repository: https://github.com/KaringX/karing

Karing is a Flutter desktop/mobile GUI built around sing-box. Its documented feature set includes subscription formats (V2Ray, sing-box, Clash, Shadowsocks), profile/node groups, routing-rule groups, automatic node selection, backup/synchronization, and a beginner mode.

Useful lessons for this Windows product:
- Keep profile sources, individual nodes, and routing groups as distinct concepts.
- Treat subscriptions and imported local files as first-class profile sources, with update status and errors visible.
- Make simple mode the default, while keeping advanced routing and DNS controls available.
- Keep connection state, selected profile, and runtime health visible.

Important compatibility boundary:
- Karing documents that it uses a modified sing-box core. A feature present in Karing is not automatically present in the official sing-box version pinned by this project.
- Karing's `LICENSE.md` is GPL-3.0-or-later with an additional restriction against using the Karing name or implying association without consent. Review the full license before any reuse.

## v2rayN

Repository: https://github.com/2dust/v2rayN

v2rayN is a Windows-first desktop client that supports multiple engines, including Xray-core and sing-box. Its Naive formatter and tests are useful references for share-link interoperability.

Lessons adopted:
- Use explicit, protocol-specific parsing instead of guessing a link's meaning.
- Test real-world share-link variants, including missing default ports, password-only userinfo, and percent-encoded colons.
- Keep core/process ownership, system proxy handling, DNS, and routing as independent concerns.
- Use a Windows-native release gate rather than assuming a successful portable build proves the installed app works.

v2rayN's repository is GPL-3.0. Its [Naive formatter](https://github.com/2dust/v2rayN/blob/master/v2rayN/ServiceLib/Handler/Fmt/NaiveFmt.cs) and [format tests](https://github.com/2dust/v2rayN/tree/master/v2rayN/ServiceLib.Tests/Fmt) informed the Naive share-link edge cases covered by this project. This project uses public format behavior as an interoperability reference; no v2rayN source code is copied.

## v2rayNG

Repository: https://github.com/2dust/v2rayNG

v2rayNG is an Android client for Xray-core and v2fly-core. Its protocol parser registry and subscription tests are useful references for format coverage and compatibility fixtures.

Lessons adopted:
- Maintain focused parser tests per scheme and per credential encoding.
- Keep subscription metadata and node credentials separate.
- Treat Android VPN service integration as a platform-specific concern. Its implementation is not imported into the Windows application.

v2rayNG's repository is GPL-3.0. No source code is copied.

## Hiddify

Application: https://github.com/hiddify/hiddify-app  
Core: https://github.com/hiddify/hiddify-core

Hiddify is useful as a product reference for multi-format subscription import, user-facing profile metadata, automatic server selection, DNS settings, and a desktop privileged-service boundary. Its [Windows/Linux desktop TUN interface](https://github.com/hiddify/hiddify-app/blob/main/lib/hiddifycore/core_interface/core_interface_desktop_tun.dart) separates the Flutter UI process from an elevated background service that owns the full VPN core. Its [Windows signing/elevation notes](https://github.com/hiddify/hiddify-app/blob/main/docs/windows-code-signing.md) and [core service implementation](https://github.com/hiddify/hiddify-core/tree/main/v2/hcore/adminbgservice) further illustrate the service lifecycle, UAC, and restricted control-secret pattern. These are architectural references, not code copied into this project.

Compatibility boundary:
- Hiddify documents that its app uses `hiddify-sing-box`, a fork with additional contributions including Mieru and other protocols.
- Therefore, Mieru support in Hiddify is not evidence that upstream sing-box 1.14.4 can validate or run Mieru.
- Hiddify's `LICENSE.md` is GPL-3.0 with additional terms, including non-commercial use, attribution, fork/source publication, share-alike, and restrictions on app-store naming/interface similarity. It is not a safe basis for copying code into this project without a specific legal review and permission where required.

Useful lessons adopted:
- Profile import should be separated from subscription download, parsing, and node normalization.
- Display subscription update metadata and actionable import failures rather than treating all invalid input as one error.
- A privileged Windows service can own TUN and routes while the unprivileged UI remains a controller.
- Authenticate local service IPC and restrict its control secret and endpoints to the intended user/service identities.
- DNS configuration and route state are part of the connection lifecycle, not independent toggles.

## Mieru — possible Windows integration path

Upstream project: https://github.com/enfein/mieru

The official Mieru client supports Windows and its documented configuration is a JSON file rather than a canonical `mieru://` share URI. The client config includes a profile with username/password, one or more server IP/domain addresses, TCP/UDP port bindings, MTU, multiplexing and handshake mode; it can expose a local SOCKS5 listener and can be started/stopped/tested through its CLI. Mieru's protocol itself is not TLS-based; its authentication and encryption semantics are distinct from TLS proxy protocols.

Candidate architecture for our Windows client:
- Treat Mieru as a separate engine adapter / supervised sidecar, not as an unsupported outbound type in upstream sing-box.
- Generate a unique Mieru client JSON config from an imported Mieru config/profile, with credentials isolated in a temporary directory protected by a restrictive ACL.
- Start and supervise the official Mieru client as a long-lived child process owned by the privileged Windows agent.
- Connect the main sing-box session to the Mieru client's loopback SOCKS5 listener using a SOCKS5 outbound, but only after testing TCP and UDP ASSOCIATE semantics, crash detection, and cleanup.
- Never use the Mieru CLI's default persistent user configuration for a VPN session unless its profile isolation and credential-at-rest behavior are proven; avoid leaving user secrets in the machine's normal Mieru config directory.
- Check the GPL-3.0 obligations and third-party dependencies before distributing a Mieru binary.

This is a researched option, not implemented support. It does not prove arbitrary Mieru URLs/config formats are interoperable; the initial importer should accept an explicit JSON config file or a documented supported format and reject unknown fields rather than invent a share-link scheme.

## Project decisions

1. Windows remains the only release target until the Windows VPN has passed clean-machine installation, real traffic routing, DNS leak, failure rollback, and upgrade/uninstall tests.
2. The normal VPN session will be Rust-owned and separate from the existing short-lived Real Delay/preflight path.
3. The first normal connection will use the official pinned sing-box engine and only protocol options explicitly supported by its configuration schema.
4. Naive HTTPS / QUIC import and outbound mapping are implemented for a bounded set of v2rayN-style links, using the official sing-box 1.14.4 outbound and the required Windows `libcronet.dll`. Controlled-server authentication tests remain open.
5. Mieru remains a researched compatibility target. It needs separate upstream-core and configuration-format verification before implementation.
6. Subscription formats, groups, routing rules, and profile metadata can be adopted as product concepts incrementally, after the core Windows Connect/Disconnect path is safe.
