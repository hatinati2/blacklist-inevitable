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

v2rayN's repository is GPL-3.0. This project uses its public format behavior as an interoperability reference; no v2rayN source code is copied.

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

Hiddify is useful as a product reference for multi-format subscription import, user-facing profile metadata, automatic server selection, DNS settings, and a desktop privileged-service boundary. Its Windows desktop TUN interface explicitly separates the Flutter UI process from an elevated background service that owns the full VPN core. That is a useful architectural pattern to evaluate for Windows, rather than elevating the UI process itself.

Compatibility boundary:
- Hiddify documents that its app uses `hiddify-sing-box`, a fork with additional contributions including Mieru and other protocols.
- Therefore, Mieru support in Hiddify is not evidence that upstream sing-box 1.14.4 can validate or run Mieru.
- Hiddify's `LICENSE.md` is GPL-3.0 with additional terms, including non-commercial use, attribution, fork/source publication, share-alike, and restrictions on app-store naming/interface similarity. It is not a safe basis for copying code into this project without a specific legal review and permission where required.

Useful lessons adopted:
- Profile import should be separated from subscription download, parsing, and node normalization.
- Display subscription update metadata and actionable import failures rather than treating all invalid input as one error.
- A privileged Windows service can own TUN and routes while the unprivileged UI remains a controller.
- DNS configuration and route state are part of the connection lifecycle, not independent toggles.

## Project decisions

1. Windows remains the only release target until the Windows VPN has passed clean-machine installation, real traffic routing, DNS leak, failure rollback, and upgrade/uninstall tests.
2. The normal VPN session will be Rust-owned and separate from the existing short-lived Real Delay/preflight path.
3. The first normal connection will use the official pinned sing-box engine and only protocol options explicitly supported by its configuration schema.
4. Naive HTTPS / QUIC import and outbound mapping are implemented for a bounded set of v2rayN-style links, using the official sing-box 1.14.4 outbound and the required Windows `libcronet.dll`. Controlled-server authentication tests remain open.
5. Mieru remains a researched compatibility target. It needs separate upstream-core and configuration-format verification before implementation.
6. Subscription formats, groups, routing rules, and profile metadata can be adopted as product concepts incrementally, after the core Windows Connect/Disconnect path is safe.
