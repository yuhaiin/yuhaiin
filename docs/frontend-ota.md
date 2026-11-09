# Frontend OTA protocol (v1)

The embedded frontend remains a usable recovery image. The Go Core serves either
its embedded assets, a verified downloaded frontend, or the explicitly configured
EXTERNAL_WEB directory. Switching the selected UI never restarts the Core, VPN,
or the proxy network stack.

## Precedence

1. EXTERNAL_WEB is an explicit operator/developer override and disables OTA.
2. A compatible installed release is selected **only if its buildNumber is
   strictly greater** than the embedded release's buildNumber.
3. If the current downloaded release is unreadable or incompatible, a compatible
   previous release may be used, subject to the same embedded precedence.
4. Otherwise the binary's embedded frontend is served.

This comparison runs on startup and during UI requests. Upgrading a binary with
a newer embedded frontend therefore overrides a stale installed OTA automatically.
No removal of the installed release is required. Bundled assets use the metadata
from ui-build.json; pre-metadata Go modules use their pseudo-version timestamp.

## Update protocol

The v2 channel is the rolling `ui-v2` prerelease of
https://github.com/yuhaiin/yuhaiin-react, which CI refreshes on every v2 build:

- feed: https://github.com/yuhaiin/yuhaiin-react/releases/download/ui-v2/ui-update.json
- archive: https://github.com/yuhaiin/yuhaiin-react/releases/download/ui-v2/frontend.tar.gz

The feed metadata includes version, monotonic buildNumber, apiContract, required
and optional capabilities, Android bridge minimum, archive byte size, and
SHA-256. The feed's archive URL must be exactly the archive above. GitHub
redirects release downloads to its asset hosts; only github.com,
objects.githubusercontent.com and release-assets.githubusercontent.com are
followed, over HTTPS, for at most two redirects.

The stable channel (https://yuhaiin.github.io/ui-update.json, built from the
main branch) is deliberately never read here. v2 build numbers use their own
range (2_000_000_000_000 and up, see yuhaiin-react scripts/ui-ota.mjs), so even
a stray stable bundle could not outrank a v2 build. Because release assets are
replaced in place, the archive is uploaded before the feed; a client that sees a
new feed with an old archive fails the size/SHA-256 check and retries later.

The Core refuses unknown API contracts, unknown required capabilities, Android
bridge requirements it cannot satisfy, outdated build numbers, invalid archive
hashes or sizes, archive traversal, symlinks and decompression bombs.

The frontend Update section calls the permission-checked v2 RPC operations:

- frontend.status: inspect selected, embedded, installed and previous releases
- frontend.check: check the official feed without modifying running files
- frontend.apply: verify a specific feed version and checksum, download and install
- frontend.rollback: restore the last downloaded/embedded candidate
- frontend.reset: force the current binary's embedded frontend

Mutating endpoints require update:manage. HTTP caches must not pin index.html,
and previously installed hashed assets are retained for already-open browser tabs.

When a downloaded UI cannot render, open /__ui_recovery, which is served by the
Core binary. The Android WebView menu also exposes that recovery page.

## Compatibility contract maintenance

apiContract version 1 and the requiredCapabilities list are explicit,
maintainer-reviewed declarations. A pure UI/CSS change does not need a new API
contract. An additive feature should use an optional capability guard, so a
compatible older Core can show an upgrade notice for that feature without
breaking existing pages. A breaking change to a required API or its request or
response semantics MUST bump the contract and coordinate with the Core.

CI should cover supported old backend/Android hosts before an OTA is promoted.
Adding a feature is not automatically proof of compatibility.

## Deployment/security notes

The v1 feed is served from one fixed HTTPS origin and the downloaded archive
is integrity-checked against the feed. Detached cryptographic manifest signing
has not yet been provisioned. For now updates are manually installed, not
silently auto-applied. Do not enable unattended OTA installation without a
reviewed signing and release-key management process.
