# Configuration flow audit

Captured in an isolated Chrome session with explicit user authorization, using the
local frontend preview and synthetic MSW data. These screenshots prove rendered
interaction behavior, not remote connectivity. Real SQLite/runtime tests separately
cover transactions, failed apply, references, socket initialization and retry.

## Verified steps

1. Home setup: default routing and a three-step setup path are visible.
2. Rule creation: domain data, destination selection and optional sharing are in one
   editor; one save commits the rule and owned/shared data. The preview returned a
   new rule and closed the modal.
3. Routing overview: advanced DNS controls are collapsed so routing actions remain
   visible. Comboboxes have explicit accessible names.
4. Connection decision: rule, shared destination and selected node are linked; matched
   data uses readable names. Links use stable identities.
5. Connection-derived draft: hostname and matching data are prefilled. Saving and
   applying clears the query and closes the modal; opening the link alone writes no
   configuration.
6. DNS roles: inline resolver creation selects the new resolver; saving its role
   preserves the default routing action/target. A stale resolver tile list found in
   this step was repaired by invalidating all resolver-list caches. Reverification
   showed the new resolver in both its role picker and the visible tile list. The
   updated capture shows the listener before collapsed advanced settings.
7. Entry editing: initialized listener status, incoming-request counts and connection
   instructions are visible. Missing runtime endpoints found during the audit were
   added; occupied-port/retry/SOCKS5 tests cover the actual backend.
8. Failed apply: an inline error and retained input remain visible. Retry sent a second
   apply request without creating a second rule (create count 1; apply statuses 500,
   200), then closed the editor.
9. Mobile rule editing (390 × 844): the dialog width equals its scroll width (364 px).
   Its body scrolls vertically while the save action stays visible. Switching to the
   advanced editor retained the name and matching text.

10. Shared destination replacement: selected node changed to Node 1 with the same
    destination ID and revision 2. The 35 references are collapsed for readability;
    delete remains disabled. The final stable modal capture replaced two rejected
    captures taken during opening/closing animations.

11. Import recovery: two previewed nodes produced create statuses 200 and 500.
    Retry sent one additional create (200), then selected the imported default node
    (200) and closed the dialog. Successful nodes were not recreated. A stale virtual
    preview module initially repeated the simulated failure; explicit module-cache
    invalidation repaired the harness, and the flow was rerun against fresh fixtures.

12. Mobile default selection: imported nodes became both defaults after recovery.
    The advanced choice changed UDP alone to Node 1; the request succeeded and the
    home displayed different TCP/UDP endpoints. Dialog width and scroll width both
    measured 364 px. The mobile navigation opened and reached DNS directly.

13. Advanced conditions: selected an inline-created resolver, switched to simple and
    back, and retained the custom DNS override and selector. Saved an AND containing
    a host-list reference and NOT(TCP), plus an OR containing ports 443/8443; the
    canonical response retained the full expression and override (revision 2).
14. Diagnostics: the synthetic target report completed (200) and exposed copy/download
    actions. This checks rendering and request wiring, not external network health.
15. Mobile entry: chose the LAN preset, named and saved a mixed listener on
    0.0.0.0:9002 (200). Instructions use the managed device's reachable IP, and the
    dialog measured 364 px for both width and scroll width.
16. Node template: chose failover, selected Node 1 and Node 94 from all 95 candidates,
    moved Node 94 first and chose configured order. Save returned the Set chain with
    IDs in that order; reopening retained the strategy and order. The final capture
    replaced an earlier capture containing a closing dropdown animation.
17. Rule controls: disabling saved and applied (200). Exchanging two rules sent one
    priority command; simulated apply failure (500) retained the modal, and retry
    applied (200) without repeating the exchange. The first row remained the intended
    target. Deleting that rule returned 200 and removed the row.
18. Resolver names: a custom resolver initially appeared as its UUID in the rule table.
    The table now resolves the display name; the repaired rendering showed Office DNS.

## Screenshots

Files are retained under
`/home/asutorufa/.codex/visualizations/2026/10/12/01a12fd2-cd71-7291-9bbc-86635ae66270/ux-audit/`:

- `01-home.png`
- `02-rule-editor.png`
- `03-routing-overview.png`
- `04-connection-decision.png`
- `05-connection-rule-draft.png`
- `06-dns-roles.png` (repaired list cache/layout verified)
- `07-entry-status.png`
- `08-apply-failed.png`
- `09-mobile-rule.png`
- `10-shared-destination.png`
- `11-import-partial-failure.png` (partial failure; recovery verified by request counts)
- `12-mobile-default-selection.png`
- `13-advanced-rule.png`
- `14-diagnostics.png`
- `15-mobile-entry.png`
- `16-fallback-node.png`

Every listed screenshot was opened and inspected. Some captures preceded subsequent
copy/layout repairs; they remain evidence of those findings, not proof of the final
render after repair. Replace or supplement them when each repair is reverified.

## Validation and limits

- Backend full suite: `go test -p 2 ./...` passed.
- Race: store, route, node, netapi, inbound, httpapi, resolver and SQLite passed.
- Workflow-pinned golangci-lint v2.14.0: 0 issues. `go fix ./...` changed no Go files.
- Production executable build and both working-tree diff checks passed.
- Frontend: TypeScript, 73 tests in 38 files, i18n checks for 14 namespaces,
  lint, style audit and production build passed. React lint warnings remain; the
  style audit reports existing patterns rather than enforcing zero occurrences.
- No application page errors were recorded in the browser checks.

Screenshots alone do not establish WCAG compliance, runtime forwarding health or
performance under production traffic. Preview import uses canonical JSON; share-link
formats are covered by backend parser tests. Synthetic diagnostics return an empty
check list to avoid external network access. Listener status describes initialization
and ingress, not continuous end-to-end health. ResizeObserver notification warnings
appeared in the development server during layout changes; no blocked interaction was
observed. The in-app browser was unavailable, so the isolated fallback was used with
explicit user permission.

`go build ./...` encounters ignored local main packages without entrypoints in
`cmd/test` and `pkg/net/proxy/tproxy/test`. These user-owned scratch directories were
left untouched; the production executable and full test suite build successfully.

## Visual refinement — 2026-10-13

The frontend refinement adds a page heading, a compact default-routing layout,
rule rows grouping action and destination, textual/color/icon action badges,
separate matching/handling sections and clear primary save actions. The node
editor's maximum width is reduced from 1280 to 960 px. Existing theme tokens
and configuration contracts are reused.

Browser checks cover desktop light/dark rendering, 390 px mobile rendering,
mode changes (proxy/direct/block), editor switching, save/reopen after rename,
and priority controls opening only their intended modal. Mobile rule dialogs
measure 364 px for both client and scroll width. A stale detail-cache issue
found on save/reopen was repaired by storing the canonical save response in
SWR. Synthetic save requests returned 200; the reopened name matched the save.

Inspected captures are in the adjacent `ux-style` visualization folder:
`01-routing-desktop.png`, `02-routing-dark.png`, `03-editor-dark.png`,
`04-editor-desktop.png`, `05-editor-mobile.png`, `06-routing-mobile.png`,
`07-node-editor.png`. The node dialog measures 958 px without horizontal overflow;
the 834 px tablet routing surface also has no horizontal overflow.
A screenshot taken during a theme transition was rejected and replaced.
TypeScript, 73 tests, i18n, lint and production build passed; React lint warnings
remain. The screenshots use local synthetic data and do not measure production
network behavior or certify accessibility compliance.

## Integration with current main

Both branches were rebased onto the current main branches before opening their
paired pull requests. The existing custom-group editor and five new VPN protocols
were retained. Generated TypeScript contracts were reproduced from the rebased Go
sources. With the current lockfile installed, the frontend passed 78 tests in 40
files, TypeScript, i18n, lint, style audit and production build. The group test needed
a jsdom-only scrolling shim; the real Chrome group-edit flow was checked separately.
The backend full suite, focused routing/storage/runtime and VPN race checks,
workflow-pinned lint, go fix and production build passed. Tracked Go files pass the
gofmt check. React lint warnings remain.

## Compact list refinement

Routing rules, nodes and shared destinations now use flat rows with restrained
separators and nearby controls. The routing list places the name, status, action
and destination together instead of distributing them across expanding columns.
These pages cap the content width at 896 px. Fallback settings collapse behind
a summary; the rule menu keeps priority and enable/disable controls accessible.
Other accordion consumers retain their panel appearance.

Isolated Chrome checks covered light/dark desktop rendering, 390 px mobile
rendering without horizontal overflow, a long node name, expansion, searching
Node 94 in a 95-node group, shared-destination editing and the rule priority menu
opening exactly one dialog. No page errors were recorded. Captures taken during
page transitions or with the heading scrolled out of view were replaced. The
frontend again passed 78 tests in 40 files, TypeScript, i18n, lint, style audit and
production build. The frontend PR includes inspected synthetic-data screenshots
in `docs/ux-refactor`.
