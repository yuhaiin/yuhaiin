# Configuration and usability refactor

The backend and frontend share one configuration model. Simple and advanced
editors operate on the same objects. Lists own matching data and indexes; rules
combine match results and choose an action. Obsolete tag/mirror paths are removed.

## Requirements and completion evidence

- [x] Stable rule/list IDs, names independent of identity (storage and HTTP rename tests).
- [x] Rule-owned and shared lists in one table; atomic rule/list editing, ownership
      validation, cleanup, references and deletion protection.
- [x] Direct/default/node/selector destinations, selectors owned by Outbound,
      integration with existing Set execution, obsolete tag/mirror removal.
- [x] Recursive all/any/not conditions, explicit match-all, strict condition validation
      and ordering by stable IDs; configured default action for unmatched traffic
      (contract/runtime and snapshot tests).
- [x] Coordinated saved/applied revisions, failed builds retain running state,
      action/order-only changes reuse indexes, concurrent update protection.
- [x] Complete simple and advanced rule editing without loss of hidden options;
      create, edit, switch destination, delete, reorder and explain matches.
- [x] Unified node import, protocol templates, system-owned identity/origin,
      default selection after import and readable Set member selection.
- [x] Inbound task presets, platform capability checks, listener status and
      connection instructions, existing underlying configuration preserved.
- [x] Overview/setup path linking nodes, default destination, inbounds and tests;
      combined default TCP/UDP selection with advanced independent selection.
- [x] DNS roles, inline resolver creation and separate query/listen configuration.
- [x] Connection explanations and links to rule/node/selector, diagnostics and
      route drafts; actionable failure summaries and retained editor input.
- [x] Task-oriented navigation, advanced tools, readable units and strategies,
      consistent pending/saved/applied/error feedback and shared impact display.
- [x] Regenerated contracts/client; backend tests/race/lint/go-fix/build and
      frontend tests/typecheck/lint/i18n/style/build; rendered interaction evidence.

## Checkouts

- Backend: `/home/asutorufa/Documents/Programming/yuhaiin`
- Frontend: `/run/media/asutorufa/WD20EJRX/yuhaiin-react`

## Implementation and evidence

All listed flows are implemented in the two checkouts above. Browser interactions,
request outcomes, inspected screenshots and validation limits are documented in
[UX_AUDIT.md](UX_AUDIT.md).

- SQLite migrations 8–11 introduce stable identities, owned/shared lists, selectors
  and saved/applied revisions. RuleDraft saves matching data and rules atomically;
  sharing preserves list identity. References and stale edits are protected.
- Tag/mirror API, store and frontend paths are removed. One-time migration flattens
  historical mirrors; candidate groups reuse Set nodes. Canonical models use typed
  default/node/selector destinations and recursive all/any/not/always conditions.
- Lists prepare and own indexes. Runtime installation uses one configuration snapshot
  and compares its version before swapping. Failed preparation preserves the running
  configuration. Name/action/order changes reuse matching indexes.
- Simple and advanced editors share drafts, preserve hidden overrides and provide
  inline resource creation. Task navigation, default selection, imports/templates,
  entry presets/instructions, DNS roles and connection explanations are integrated.
- Import preview assigns fresh IDs and remaps batch references. Partial retries retain
  successful writes. Combined TCP/UDP default selection is transactional.
- Inbound capabilities and status/events/retry APIs are implemented. Fixed sockets bind
  before initialization is published, and TCP-only mixed listeners retain SOCKS5.
  Tests cover occupied ports, retry and actual SOCKS5 negotiation.
- Connection traces carry readable rule/list labels and stable resource IDs. Set dial
  attempts isolate mutable contexts and publish only the winning node metadata.
- Save/apply failures retain revisions and editable input. Apply retries avoid repeating
  already-committed create/delete/reorder operations. Toggle actions apply immediately.

## Final verification

Full backend tests, targeted race suites, workflow-pinned lint (0 issues), go fix
(no changes), production executable build and diff checks passed. Frontend TypeScript,
73 tests, i18n, lint, style audit and production build passed. Desktop and 390 px
mobile interactions were exercised in isolated Chrome using synthetic preview data.
See the audit for exact scope and remaining lint/runtime verification limits.

The backend and frontend changes should be reviewed and deployed together. The new
frontend uses the revised canonical contracts; obsolete Tag/Mirror APIs are removed.
