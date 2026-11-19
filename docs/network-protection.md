# Network Protection (kill switch)

Network Protection blocks Internet traffic that does not go through Yuhaiin,
for every application, at the operating system level. **It keeps blocking
while Yuhaiin is stopped, crashed, killed with `SIGKILL`, or failing to
start**, and on macOS it is restored at boot before anyone logs in. The rules
live in the kernel's packet filter and belong to a separate root service, not
to the Yuhaiin core, so nothing that happens to the core turns them off.

It is part of System Network management: **System Network → Protection** in
the web interface, `GET/PUT /api/v2/system-network/protection` in the API,
and `yuhaiin protection` on the command line.

Implemented for **macOS** (PF). Other platforms report `unsupported`; the API
and the page work everywhere.

> If Yuhaiin cannot start while the kill switch is on, restore the network
> from a terminal. You never need to edit `/etc/pf.conf` or run `pfctl -d`:
>
> ```sh
> sudo yuhaiin protection disable --recovery
> ```

## What is allowed

```text
Application traffic
        │
Network Protection ──┬── Yuhaiin TUN (running) ──> Yuhaiin ──> proxy / tunnel endpoint
                     ├── Yuhaiin's own connections (proxy servers, endpoints, bootstrap DNS, direct routes)
                     ├── Private networks, loopback, DHCP, IPv6 neighbor discovery, link-local multicast
                     ├── Bypass routes (explicit System Network bypasses)
                     └── everything else ──> blocked (TCP reset / ICMP unreachable)
```

| Traffic | Yuhaiin running | Yuhaiin stopped / crashed |
| --- | --- | --- |
| Out through a Yuhaiin TUN | allowed | — (the TUN is gone; its routes go with it) |
| Yuhaiin's own sockets (to proxy servers, tunnel endpoints, DNS, direct destinations) | allowed | — (no such process) |
| Private networks (RFC 1918, RFC 6598 100.64/10, ULA `fc00::/7`, loopback, link-local) | allowed | allowed |
| DHCP / DHCPv6, router & neighbor solicitation/advertisement, `224.0.0.0/24`, `255.255.255.255`, `ff02::/16` | allowed | allowed |
| Bypass routes | allowed | allowed |
| Another program's tunnel (`utun` of a VPN app) | blocked | blocked |
| Anything else on any interface (Wi-Fi, Ethernet, USB adapters, new interfaces) | blocked | blocked |

Blocking is by direction (outgoing) on every interface except loopback, so no
interface name is hard-coded and adapters plugged in later are covered.
Multicast beyond the link and other special-purpose ranges are not allowed.

### Private networks

The same private networks the `non_private` route mode keeps local
(`policy.PrivateNetworks()`): `10/8`, `172.16/12`, `192.168/16`,
`100.64/10`, `fc00::/7`, plus `127/8`, `::1`, `169.254/16`, `fe80::/10`.
Routing and protection therefore agree on what "private" means.

### Bypass routes

Bypasses come from the **effective System Network configuration**, never from
the operating system routing table (which would include the physical default
route and make the kill switch pointless):

- bypass CIDRs of enabled rules that send traffic to a Yuhaiin TUN;
- the countries a GeoIP-inverted rule keeps direct ("everything except CN");
- destinations an active **custom** rule routes to another interface (for
  example a WireGuard interface), exactly as assigned after rule priorities.

Never a bypass: `0.0.0.0/0` / `::/0` entries, global or non_private rules to
another interface ("the whole Internet outside Yuhaiin" — reported as a
problem instead), disabled rules, and private networks (allowed anyway). The
bypass table is recomputed on every System Network reconciliation —
configuration saves, TUN start/stop, network and interface changes, GeoIP
updates — so PF never disagrees with the routes.

A custom rule that sends only some destinations to the TUN means everything
else would go direct; with the kill switch on, "everything else" is blocked.
Use bypass CIDRs (or GeoIP-inverted rules) for destinations that should go
direct.

### Tunnel endpoints and Yuhaiin's own traffic

Yuhaiin's connections to proxy servers and tunnel endpoints must leave
through the physical interface. Instead of an IP list, the kill switch allows
**sockets created by the Yuhaiin process**: the protection service creates a
hidden system group `_yuhaiin` (gid 340–399, no members), the core joins it
at startup (`setgid`, root only), and PF passes TCP/UDP whose socket belongs
to that group (`group <gid>`).

This follows every way an endpoint can change without a race: DNS names
resolved by Yuhaiin's bootstrap resolver, IP changes, reconnects, IPv4 and
IPv6, TCP and UDP, and Yuhaiin's `direct` routes. Nothing has to be added
before a connection or removed after it, so an update never opens a window
without the endpoint. Other processes cannot use the allowance: no user is a
member of the group and only root can switch to it. DNS is not opened in
general — only queries Yuhaiin itself sends to its configured resolvers pass
(the bootstrap policy). Other applications' DNS goes through the TUN, to a
private resolver, or is blocked.

The allowance (like the TUN interfaces) is bound to the core's connection to
the protection service: when the core exits or is killed, the kernel closes
the socket and the service reloads the rules without them at once.

## macOS architecture

```text
Yuhaiin core (root LaunchDaemon com.asutorufa.yuhaiin)
  System Network Manager ──> protection.Controller ──(Unix socket)──┐
                                                                    ▼
Protection service (root LaunchDaemon io.github.yuhaiin.protection, same binary)
  saved state ── pf.Engine ── /sbin/pfctl ── kernel PF
                                   anchor io.github.yuhaiin/protection   (kill switch)
                                   anchor io.github.yuhaiin/forward      (forwarding)
```

| Package | Role |
| --- | --- |
| `pkg/contract/sysnet` (`protection.go`) | OS-neutral API types: settings, status, problems |
| `pkg/sysnet/protection` | OS-neutral `Policy`, `Backend` interface, `Controller` (serialized, coalescing sync) |
| `pkg/sysnet/protection_inputs.go` | Bypass and tunnel inputs from the System Network Manager |
| `pkg/sysnet/protection/pf` | Rule compiler, `pf.conf` registration, pfctl output parsing, `Engine` |
| `pkg/sysnet/protection/helper` | The protection service, its client (the macOS backend), saved state, recovery |
| `cmd/yuhaiin/protection.go` | `yuhaiin protection status / disable [--recovery] / daemon` |

The backend interface is platform neutral (`Status`, `Enable`, `Update`,
`Disable`, `Close`); `Close` never removes protection. A Linux (nftables) or
Windows (WFP) backend implements the same interface; nothing above the
backend knows about anchors, `pfctl` or `utun`.

### The protection service

`yuhaiin install` installs `/usr/local/bin/yuhaiin` (left alone when it is a
Homebrew symlink) and two LaunchDaemons: the Yuhaiin service and
`io.github.yuhaiin.protection` (`/usr/local/bin/yuhaiin protection daemon`,
`RunAtLoad`, `KeepAlive`, root, log `/var/log/yuhaiin-protection.log`). If
the protection service is missing when the kill switch is enabled (for
example after an update from an older version), the core installs and starts
it.

It is the only component that changes PF for the kill switch. Its socket
(`/var/run/io.github.yuhaiin/protection.sock`) accepts four operations —
`status`, `enable`, `update`, `disable` — as typed JSON: no command strings,
no rule text, no file paths. `status` is open to every local user; the other
three require the peer to be root (checked with `LOCAL_PEERCRED`, which the
client cannot forge). Policies are validated (prefixes masked and zone-free,
no `/0` bypass, interface names `^[a-z]{1,10}[0-9]{1,4}$`, limits on sizes)
and compiled from typed values only, so input can never inject a rule.
`pfctl`, `launchctl`, `dscl` and `dseditgroup` run by absolute path with fixed
arguments and no shell.

Saved state: `/Library/Application Support/io.github.yuhaiin/protection/state.json`
(root, `0600`) — enabled, start at boot, the persistent policy (private and
bypass networks), Yuhaiin's PF reference token and the boot session it was
taken in, the socket group. It is the single source of truth for whether
protection is requested; Yuhaiin's own configuration does not contain it, so
a backup or an old configuration can never re-enable a kill switch the user
turned off. Writes are atomic (synced temporary file, rename, synced
directory) and read back.

Every 5 seconds the service checks the real state and repairs it: rules
removed or changed by another program are loaded again, PF switched off with
`pfctl -d` is enabled again with a new reference, a main ruleset replaced
without Yuhaiin's anchor is registered again (at most three times in ten
minutes; then it reports that another program keeps replacing it instead of
fighting), and TUN interfaces that disappeared are dropped from the rules (a
reused `utun` name is never trusted).

### PF anchor and `/etc/pf.conf`

All of Yuhaiin's rules live below `io.github.yuhaiin`. Loading rules into an
anchor is not enough — the main ruleset must evaluate it — so two lines are
added to `/etc/pf.conf`, each carrying the marker
`# managed by Yuhaiin (io.github.yuhaiin)`:

```text
scrub-anchor "com.apple/*"
nat-anchor "com.apple/*"
rdr-anchor "com.apple/*"
nat-anchor "io.github.yuhaiin/*" # managed by Yuhaiin (io.github.yuhaiin)
dummynet-anchor "com.apple/*"
anchor "io.github.yuhaiin/*" # managed by Yuhaiin (io.github.yuhaiin)
anchor "com.apple/*"
load anchor "com.apple" from "/etc/pf.anchors/com.apple"
```

- `nat-anchor` goes after the last translation rule, `anchor` before the
  first filter rule, as PF requires translation before filtering. If a
  customized file rejects the `nat-anchor` position, only the filter anchor is
  registered (forwarding NAT then reports the problem).
- Editing: the current file must load (`pfctl -nf`), the edited copy must
  load, the original is kept as `pf.conf.previous` in the state directory,
  the file is replaced atomically, the running main ruleset is reloaded only
  if it lacks the reference, and a failed reload restores the original file
  and loads it again. Edits are serialized with a lock shared by the core
  (forwarding) and the service.
- Everything else in the file is kept byte for byte. Registering twice adds
  nothing; a line a user added by hand counts as registered and is never
  removed. `yuhaiin uninstall` removes exactly the marked lines.
- `com.apple/*` anchors are not modified. Earlier versions loaded forwarding
  into `com.apple/yuhaiin`; that anchor (which only ever held Yuhaiin's
  rules) is flushed once and forwarding now uses `io.github.yuhaiin/forward`.
- Disabling protection keeps the registration (an empty anchor changes
  nothing); uninstalling removes it.

**Rule order.** Yuhaiin's anchor is the first filter rule, and its rules are:

```text
table <yuhaiin_private> const { 10.0.0.0/8, ... }
table <yuhaiin_bypass>  const { ... }
pass out on lo0 all                                 tag io.github.yuhaiin.pass label "yuhaiin-loopback"
pass out to <yuhaiin_private>                       tag ... label "yuhaiin-private"
pass out inet to { 224.0.0.0/24, 255.255.255.255 }  tag ...
pass out inet6 to ff02::/16                         tag ...
pass out inet proto udp from any port 68 to any port 67     tag ...   (DHCP)
pass out inet6 proto udp from any port 546 to any port 547  tag ...   (DHCPv6)
pass out inet6 proto icmp6 all icmp6-type { routersol, neighbrsol, neighbradv } tag ...
pass out to <yuhaiin_bypass>                        tag ...
pass out on utun4 all keep state (if-bound)         tag ... label "yuhaiin-tunnel"     (while the core runs)
pass out proto tcp all group 340 flags any keep state tag ... label "yuhaiin-own-tcp" (while the core runs)
pass out proto udp all group 340 keep state         tag ... label "yuhaiin-own-udp"
block return out quick all ! tagged io.github.yuhaiin.pass label "yuhaiin-block-<policy id>"
```

Only the final block is `quick`: blocked traffic is final, no later rule of
another program can pass it. Allowed traffic is tagged and passed *without*
`quick`, so it still goes through every later rule — the `com.apple` anchors
and any other firewall can still block it. The kill switch therefore never
bypasses another firewall's restrictions. The macOS Application Firewall
(socket filter, not PF) is independent and keeps working.

Tables are defined inside the ruleset, so a policy update replaces rules and
tables in one PF transaction (`pfctl -a io.github.yuhaiin/protection -f -`),
after a dry run (`pfctl -n`). A rejected ruleset leaves the previous one in
force; a new endpoint or bypass never requires removing an old one first. The
label of the block rule carries the policy fingerprint, which is how the
service verifies that exactly the intended ruleset is loaded.

**States.** TUN rules use `if-bound` states, so a connection's state on a TUN
never matches its packets after the TUN is gone and traffic falls back to a
physical interface. Yuhaiin never kills PF states: if PF was already enabled
by another program, connections opened before protection may continue until
they close (reported as a note); new connections are blocked.

### PF enable reference

PF is enabled with `pfctl -E`, which takes a reference and prints a token.
The service saves the token with the boot session (`kern.bootsessionuuid`)
and releases only that token (`pfctl -X <token>`) when protection is
disabled. PF stays enabled while other programs hold references. Yuhaiin
never runs `pfctl -d`, `pfctl -F all`, flushes the main ruleset or other
anchors, or deletes states.

### Startup

The service is a LaunchDaemon, so it runs at boot before any user logs in.
With **Protect from system startup** on (the default), it loads the rules as
soon as it starts, without waiting for the core: only private networks and
bypass routes are reachable until the core starts and connects. Old TUN names
and processes are never trusted after a restart — tunnels and the core's
allowance only come from a live connection.

With it off, the saved state stays enabled but the service waits after a
reboot; protection returns when the core starts and sends its policy (status
*Initializing* until then).

**Limitation:** launchd starts the service early but does not guarantee it
runs before the network is up. Traffic in the short window between the
network coming up and the service starting is not blocked. The status only
reports *Protected* after the rules are verified in the kernel.

## Status

`Protected` is reported only when PF is enabled, the main ruleset evaluates
the anchor, and the anchor holds exactly the ruleset of the current policy.
Desired and effective state are separate fields; values that cannot be read
are `null`, never guessed.

| State | Meaning |
| --- | --- |
| `protected` | rules verified in the kernel |
| `disabled` | not requested |
| `initializing` | requested, not applied yet (start at boot off, waiting for Yuhaiin) |
| `updating` | a policy update is being applied |
| `degraded` | blocking, but something needs attention (Yuhaiin's own traffic not allowed, damaged state, a failed update) |
| `error` | requested but not enforced, or the state is unknown |
| `unsupported` | no backend on this platform |

The status includes the backend, PF enabled / anchor registered (running and
persistent) / rules loaded / own reference held, the last successful update,
the last error, protected interfaces, Yuhaiin TUNs, private and bypass
networks, how Yuhaiin's traffic passes and its open connection count (PF
states of the own-traffic rules), and the packets and bytes the block rule
rejected (from `pfctl -v -s rules`). "Last blocked" is when the counter was
last seen increasing; PF logs are not parsed. Problems carry a code, a
message and a suggested fix.

## Command line

The command line works without the Yuhaiin core, its web interface, its HTTP
API, its configuration or a network connection.

```sh
yuhaiin protection status            # any user; add -json for JSON
sudo yuhaiin protection disable      # through the protection service
sudo yuhaiin protection disable --yes
sudo yuhaiin protection disable --recovery   # emergency, without the service
```

```text
Yuhaiin Network Protection

Status: Protected

Desired State: Enabled
Effective State: Protected

Backend: macOS PF
Anchor: io.github.yuhaiin/protection
PF: Enabled
Anchor Registered: Yes (pf.conf: yes)
Rules Loaded: Yes
PF Reference Held: Yes
Privileged Helper: Running
Boot Persistence: Enabled
```

When the service does not answer, `status` reads PF and the saved state
directly (with `sudo`), and `disable` prints:

```text
Unable to connect to Yuhaiin Privileged Helper.

Yuhaiin Core may be unavailable.

You can try emergency recovery:

  sudo yuhaiin protection disable --recovery
```

`disable` saves the disabled state, removes the rules, releases Yuhaiin's
reference and succeeds only after the service confirms the rules are gone.

`disable --recovery` needs root and does, in this order:

1. checks administrator rights;
2. checks there is Yuhaiin protection to remove (state file, rules or
   managed lines; otherwise it reports nothing to do and succeeds);
3. saves the state as disabled and syncs it to disk — **before** any rule is
   removed, so neither the service nor a restart can bring protection back;
4. stops the protection service (`launchctl bootout`; it starts again at the
   next boot and keeps protection off);
5. flushes only the `io.github.yuhaiin/protection` anchor;
6. releases only Yuhaiin's own PF reference of this boot;
7. verifies that no protection rules are loaded and that the saved state is
   disabled.

Each step prints OK / FAIL / SKIP; the command exits non-zero unless every
step succeeded, and says so if protection might return at the next start. A
damaged state file is moved aside and replaced. Running it again on an empty
anchor is safe. Other programs' anchors, references, the main ruleset and
PF's enabled state are not touched (PF turns off only if Yuhaiin held the last
reference).

The CLI is `/usr/local/bin/yuhaiin`, the binary both LaunchDaemons run, so it
is on the default `PATH`, updated with Yuhaiin, and survives when the app or
core is broken. `yuhaiin uninstall` removes protection completely (the
recovery steps, the managed `pf.conf` lines, the service, the `_yuhaiin`
group and the state); reinstalling or updating keeps it.

## API

| Method | Path | Permission | |
| --- | --- | --- | --- |
| GET | `/api/v2/system-network/protection` | `settings:read` | status, read from the OS |
| PUT | `/api/v2/system-network/protection` | `settings:write` | `{"enabled": true, "startAtBoot": true}`; returns the status after applying |

Enabling validates and applies the current policy at once; the response says
whether it really took effect. On unsupported platforms GET returns
`state: "unsupported"` and PUT is rejected.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| No Internet at all, Yuhaiin does not start | `sudo yuhaiin protection disable --recovery` |
| *Protected*, but no Internet | No Yuhaiin TUN is running or no rule routes traffic to it (problem `tunnel_missing`). Start the TUN inbound or add a route rule. |
| *Degraded*: Yuhaiin's own connections are blocked | Yuhaiin does not run as root (cannot join `_yuhaiin`). Run it as the system service: `sudo yuhaiin install`. |
| `service_missing` / `service_down` | `sudo yuhaiin install`, or `sudo launchctl kickstart system/io.github.yuhaiin.protection`; see `/var/log/yuhaiin-protection.log`. |
| `registration` | `/etc/pf.conf` does not load (`sudo pfctl -nf /etc/pf.conf`) or an `include`/other tool replaces the main ruleset. Yuhaiin does not edit a file that is already broken. |
| `modified` | Another program flushed the anchor or loaded its own main ruleset. Yuhaiin restores it; if it keeps happening, add `anchor "io.github.yuhaiin/*"` to that program's ruleset. |
| A site that should go direct is blocked | Add it as a bypass CIDR of the TUN rule (or use a GeoIP-inverted rule). Destinations a custom rule leaves out are not bypasses. |
| `ping` from Yuhaiin fails | ICMP has no socket owner PF can match; Yuhaiin's own ICMP is blocked while protection is on. |

## Limitations (macOS)

- Protection at boot depends on launchd starting the service; traffic before
  that is not blocked.
- Yuhaiin's own traffic is identified by socket group and requires Yuhaiin to
  run as root (the system service). ICMP from Yuhaiin itself is blocked.
- Inbound services reachable from the Internet stop answering public clients
  (their replies are outgoing traffic to public addresses). LAN clients work.
- Forwarded (side-router) traffic leaving directly through a physical
  interface is blocked too; forwarding to a Yuhaiin TUN works.
- If another program already had PF enabled, its existing connections may
  continue until they close.
- Interface groups are not available for `utun` on macOS, so Yuhaiin's TUNs
  are listed by name and updated whenever they change.

## Tests

- Unit tests (any OS): policy validation and fingerprints, rule generation,
  input rejection (injection attempts, `/0` bypass, invalid prefixes and
  names), `pf.conf` registration on the default macOS file and custom files,
  pfctl output parsing, the engine against a simulated pfctl
  (`pf/pftest`), and the service end to end over its socket: enable,
  core disconnect, non-root rejection, disable ordering, external changes and
  self-repair, restart and reboot, start-at-boot off, damaged state, rejected
  policies, missing pfctl, vanished TUNs, recovery ordering and failures.
- Real PF on macOS (`.github/workflows/network-protection-macos.yml`, or
  `scripts/integration/network-protection-macos.sh --live` on a disposable
  machine): creates a "Yuhaiin" utun and an unrelated utun, routes
  documentation prefixes through them and checks each verdict by whether the
  packet arrives on the utun descriptor, captures the physical interface with
  tcpdump to prove direct traffic does not leave, and covers own-socket
  traffic, counters, a `pf.conf` reload, rejected updates, a client killed
  with `SIGKILL`, TUN removal, service restart, PF disabled by another
  program, disable with another program's reference held, recovery with the
  service stopped and a simulated reboot, and the real CLI under launchd
  (status as root and non-root, disable, disable without the service,
  `--recovery`, idempotence). `/etc/pf.conf` is compared byte for byte at the
  end and another anchor and reference are checked to be unchanged. A real
  reboot is not part of CI.
