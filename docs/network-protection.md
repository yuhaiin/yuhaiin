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

Implemented for **macOS** (PF), **Linux** (nftables) and **Windows**
(Windows Filtering Platform). Android and other platforms report
`unsupported`; the API and the page work everywhere.

| | macOS | Linux | Windows |
| --- | --- | --- | --- |
| Mechanism | PF anchor `io.github.yuhaiin/protection` | nftables table `inet yuhaiin_protection` | WFP provider and sublayer (weight 65535) |
| Applied by | protection service (LaunchDaemon) | the Yuhaiin process (root) | the Yuhaiin process (Windows service) |
| Survives Yuhaiin exiting | rules stay in the kernel | rules stay in the kernel | persistent filters |
| Allowances that end with Yuhaiin | TUN + socket group, bound to its connection to the service | TUN matched by interface index (gone with the device) | TUN + application permits in a dynamic WFP session (Windows deletes them when the process ends) |
| Yuhaiin's own traffic | socket group `_yuhaiin` | Socket Protection mark `0x500` (`SO_MARK`, needs `CAP_NET_ADMIN`) | application ID of the Yuhaiin executable |
| At startup | LaunchDaemon (early, not guaranteed before the network) | `yuhaiin-protection.service`, ordered before `network-pre.target` | persistent filters, applied by the Base Filtering Engine at boot |
| Blocked counters | yes | yes | no (WFP keeps none) |

> If Yuhaiin cannot start while the kill switch is on, restore the network
> from a terminal. You never need to edit `/etc/pf.conf`, run `pfctl -d`,
> flush nftables or delete WFP filters by hand:
>
> ```sh
> sudo yuhaiin protection disable --recovery          # macOS, Linux
> yuhaiin protection disable --recovery               # Windows, elevated terminal
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

## Linux (nftables)

The Yuhaiin process (root, with `CAP_NET_ADMIN`) loads one table:

```text
table inet yuhaiin_protection {
	set private4 { type ipv4_addr; flags constant,interval; elements = { 10.0.0.0/8, ... } }
	set private6 / bypass4 / bypass6 ...
	chain output {
		type filter hook output priority filter; policy accept;
		oifname "lo" counter accept comment "yuhaiin-loopback"
		ip daddr @private4 counter accept / ip6 daddr @private6 counter accept
		link-local multicast, broadcast, DHCP / DHCPv6, router and neighbor solicitation/advertisement
		ip daddr @bypass4 counter accept / ip6 daddr @bypass6 counter accept
		oif <TUN index> counter accept comment "yuhaiin-tunnel"
		meta mark 0x500 counter accept comment "yuhaiin-own"
		meta l4proto tcp counter reject with tcp reset
		meta l4proto != tcp counter reject with icmpx admin-prohibited
	}
}
```

- nftables evaluates every base chain of a hook: Yuhaiin's accept only ends
  its own chain, while its reject — and any other table's drop — is final.
  So the kill switch cannot be passed by another table, and other firewalls
  still apply to what Yuhaiin allows.
- The table is replaced in one netlink batch (delete and add in one kernel
  transaction): a rejected update leaves the previous table, and there is
  no moment without rules. Only this table is ever created or deleted.
- TUNs are matched by interface **index**. When Yuhaiin exits, its TUN is
  destroyed and the rule matches nothing; a TUN another program creates
  later with the same name gets a new index and does not pass.
- Yuhaiin's sockets carry the Socket Protection mark `0x500`; setting a
  mark needs `CAP_NET_ADMIN`, so unprivileged programs cannot use it.
  Without the mark (Yuhaiin not root), its own connections are blocked and
  the status is *degraded*.
- Rules are checked per packet, so connections opened before protection
  keep working when they are allowed.
- State: `/var/lib/yuhaiin/protection/state.json` (root, `0600`).
- Startup: with *Protect from system startup*, Yuhaiin installs and enables
  `/etc/systemd/system/yuhaiin-protection.service` (`DefaultDependencies=no`,
  `Before=network-pre.target`), which runs `yuhaiin protection restore` and
  loads the saved baseline before the network comes up. Without systemd,
  protection returns when Yuhaiin starts (reported).
- Yuhaiin checks the table on every status poll; if another program deleted
  or replaced it, it is loaded again.
- Rules view: every base chain of the system in evaluation order per hook
  (Yuhaiin's marked), Yuhaiin's rules with counters, its sets, the boot
  unit, and `nft list ruleset` when `nft` is installed.

## Windows (Windows Filtering Platform)

The Yuhaiin service (LocalSystem) adds a provider and a sublayer with the
highest weight (65535), and in it filters at the ALE connect layers (IPv4 and
IPv6):

| Weight | Filter | Session |
| --- | --- | --- |
| 12 | permit Yuhaiin's executable (application ID) | dynamic |
| 12 | permit the Yuhaiin TUN (interface LUID) | dynamic |
| 10 | permit loopback, private networks, link-local multicast and broadcast, DHCP / DHCPv6, neighbor discovery, bypass networks | baseline |
| 0 | block | baseline |

- WFP arbitration makes a block in any sublayer final; Yuhaiin's permits
  are soft, so another firewall can still block what Yuhaiin allows.
- Baseline filters are **persistent** when protection starts at boot: the
  Base Filtering Engine applies them at boot, before services start (the
  strongest startup guarantee of the three platforms). Without it they last
  until the next restart.
- The TUN and application permits are created in a **dynamic session**
  owned by the Yuhaiin process: Windows deletes them when the process exits
  or is killed, so a crashed Yuhaiin leaves only the baseline.
- Filters have stable IDs derived from their content. An update adds new
  filters before deleting obsolete ones, and the block filters never go
  away.
- ALE filters decide when a connection is created, so connections opened
  before protection keep working.
- State: `%ProgramData%\yuhaiin\protection\state.json`, in a directory only
  SYSTEM and Administrators can access.
- WFP keeps no per-filter packet counters, so *Blocked traffic* is shown as
  unavailable.
- Rules view: every sublayer by weight (Yuhaiin's marked) and Yuhaiin's
  filters with their conditions.
- Commands that change protection need an elevated terminal
  (`yuhaiin protection disable --recovery` from *Run as administrator*).

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
`RunAtLoad`, `KeepAlive`, root, log `/var/log/yuhaiin-protection.log`).

**The protection service runs only while the kill switch is on.** With it
off, the LaunchDaemon is installed but disabled (`launchctl disable`): no root
process stays resident, nothing starts at boot and PF is not polled. Turning
the kill switch on makes the core (root) enable and start it
(`launchctl enable` + `bootstrap`; a missing LaunchDaemon is installed from
`/usr/local/bin/yuhaiin`); from then on it starts at every boot. Turning it
off — from Yuhaiin, `yuhaiin protection disable` or `--recovery` — removes the
rules, saves the state, and the service disables and unloads itself. A
service started without protection being enabled stops itself after a
minute. Turning protection off and on quickly is safe: an enable cancels a
pending self-stop, and if the service was already stopping the core starts
it again and repeats the request. While the service is stopped the core and
`yuhaiin protection status` report *Disabled* from the saved state, and
the core joins the socket group directly (`dscl`), so its connections already
pass the moment protection is enabled.

**Same binary, own process.** The service is not a separate or embedded
executable: it is the `protection daemon` subcommand of
`/usr/local/bin/yuhaiin`, run by its own LaunchDaemon. Core, service and CLI
therefore always come from one build, and nothing has to be extracted or
signed separately.

**Updates.** An update replaces `/usr/local/bin/yuhaiin` and restarts the
core. The service reports its build (`serviceVersion` in the status); when
the core starts and the running service is a different build, the core
restarts it (`launchctl kickstart -k`) so it runs the new binary.
`yuhaiin install` does the same, and `sudo yuhaiin protection restart` does
it by hand; `yuhaiin protection status` warns while the builds differ. A
restart never opens the network: the rules stay in the kernel, and the new
process verifies and keeps them. The macOS test samples the kernel every
20 ms during an upgrade and requires the rules and PF to be present
throughout.

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

### Rules view

**System Network → Protection → Packet filter rules** shows, read-only:

- the system's **main ruleset in full**, translation then filter rules in
  evaluation order, with Yuhaiin's lines marked — so you can check that
  Yuhaiin's anchor comes before other filter rules;
- Yuhaiin's rule sets (`io.github.yuhaiin/protection`,
  `io.github.yuhaiin/forward`): every rule with its category (loopback,
  private, local network services, bypass, TUN, Yuhaiin's own traffic,
  block, forwarding) and its counters (evaluations, packets, bytes, states);
- the contents of `<yuhaiin_private>` and `<yuhaiin_bypass>` (up to 2000
  addresses each, with the full count);
- Yuhaiin's lines in `/etc/pf.conf` with their line numbers;
- the raw pfctl output, to copy into bug reports.

It is read by the core with fixed read-only pfctl calls (`-s`, `-T show`),
so it also works while the kill switch is off and the protection service is
stopped. The main ruleset may include other programs' rules; the view needs
`settings:read`. Nothing can be changed from it.

| Method | Path | Permission |
| --- | --- | --- |
| GET | `/api/v2/system-network/protection/rules` | `settings:read` |

## Command line

The command line works without the Yuhaiin core, its web interface, its HTTP
API, its configuration or a network connection.

```sh
yuhaiin protection status            # any user; add -json for JSON
sudo yuhaiin protection disable      # through the protection service
sudo yuhaiin protection disable --yes
sudo yuhaiin protection disable --recovery   # emergency, without the service
sudo yuhaiin protection restart              # run the installed binary (after an update)
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
4. stops the protection service and disables it (`launchctl disable` and
   `bootout`), so launchd does not start it again, also not at boot, until
   the kill switch is enabled again;
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

## Limitations (Linux)

- Without systemd, protection is not restored at boot (only when Yuhaiin
  starts).
- Yuhaiin's own traffic needs the socket mark, so Yuhaiin must run with
  `CAP_NET_ADMIN` (root); ICMP from Yuhaiin itself is allowed only with the
  mark.
- Only locally generated traffic (the output hook) is filtered; forwarded
  traffic follows the forwarding rules.
- While Yuhaiin is not running, nothing repairs a table another program
  deleted (the next start or boot loads it again).

## Limitations (Windows)

- No blocked-traffic counters.
- Yuhaiin's own traffic is identified by executable path; another program
  would have to replace that executable (administrator rights) to use it.
- Only outgoing connections are filtered (ALE connect); inbound services
  keep accepting connections.

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
- If another program runs `pfctl -d`, the packet filter is off until the
  service's next check (at most 5 seconds) re-enables it.
- Connections Yuhaiin opened before it joined the socket group (only when
  the protection service was installed after Yuhaiin started) are blocked
  once protection is on and reconnect.
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
- Linux, real nftables: `scripts/integration/network-protection-podman.sh`
  (a privileged Podman container, so the host is not touched) or the
  `nftables` job (a fresh network namespace). Dummy interfaces and TUNs
  carry the test destinations; verdicts come from transmit counters and
  from reading the TUN: direct IPv4/IPv6 blocked, bypass, private and
  marked sockets allowed, the Yuhaiin TUN allowed and another TUN blocked,
  another table's drop still applying, an existing connection surviving, a
  reused TUN name not passing, a rejected update keeping the table, only
  Yuhaiin's table removed, the backend restoring a deleted table, boot
  restore, and recovery (idempotent, no restore after it).
- Windows, real WFP (`wfp` job): verdicts from a copy of the test binary
  (another application ID) — public blocked, bypass, loopback and private
  allowed — Yuhaiin's executable allowed, an existing connection surviving,
  persistent baseline and non-persistent runtime filters, the runtime
  permits disappearing with the process, restore by a new process,
  detection of deleted filters, other providers' filters unchanged, the
  rules view, and recovery with the real `yuhaiin.exe` (idempotent).
- Real PF on macOS (`.github/workflows/network-protection.yml`, or
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
