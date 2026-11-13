# Automatic FakeIP routes for TUN

The TUN protocol's `autoFakeIpRoute` boolean routes the active FakeIP IPv4 and
IPv6 pools to that TUN. New TUNs created in the Web UI enable this option.
Missing fields in existing or migrated configurations remain disabled; API
clients opt in explicitly.

Only address families configured on the TUN are added. IPv6 also requires the
global IPv6 setting. The option is independent of the global FakeDNS switch,
because inbound DNS hijacking or forced FakeIP can still use those pools.

The pools are *required routes* of the TUN. The TUN reports them to the System
Network Manager ([system-network.md](system-network.md)), which installs them
ahead of every route rule and removes them when the TUN stops. If two TUNs
request the same pool, the first one (by inbound ID) owns it and the other is
reported as a conflict in the System Network status.

After a successful FakeIP pool update, active TUNs report the new pools and the
manager updates system routes in place: new routes are installed before
obsolete ones are deleted, without rebuilding the device or running
post-up/post-down commands. Failed additions roll back and keep the previous
routes; failed deletions are retried. The FakeDNS settings and successfully
updated pools remain applied if route synchronization fails; the error is shown
in the System Network status.

Routes are managed for kernel `tun://` devices on Linux, macOS and Windows.
On Android the pools are passed to the VPN interface (`fakeIpRoutes`).
Externally supplied `fd://` devices keep host-managed routing.
