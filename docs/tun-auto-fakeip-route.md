# Automatic FakeIP routes for TUN

The TUN protocol's `autoFakeIpRoute` boolean adds the active FakeIP IPv4 and
IPv6 prefixes to the routes installed for that TUN. New TUNs created in the
Web UI enable this option. Missing fields in existing or migrated configurations
remain disabled; API clients opt in explicitly.

Only address families configured on the TUN are added. IPv6 also requires the
global IPv6 setting. The option is independent of the global FakeDNS switch,
because inbound DNS hijacking or forced FakeIP can still use those pools.

Route merging masks network addresses, removes duplicates and contained
prefixes, and keeps adjacent prefixes separate. CIDR, individual IP addresses,
and `file:` entries retain their existing parsing behavior. Automatically
added prefixes are runtime state: the saved `routes` and `excludes` lists are
not rewritten, and the existing handling of `excludes` is unchanged.

After a successful FakeIP pool update, active TUNs update their system routes
in place. New routes are installed before obsolete routes are deleted, without
rebuilding the device or running post-up/post-down commands. Failed additions
roll back newly installed routes and preserve previous routes. Failed deletions
remain tracked for retry. Existing matching system routes can be borrowed but
are never deleted. Linux policy rules shared by TUNs remain until their last
user closes.

Synchronization errors are returned to the API and logged. The FakeDNS settings
and successfully updated pools remain applied if system route synchronization
fails. Saving the same FakeDNS settings or the same TUN again retries route
synchronization. Failed cleanup of removed TUNs is retried on subsequent inbound
operations, range synchronization, or another runtime close.

System routing is supported for kernel-managed `tun://` devices on Linux,
macOS, and Windows. Android and externally supplied `fd://` devices continue
to use host-managed routing.

## Validation

The platform-independent tests inject route operations to verify ordering,
rollback, retries, route ownership, shared policy rule lifetime, and concurrent
updates and close. For real Linux route operations, run the opt-in test in an
environment permitted to create network namespaces:

```sh
YUHAIIN_TEST_TUN_ROUTES=1 GOEXPERIMENT=jsonv2 go test ./pkg/net/netlink -run '^TestLinuxRouteLifecycleInNamespace$' -v
```

The integration test creates an isolated network namespace before adding any
interfaces or routes. It skips if namespace creation is unavailable.
