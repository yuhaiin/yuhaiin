# Android VpnService fixture

This isolated debug APK tests the actual framework VPN FD as an ordinary app
UID. It does not use `adb root`, open `/dev/net/tun`, modify yuhaiin-android,
or intercept other apps: only this fixture and `198.18.0.0/24` are routed.
The foreground service closes its VPN and native child after each run.

The fixture passes the `ParcelFileDescriptor` to a native Go child using
`LocalSocket`/SCM_RIGHTS. It records TUN flags, SELinux context, and the result
of `TUNSETOFFLOAD(0)` (a zero-flags capability probe, not enabling offload).
The native core uses CUBIC and the production device opener/packet adapter,
as does the Linux fixture. A plain framework fd does not negotiate offloads.

Java and Go run in separate processes. Java sends three upload/download pairs,
256 MiB each, after one 16 MiB warmup in each direction. Upload is verified by
Go, download by Java; both require a completion marker. The workload uses a
repeated nonzero pattern. There is no SOCKS backend, encryption, loss emulation,
or comparison with hev on Android. This is a platform/integrity probe plus a
local throughput diagnostic, not a phone throughput or steady-state claim.
Fast samples can still be shorter than a second; Java/JIT, virtualization,
emulator CPU allocation and host activity affect them.
The generator waits for the VPN `Network` whose link has `198.18.0.1` and uses
its socket factory explicitly; otherwise a startup race can select the underlay.

Build from the repository root (Linux SDK/NDK host, x86_64 AVD):

```sh
python3 scripts/benchmarks/build_android_probe.py \
  --sdk /path/to/Android/Sdk --ndk /path/to/android-ndk \
  --output /tmp/stackprobe.apk
adb -s emulator-5560 install /tmp/stackprobe.apk
adb -s emulator-5560 shell am start \
  -n dev.yuhaiin.stackprobe/.ProbeActivity --ei mtu 1500
```

Accept the Android VPN connection dialog for this fixture. Wait until the
service finishes and `files/result-1500.json` exists; it must contain `ok:true`.
Use the same APK to run `--ei mtu 9000` after the first service has stopped.
The APK uses target SDK 33 and extracts the native PIE executable from its
`lib/x86_64/libstackprobe.so` entry, so it can execute without copying code
into a writable app-data location. A newly built APK has a fresh debug signing
key; uninstall only `dev.yuhaiin.stackprobe` before reinstalling such a build.

```sh
adb -s emulator-5560 shell run-as dev.yuhaiin.stackprobe cat files/result-1500.json
adb -s emulator-5560 shell run-as dev.yuhaiin.stackprobe cat files/native-1500.log
adb -s emulator-5560 uninstall dev.yuhaiin.stackprobe
```

For an isolated AVD run, use `-read-only -no-snapshot -no-window -no-audio`
with a free emulator port. Shut down only the emulator created for this test.
API 34/4 KiB and API 35/16 KiB results are recorded separately in the report.
This does not establish arm64 performance or compatibility with every vendor
kernel. Building for arm64 requires a matching APK ABI directory and NDK target;
the current builder intentionally supports only the tested x86_64 fixture.
