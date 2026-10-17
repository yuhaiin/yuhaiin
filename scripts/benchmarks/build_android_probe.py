#!/usr/bin/env python3
"""Build the isolated x86_64 emulator VPN fixture with SDK/NDK tools, no Gradle.

The generated APK uses a fresh temporary debug key. Remove an older installation
of dev.yuhaiin.stackprobe before installing a newly signed build.
"""

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--sdk", type=Path, required=True)
    p.add_argument("--ndk", type=Path, required=True)
    p.add_argument("--build-tools", default="36.1.0")
    p.add_argument("--platform", default="android-34")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    repo = Path(__file__).resolve().parents[2]
    source = Path(__file__).resolve().parent / "android-vpn-probe"
    tools = a.sdk.resolve() / "build-tools" / a.build_tools
    android = a.sdk.resolve() / "platforms" / a.platform / "android.jar"
    a.output = a.output.resolve()
    a.output.parent.mkdir(parents=True, exist_ok=True)

    def run(*argv, **kwargs):
        subprocess.run([str(x) for x in argv], check=True, **kwargs)

    with tempfile.TemporaryDirectory(prefix="android-stackprobe-") as tmp:
        tmp = Path(tmp)
        classes, dex = tmp / "classes", tmp / "dex"
        classes.mkdir()
        dex.mkdir()
        binary = tmp / "libstackprobe.so"
        compiler = a.ndk.resolve() / "toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android28-clang"
        run("go", "build", "-o", binary, "./scripts/benchmarks/stackprobe", cwd=repo,
            env=dict(os.environ, GOOS="android", GOARCH="amd64", CGO_ENABLED="1", CC=str(compiler)))
        run("javac", "-source", "8", "-target", "8", "-bootclasspath", android,
            "-d", classes, source / "ProbeActivity.java")
        run(tools / "d8", "--lib", android, "--min-api", "28", "--output", dex,
            *sorted(classes.rglob("*.class")))
        unsigned = tmp / "unsigned.apk"
        run(tools / "aapt", "package", "-f", "-M", source / "AndroidManifest.xml",
            "-I", android, "-F", unsigned)
        with zipfile.ZipFile(unsigned, "a", compression=zipfile.ZIP_DEFLATED) as apk:
            apk.write(dex / "classes.dex", "classes.dex")
            apk.write(binary, "lib/x86_64/libstackprobe.so")
        aligned = tmp / "aligned.apk"
        run(tools / "zipalign", "-f", "4", unsigned, aligned)
        # This is a disposable, public-password debug signing key, not a user key.
        key = tmp / "debug.keystore"
        run("keytool", "-genkeypair", "-keystore", key, "-alias", "androiddebugkey",
            "-storepass", "android", "-keypass", "android", "-keyalg", "RSA",
            "-validity", "30", "-dname", "CN=Isolated Stack Probe", "-noprompt")
        run(tools / "apksigner", "sign", "--ks", key, "--ks-key-alias", "androiddebugkey",
            "--ks-pass", "pass:android", "--key-pass", "pass:android", "--out", a.output, aligned)
        run(tools / "apksigner", "verify", a.output)
    print(a.output)


if __name__ == "__main__":
    main()
