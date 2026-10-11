#!/usr/bin/env python3
"""Move only used MIT-licensed veepin client engines into yuhaiin pkg/net/proxy.

One-time migration of the reviewed pinned source at 810e017596c0b5b55bc0da563929bde13a6b201d.
No runtime, startup or build-time git download and no vendored Go module.
"""
from __future__ import annotations
from collections import deque
import pathlib
import re
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "third_party/veepin"
TARGET = ROOT / "pkg/net/proxy/enterprisevpn/internal/engine"
OLD_IMPORT = "github.com/xen0bit/veepin"
NEW_IMPORT = "github.com/Asutorufa/yuhaiin/pkg/net/proxy/enterprisevpn/internal/engine"
PIN = "810e017596c0b5b55bc0da563929bde13a6b201d"

if not SOURCE.is_dir() or TARGET.exists():
    raise SystemExit("migration requires existing third_party/veepin and absent engine destination")

# Import-closure pruning: begin at the four real client facade packages, and
# recursively include only in-repository packages they import. Never ship the
# demo CLI, standalone servers, host-network setup, or other VPN protocols.
roots = ("client", "dataplane", "ikev2", "anyconnect", "sstp", "fortinet")
packages = deque(roots)
files: dict[str, list[tuple[pathlib.Path, str]]] = {}
scan = re.compile(r'(?m)^\s*(?:\w+\s+)?"(github\.com/xen0bit/veepin(?:/[^"]+)?)"')
def remove_pq(src: str) -> str:
    src = re.sub(r'(?m)^\s*"github.com/xen0bit/veepin/internal/pqpolicy"\n', "", src)
    src = re.sub(r'(?m)^.*(?:PostQuantumOnly: pqpolicy.Requested\(opts\)|cfg.PostQuantumOnly = pqpolicy.Requested\(opts\)).*\n', "", src)
    src = src.replace('pqpolicy.Requested(opts)', 'false')
    for pattern in ('if cfg.PostQuantumOnly {', 'if opts[OptPQ] == "true" && !false {'):
        while pattern in src:
            start=src.index(pattern)
            brace=src.index("{",start)
            depth=0
            end=None
            for index in range(brace,len(src)):
                if src[index]=="{":depth+=1
                if src[index]=="}":
                    depth-=1
                    if depth==0:
                        end=index+1
                        break
            if end is None: raise RuntimeError("unclosed PQ conditional")
            src=src[:start]+src[end:]
    # No optional PQ negotiations are enabled from these outbounds.
    src=src.replace('cfg.PostQuantum || cfg.PostQuantumOnly','false')
    src=src.replace('cfg.PostQuantumOnly,','false,')
    return src

while packages:
    package=packages.popleft()
    if package in files or package.endswith("/pq") or package=="internal/pqpolicy":
        continue
    source_dir=SOURCE/package
    if not source_dir.is_dir():
        raise RuntimeError(f"missing imported package: {package}")
    members=[]
    for f in sorted(source_dir.glob("*.go")):
        name=f.name
        if name.endswith("_test.go") or name=="server.go" or name.startswith("server_") or name.endswith("_server.go"):
            continue
        if package=="dataplane" and (name.startswith("client_") or name in {"routes.go","client_net.go"}):
            continue
        src=f.read_text()
        if package in ("ikev2","anyconnect","sstp","fortinet"):
            src=remove_pq(src)
        members.append((f,src))
        for imp in scan.findall(src):
            dep=imp.removeprefix(OLD_IMPORT).lstrip("/")
            if dep and dep not in files and dep not in packages and dep!="internal/pqpolicy" and not dep.endswith("/pq"):
                packages.append(dep)
    if not members:
        raise RuntimeError(f"no client implementation for {package}")
    files[package]=members

# All affected packages are under net/proxy. Keep the MIT license and upstream
# attribution in this subtree and remove the nested module boundary entirely.
for package,members in files.items():
    d=TARGET/package
    d.mkdir(parents=True,exist_ok=True)
    for old,src in members:
        (d/old.name).write_text(src.replace(OLD_IMPORT,NEW_IMPORT))
shutil.copy2(SOURCE/"LICENSE",TARGET/"LICENSE")
(TARGET/"UPSTREAM.md").write_text(
    "# Enterprise VPN protocol engines\n\n"
    "Selected client code adapted from [veepin](https://github.com/xen0bit/veepin)\n"
    f"at commit `{PIN}`. Copyright (c) 2026 Remy, MIT (see LICENSE).\n\n"
    "Only the import closure of the IKEv2, AnyConnect, SSTP and Fortinet clients\n"
    "is kept. No extra Go module, external subprocess, OS route setup, unused\n"
    "VPN variants or PQ-specific facade packages are included. Custom changes\n"
    "inject yuhaiin's packet bridge and outbound dialers.\n"
)

outer=ROOT/"pkg/net/proxy/enterprisevpn/client.go"
outer.write_text(outer.read_text().replace(OLD_IMPORT,NEW_IMPORT))
mod=ROOT/"go.mod"
m=mod.read_text()
m=m.replace("\tgithub.com/xen0bit/veepin => ./third_party/veepin\n","")
m=m.replace("\tgithub.com/xen0bit/veepin v0.0.0\n","")
mod.write_text(m)

# Root code no longer depends on a third-party module, and no upstream source
# remains in third_party. The migration script is removed after it is run.
shutil.rmtree(SOURCE)
old_script=ROOT/"scripts/vendor_veepin_for_yuhaiin.py"
old_script.unlink(missing_ok=True)
subprocess.run(["gofmt","-w",*[str(p) for p in TARGET.rglob("*.go")],str(outer)],check=True)
print(f"Moved {sum(map(len,files.values()))} source files in {len(files)} needed Go packages to {TARGET.relative_to(ROOT)}")
print("Packages:",", ".join(sorted(files)))
