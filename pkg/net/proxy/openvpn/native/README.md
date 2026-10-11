OpenVPN's wire codec, reliability, TLS static-key wrappers, key-method-2 PRF
and initial AES-256-GCM implementation are adapted from xen0bit/veepin,
commit 810e017596c0b5b55bc0da563929bde13a6b201d (MIT).
See THIRD_PARTY_LICENSE. Original modules: internal/openvpn/{wire,reliable,
control,keys,data,tlswrap}. Their protocol regression tests are retained.

Yuhaiin supplies the session orchestration, transport, certificate policy,
configuration validation, gVisor adapter, and node lifecycle. This directory
uses no host TUN, shell commands, scripts, or external credential files.
