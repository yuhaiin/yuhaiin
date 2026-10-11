# Enterprise VPN protocol engines

Selected client code adapted from [veepin](https://github.com/xen0bit/veepin)
at commit `810e017596c0b5b55bc0da563929bde13a6b201d`. Copyright (c) 2026 Remy, MIT (see LICENSE).

Only the import closure of the IKEv2, AnyConnect, SSTP and Fortinet clients
is kept. No extra Go module, external subprocess, OS route setup, unused
VPN variants or PQ-specific facade packages are included. Custom changes
inject yuhaiin's packet bridge and outbound dialers.
