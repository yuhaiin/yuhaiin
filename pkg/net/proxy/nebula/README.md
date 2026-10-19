# Nebula userspace outbound

yuhaiin embeds the official Nebula engine and delivers decrypted IP packets to the lightweight TCP/IP stack. No external nebula executable, system TUN device, root privilege, or host routing changes are required.

Add a node protocol named **nebula**. Paste your existing standard Nebula client YAML into the **config_yaml** field. Use embedded certificate, CA and private key contents rather than filesystem paths for portability. For example:

~~~yaml
pki:
  ca: |
    <your Nebula CA PEM>
  cert: |
    <your Nebula host certificate PEM>
  key: |
    <your Nebula host private key PEM>
static_host_map:
  "10.42.0.1": ["198.51.100.10:4242"]
lighthouse:
  am_lighthouse: false
  hosts: ["10.42.0.1"]
listen:
  host: 0.0.0.0
  port: 0
tun:
  mtu: 1300
firewall:
  outbound:
    - port: any
      proto: any
      host: any
  inbound: []
~~~

Replace all placeholders with real certificates, addresses, and firewall policies. The local overlay addresses are read from the Nebula node certificate.

## Restrictions

- Nebula's native UDP underlay opens sockets directly. **Chained upstream proxies are rejected** instead of silently bypassed. Place Nebula first in the protocol chain.
- No custom tun.routes / tun.unsafe_routes or system route-table operations. Traffic to overlay peers is supported, but Nebula unsafe-route gateways are not.
- No Nebula built-in SSH listener, Lighthouse DNS service, external statistics listeners or multiqueue packet processing.
- No automatic PKI enrollment; provision certificates using nebula-cert.
- This PR includes configuration validation tests but has **not** established live Lighthouse / remote-peer interoperability yet.

Project: https://github.com/slackhq/nebula
