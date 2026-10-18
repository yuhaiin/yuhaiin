# Congestion control algorithms

BBR and Brutal implementations are adapted from the MIT-licensed Hysteria 2 core (upstream files under `core/internal/congestion`). The package paths have been changed for use inside yuhaiin. The original MIT license is included as `LICENSE.upstream`.

They are included separately from the HY2 protocol state machine because both are QUIC congestion controllers, not part of the Hysteria wire format.
