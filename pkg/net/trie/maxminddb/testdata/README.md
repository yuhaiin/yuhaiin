# Synthetic MMDB fixtures

Generated with `github.com/maxmind/mmdbwriter v1.2.0`, IP version 6, record size
24, reserved networks enabled, database type `Synthetic-Country`, build epoch 1.
These contain only synthetic records; no GeoIP service data is included.

`countries.mmdb` maps `1.0.0.0/24` and `1.0.1.0/24` to `country.iso_code=CN`,
`2001:4860::/48` to `JP`, and `10.0.0.0/8` to the custom value `LAN`.
`2.0.0.0/24` has only `registered_country.iso_code=DE`, which the route matcher
does not use. `updated.mmdb` maps `3.0.0.0/24` to `country.iso_code=US`.
