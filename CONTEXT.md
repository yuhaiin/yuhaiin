# Traffic routing

## Language

**Node**: A named connection configuration defining how traffic reaches an
endpoint, including its protocol chain.

**Selector**: A reusable choice of node used by multiple routing rules.
_Avoid_: Tag, mirror

**Rule**: A condition expression and an action applied to matching traffic.

**List**: A collection of host or process matching data. A list is either shared
or belongs exclusively to one rule.

**Inbound**: A configured way for application or device traffic to enter yuhaiin.

**Resolver**: A configured upstream service used to resolve domain names.
