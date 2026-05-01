# Path Debug Patterns

Use this reference when a capture crosses a proxy/load balancer.

## Common Patterns

- Clientside handshake present, no serverside flow: proxy/policy/pool
  selection issue, or serverside not captured.
- Serverside SYN retransmits: pool member unreachable or wrong route.
- Immediate responder RST after HTTP request: application or proxy
  rejected after request was visible.
- Client RST after response: client/application closed first.
- TLS alert before HTTP: TLS profile, version, cipher, SNI, or cert
  mismatch.

## Required Caveat

If only one side of the proxy is captured, say so. Do not invent the
missing side.
