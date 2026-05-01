---
name: load-balancer-path-debug
description: Use when the user mentions VIP, virtual server, pool member, SNAT, NAT, load balancer, clientside, serverside, reset side, proxy, health checks, or wants to follow a connection through a load-balanced path using packet captures. Guides full-path capture and evidence-based interpretation.
---

# Load-Balancer Path Debug

Use this skill for full-path network debugging through a proxy or load
balancer. Prefer evidence over topology assumptions. The packet capture
may show only one side of the proxy; say that clearly.

For common path patterns and reset-side interpretations, read
`references/path-debug-patterns.md`.

## Mental Model

Track each side separately:

- client -> VIP: clientside flow
- load balancer/SNAT -> pool member: serverside flow
- reset source: originator, responder, proxy, or unknown
- TLS mode: pass-through, offload, re-encrypt, or unknown

Do not claim a specific load-balancer vendor unless packet evidence,
user context, or configured profile context supports it.

## Capture Plan

Ask for:

- VIP IP and port
- client IP if known
- pool member IP and port if known
- SNAT/self IP if known
- timestamp and symptom

For full path, capture both VIP and pool member traffic:

```sh
tcpdump -s0 -nni 0.0 -w /var/tmp/fullpath.pcap \
  'tcp and (host VIP_IP or host POOL_MEMBER_IP)'
```

If the client is known:

```sh
tcpdump -s0 -nni 0.0 -w /var/tmp/fullpath.pcap \
  'tcp and (host CLIENT_IP or host VIP_IP or host POOL_MEMBER_IP)'
```

## MCP Usage

Start generic unless the user explicitly requests a specific analysis
profile:

```text
Analyze the pcap without assuming vendor or topology. Identify clientside and serverside flows only if packet evidence supports them.
```

If using `f5_ltm_tls_debug`, require `virtual_server_ip` for VIP
claims. Treat `virtual_server_port` as narrowing context, not proof of
VIP identity by itself.

## Interpretation Checks

- Is there a complete TCP handshake on clientside?
- Is there a corresponding serverside flow?
- Does the reset come from client, server, or proxy side?
- Is the pool member reached at all?
- Do HTTP status codes show application response vs transport failure?
- Does TLS show SNI/cert/cipher, and is payload decryption needed?
- Are there Zeek weird events indicating malformed, truncated, or odd
  protocol behavior?

## Output Shape

Report:

- path observed
- failure point
- packet evidence
- what is missing
- next capture or config check
