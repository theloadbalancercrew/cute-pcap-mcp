# AGENTS

This repo is for one product: `cute-pcap-mcp`, a typed MCP server for
bounded, redacted packet-capture analysis.

## Hard Rules

- PCAP semantics live here: allowlisted artifact references, analyzer
  availability, bounded tshark/Zeek/capinfos evidence, redaction, typed
  errors, and public PCAP MCP docs.
- Capture acquisition, approval flows, ticketing, notifications, live
  network changes, and product/demo orchestration do not live here.
- Do not return raw packet payload bytes, decrypted bodies, key material,
  secrets, or arbitrary raw analyzer dumps through MCP output.
- Do not create a generic network automation framework in this repo.
- Do not compensate for missing typed tools with prompt steering,
  keyword routing, scenario classifiers, or prose parsing.
- Do not turn a full product/demo request into a lab-shaped MCP command.
  Product workflows may be described in issues, but this repo implements
  only reusable typed PCAP-analysis capabilities. Cross-tool
  orchestration, demo sequencing, capture planning, and
  environment-specific glue belong in the host, skill/demo, or CuteOS
  layer.

## Review Gate

Every MR or issue handoff must answer:

1. What reusable PCAP-analysis capability does this add?
2. Why does it belong in `cute-pcap-mcp` instead of a host/client,
   capture producer, demo repo, or CuteOS?
3. If this came from a product/demo issue, which part is typed packet
   evidence here, and which part stays host/model orchestration?
4. How did we prove it did not change existing MCP behavior
   accidentally?

Kick back work that hides uncertainty, leaks raw/sensitive evidence,
adds capture/acquisition/control-plane behavior, or encodes a lab demo
as a single MCP server command when existing typed tools plus host/model
orchestration should do the sequencing.
