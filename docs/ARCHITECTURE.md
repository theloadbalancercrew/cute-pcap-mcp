# Architecture

`cute-pcap-mcp` owns packet evidence only.

It does not capture from network devices by itself in v0. It accepts
operator-provided pcap/pcapng files from allowlisted directories and
returns bounded summaries and selected printable ASCII evidence.

## Boundary

- External producers own capture acquisition. A producer can be a human,
  script, device-specific MCP server, CI fixture, or any other local
  process that creates a pcap/pcapng file.
- `cute-pcap-mcp` owns packet file inspection and packet-evidence
  normalization.
- The MCP client / LLM passes local artifact references to this server.

This server does not capture from network devices, copy files from
devices, or call other MCP servers. It only receives an allowlisted local
path and optional artifact metadata, then analyzes the file already on
disk.

## Privacy

Raw packet payloads are sensitive. Tool outputs must prefer structured
metadata and bounded summaries:

- packet counts
- durations
- chart-ready timing/count summaries derived from bounded evidence
- protocol hierarchy
- conversation summaries
- derived Zeek summaries for connection, DNS, HTTP, TLS, notice, and
  weird-event evidence
- TCP flag observations
- reset / handshake evidence
- TLS handshake presence
- HTTP status class, not body bytes

The `analyze_pcap` tool can also return printable ASCII strings found in
the capture file. That output is intentionally bounded by server config
and per-call limits, and common credential/token patterns are redacted by
default. Operators should still treat ASCII results as sensitive packet
evidence.

Large captures should be constrained with per-call limits and, when
useful, a tshark `display_filter` for packet-row output. Analyzer
failures are reported as partial-result errors so other available
evidence can still be returned.

Raw pcap paths and hashes are private artifact metadata.
