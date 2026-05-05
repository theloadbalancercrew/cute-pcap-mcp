# Roadmap

This document describes the product boundary for `cute-pcap-mcp` and
the likely direction after the initial release. It avoids issue-tracker
history on purpose; the durable contract lives in the tool and server
contract docs.

## Product Boundary

`cute-pcap-mcp` owns local packet-capture evidence normalization. It
accepts operator-provided PCAP/PCAPNG files from configured workspace
paths, runs bounded local analysis tools, and returns structured
evidence plus safe artifact references.

It does not capture traffic, copy files from devices, authenticate to
network equipment, or call other MCP servers. Humans, scripts, or
adjacent MCP servers create capture files and place them in the shared
workspace, typically `~/mcp-work/pcaps` on a host install or
`/work/pcaps` inside the Docker runtime.

The local artifact handoff is intentionally small:

- path
- size
- SHA-256
- optional producer/source context

The LLM receives references and bounded analysis, never raw PCAP bytes.

## Initial Release

The initial release focuses on a reliable local evidence loop:

- stable stdio MCP tools for validation, analysis, filtering, connection
  explanation, and analyzer status
- bounded `capinfos`, `tshark`, Zeek, ASCII, and pure-Go summaries
- redaction of common credential and token patterns
- typed error and finding tokens
- JSON and Markdown analysis artifacts under the configured output
  directory
- Docker runtime with packet-analysis tooling included
- native macOS/Linux/Windows release binaries
- Claude/Codex server-local skills for packet analysis and TLS keylog
  workflow, with capture planning, triage, load-balancer path analysis,
  and report writing owned by `lbc-mcp-workspace`

The design preference is **truth over closure**: unavailable analyzers,
invalid filters, missing captures, unsupported selectors, and ambiguous
TLS decryption evidence should remain explicit typed outcomes instead
of being smoothed into prose.

## Non-Goals

These are deliberately outside this repo:

- raw PCAP upload to an LLM
- arbitrary shell execution
- built-in packet capture on remote systems
- SCP/SFTP/SSH/device API clients
- direct MCP-to-MCP calls from this server
- web daemon, metrics endpoint, GUI, approval workflow, or control
  plane behavior
- long-term artifact storage or cloud object storage
- generic multi-domain plugin framework
- returning decrypted HTTP bodies or secrets by default

## Near-Term Directions

Likely follow-up work:

- GitHub Actions release pipeline for binaries, skill ZIPs, Docker image
  build, and smoke checks
- GitHub Container Registry publishing once package visibility and
  auth are settled
- better decrypted-evidence detection for TLS keylog workflows
- richer Zeek/tshark error reporting and debug logs for analyzer
  failures
- more synthetic fixture coverage for common enterprise captures:
  IPv6, multicast, DHCP, DNS, RDP, proxy paths, and load-balancer
  clientside/serverside traces
- skill evaluation and trigger tuning as real prompts accumulate

## Compatibility Principles

- Stable tool names are preferred over prompt steering.
- Structured fields are preferred over parsing analyzer prose.
- New fields should be additive where possible.
- Breaking schema changes require a major version bump and a migration
  note.
- Compatibility aliases can remain for one release window, but new
  clients should use the stable `pcap_*` tool names.
