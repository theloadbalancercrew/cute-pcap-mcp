---
name: pcap-analysis
description: Use when the user asks to analyze, inspect, summarize, filter, explain, or reason over packet captures, pcap/pcapng files, tcpdump/Wireshark files, Zeek/tshark output, packet rows, conversations, resets, DNS/HTTP/TLS evidence, or what a trace proves. Guides the agent to use cute-pcap-mcp when available and to avoid claims not grounded in packet evidence.
---

# PCAP Analysis

Use this skill to turn a packet capture into bounded, evidence-grounded
answers. Prefer `cute-pcap-mcp` when it is configured. Do not infer from
filenames, ticket titles, or user hunches unless packet evidence supports
the claim.

For nuanced conclusion language or conflicting evidence, read
`references/evidence-rules.md`.

## First Moves

1. Identify the capture path and any user-provided context: symptom,
   endpoints, ports, timestamps, VIP/pool/member details, keylog path.
2. Run `pcap_analyzer_status` if tool availability is unknown.
3. Run `pcap_validate` before analysis.
4. For packet-shape questions, run `pcap_detect_symptoms` to collect
   vendor-neutral wire symptoms. Treat tokens such as
   `tcp_repeated_short_flows_return_rst`,
   `tcp_rst_after_synack_no_app_data`, `tls_alert_after_client_hello`,
   or missing return traffic as observations at the capture point, not
   as proof of endpoint state or device configuration.
5. Run `pcap_analyze` with bounded rows. Start with:
   - `max_packet_rows: 50`
   - `max_zeek_records_per_log: 100`
   - `write_artifacts: true`
6. If the question is about one flow, use `pcap_explain_connection`
   after identifying a `frame_number`, `zeek_uid`, or five-tuple.
7. If the capture is large or noisy, use `pcap_filter` to create a
   smaller derived pcap before deeper analysis.

## Evidence Rules

- State what the packet evidence proves, what it suggests, and what it
  cannot prove.
- Cite concrete evidence: frame numbers, endpoints, ports, Zeek UIDs,
  timestamps, status codes, reset direction, SNI, DNS names.
- Do not call something "the cause" unless the capture proves causality.
  Use "consistent with" for weaker claims.
- Use PCAP symptom tokens as packet evidence only. A repeated short flow
  ending in RST or no response is the end of the observed TCP
  conversation, not by itself a conclusion about endpoint health or
  configuration.
- If a section is missing, say whether that is due to analyzer
  availability, capture contents, filters, or output limits when known.
- Treat `errors[]`, truncation findings, and `output_limit_reached` as
  part of the evidence, not footnotes.

## Useful Follow-Up Filters

Ask for or apply a display filter when it narrows the evidence:

```text
ip.addr == 192.0.2.10
tcp.port == 443
tcp.flags.reset == 1
dns || http || tls
tcp.stream == 7
```

For TLS with a keylog, ask for `display_filter: "tls || http || http2"`
so decrypted packet rows are visible when available.

## Output Shape

Prefer concise reports:

- Summary: one paragraph.
- Evidence: bullets with packet/Zeek references.
- Gaps: what the capture does not show.
- Next action: one or two specific capture/filter/test suggestions.

Never paste large raw analyzer output unless the user explicitly asks.
