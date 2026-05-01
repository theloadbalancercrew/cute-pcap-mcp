---
name: pcap-report-writer
description: Use only when the user asks for a report, write-up, customer summary, incident summary, RCA draft, handoff, or findings summary AND the request also mentions packet capture evidence such as pcap, pcapng, trace, tcpdump, Wireshark, tshark, Zeek, packets, frames, or capture artifacts. Do not trigger for generic report-writing without packet evidence.
---

# PCAP Report Writer

Use this skill to turn packet evidence into a clear human report. This
skill should not run for generic writing tasks; it is only for reports
grounded in capture evidence.

For a fuller customer/incident report structure, read
`references/report-template.md`.

## Before Writing

If no analysis has been run yet, use `pcap-analysis` first. The report
must be based on tool output, not memory or assumptions.

Gather:

- capture path and artifact metadata
- key findings and severity
- relevant frames, Zeek UIDs, endpoints, ports, and timestamps
- analyzer errors or truncation warnings
- user-supplied context, marked as context rather than packet proof

## Report Template

```markdown
# Packet Capture Analysis

## Summary

One short paragraph with the most defensible conclusion.

## Evidence

- Frame/UID/time: what happened and why it matters.
- Frame/UID/time: second supporting fact.

## What The Capture Shows

Concrete claims grounded in packet evidence.

## What The Capture Does Not Show

Missing vantage points, encrypted payloads, truncation, absent logs, or
other limits.

## Recommended Next Steps

Specific capture, filter, config check, or reproduction step.
```

## Writing Rules

- Separate user context from packet evidence.
- Say "consistent with" when evidence is suggestive but not conclusive.
- Include uncertainty plainly.
- Keep it concise unless the user asks for a full RCA.
- Do not paste raw secrets, decrypted bodies, cookies, authorization
  headers, or large raw analyzer output.
