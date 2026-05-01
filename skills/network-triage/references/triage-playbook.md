# Triage Playbook

Use this when the user starts with a symptom and no capture.

## Minimum Questions

- What is the client?
- What is the target IP/name and port?
- What is the symptom: timeout, reset, refused, HTTP error, TLS error,
  slow response, DNS failure?
- Where can the user run tcpdump: client, server, firewall, load
  balancer, mirror/span?
- Is HTTPS payload detail needed?

## Capture Handoff

The answer should include:

1. Command to run.
2. How to reproduce while it runs.
3. Where the file should be copied.
4. Exact path to ask the MCP server to analyze.

## If The First Capture Is Insufficient

Ask for the missing vantage point rather than guessing. Common misses:

- capture only on client but failure is serverside
- encrypted HTTPS without keylog
- wrong interface
- capture started after connection setup
- no reverse traffic
