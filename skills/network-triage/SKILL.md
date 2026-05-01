---
name: network-triage
description: Use when the user reports a network problem such as timeouts, slow app, connection refused, resets, failed login, intermittent reachability, DNS issues, HTTP errors, TLS failures, packet loss, or asks "can you help troubleshoot" a network path. If a pcap/trace/capture is present, guide use of cute-pcap-mcp; if not, guide capture planning and minimal questions.
---

# Network Triage

Use this skill before jumping into packet details. The goal is to turn a
vague symptom into the smallest useful evidence request, then use
`cute-pcap-mcp` when a capture exists.

For symptom-first intake and "what capture do we need?" guidance, read
`references/triage-playbook.md`.

## Triage Intake

Ask only what is needed next:

- What fails: timeout, reset, refused, HTTP error, TLS error, DNS miss,
  slow response, intermittent drop.
- Client IP, server/VIP IP, ports, protocol, and approximate time.
- Whether the user has a pcap/pcapng, Zeek logs, or tshark output.
- Where the capture was taken: client, server, firewall, load balancer,
  SPAN, cloud mirror.
- Whether TLS decryption is needed and whether an SSLKEYLOGFILE exists.

## If A Capture Exists

Use the pcap workflow:

1. `pcap_analyzer_status`
2. `pcap_validate`
3. `pcap_analyze`
4. `pcap_filter` or `pcap_explain_connection` as needed

Ground the answer in packet evidence. Do not assume topology unless the
packets expose it.

## If No Capture Exists

Walk the user through getting one. The skill is not meant to hide the
steps; it should guide the agent to print a tailored how-to for the
user's vantage point.

When the user says something like "my app is slow" and gives no pcap:

1. Ask for the minimum target details if missing: client, server/VIP,
   protocol/port, and where they can run tcpdump.
2. Give a copy-paste capture command for that host.
3. Tell them exactly where to put the finished file for the MCP server:
   - Docker runtime: copy it under the host workspace `mcp-work/pcaps`,
     then refer to it as `/work/pcaps/<file>.pcap`.
   - Native runtime: copy it under the configured host pcap directory,
     commonly `$HOME/mcp-work/pcaps/<file>.pcap`.
4. Give the follow-up prompt they should send after the file exists.

Offer a narrow capture plan:

- full snaplen: `-s0`
- no DNS/service name resolution: `-n`
- bounded duration or packet count
- both directions of the conversation
- clientside and serverside vantage points when a proxy/load balancer is
  in the path

Suggest a simple traffic generator if the issue is reproducible:

```sh
while true; do
  curl -sk --connect-timeout 3 --max-time 10 https://TARGET/ -o /dev/null \
    -w '%{time_starttransfer} %{http_code}\n'
  sleep 0.5
done
```

Example user-facing handoff:

```text
Run this on the Linux server while reproducing the slowness:

sudo timeout 60 tcpdump -s0 -nni any -w /tmp/app-slow.pcap \
  'tcp and host SERVER_IP and port 443'

Then copy /tmp/app-slow.pcap into ~/mcp-work/pcaps/app-slow.pcap.
If you use Docker, ask me to analyze /work/pcaps/app-slow.pcap.
If you use the native server, ask me to analyze
~/mcp-work/pcaps/app-slow.pcap.
```

## If Traffic Is Encrypted

If the first capture only proves TLS exists but the question needs HTTP
headers/status/body timing, guide the user to collect a second capture
with an SSLKEYLOGFILE. Use the `tls-decryption` skill's workflow:

- keylog under `mcp-work/keylogs`
- capture and traffic generation at the same time
- analyze with `tls_keylog_path`
- request `display_filter: "tls || http || http2"`

## Output Shape

Give the user a short plan:

- what evidence we have
- what evidence is missing
- exact next capture or tool call
- what result would confirm or rule out the leading hypothesis
