---
name: capture-planning
description: Use when the user asks what tcpdump/Wireshark/tshark command to run, how to capture traffic, how to capture a VIP, client, server, port, DNS, TLS, resets, intermittent failures, full path, ring buffers, or how to generate traffic for a trace. Produces practical capture and traffic-generation commands.
---

# Capture Planning

Use this skill to produce safe, useful capture commands. Favor small,
targeted captures with enough packet detail to answer the question.
The agent should turn this into a user-facing how-to: where to run the
capture, how long to run it, where to copy it, and what prompt to send
next.

For additional OS/vantage-point recipes, read
`references/capture-recipes.md`. If a deterministic Linux/macOS tcpdump
command is useful, run `scripts/render_tcpdump_plan.py`.

## Capture Defaults

Use these defaults unless the user needs something else:

- `-s0`: full packet snaplen
- `-n`: no name resolution
- bounded with `-c`, `timeout`, or ring files
- write to pcap/pcapng, not terminal
- include both endpoints when known
- capture clientside and serverside when a proxy/load balancer is in
  the path

## Linux/macOS tcpdump

Single endpoint and port:

```sh
sudo timeout 60 tcpdump -s0 -nni any -w /tmp/trace.pcap \
  'host 192.0.2.10 and tcp port 443'
```

Client to server:

```sh
sudo timeout 60 tcpdump -s0 -nni any -w /tmp/trace.pcap \
  'tcp and host 192.0.2.10 and host 198.51.100.20 and port 443'
```

Resets:

```sh
sudo timeout 60 tcpdump -s0 -nni any -w /tmp/resets.pcap \
  'tcp[tcpflags] & tcp-rst != 0'
```

Ring buffer:

```sh
sudo tcpdump -s0 -nni any -G 60 -W 10 -w 'trace-%Y%m%d%H%M%S.pcap' \
  'host 192.0.2.10 and tcp port 443'
```

## Load-Balancer Appliance Capture

On appliances, choose the interface or capture plane that can see the
traffic path you need. Some platforms expose a special all-traffic
capture plane:

```sh
tcpdump -s0 -nni 0.0 -w /var/tmp/trace.pcap \
  'host 192.0.2.10 and tcp port 443'
```

VIP plus pool member:

```sh
tcpdump -s0 -nni 0.0 -w /var/tmp/fullpath.pcap \
  'tcp and (host 192.0.2.10 or host 198.51.100.20)'
```

If direct `-w file` hits permissions on a lab device, write stdout into
the file:

```sh
tcpdump -s0 -nni 0.0 -w - 'tcp and host 192.0.2.10' > /var/tmp/trace.pcap
```

## Traffic Generators

HTTP loop:

```sh
while true; do
  curl -sS --connect-timeout 3 --max-time 10 http://TARGET/ -o /dev/null \
    -w 'http=%{http_code} connect=%{time_connect} total=%{time_total}\n'
  sleep 0.5
done
```

HTTPS loop with SNI override:

```sh
while true; do
  curl -sk --http1.1 --resolve example.test:443:192.0.2.10 \
    https://example.test/ -o /dev/null \
    -w 'http=%{http_code} total=%{time_total}\n'
  sleep 0.5
done
```

DNS loop:

```sh
while true; do
  dig +time=2 +tries=1 example.com @192.0.2.53
  sleep 0.5
done
```

## Handoff

Always include a handoff. Tell the user where to save the pcap so
`cute-pcap-mcp` can read it, then suggest the first analysis prompt once
the file exists.

Docker runtime:

```text
Copy the pcap to ~/mcp-work/pcaps/trace.pcap on the machine running the
MCP client. Then ask me to analyze /work/pcaps/trace.pcap.
```

Native runtime:

```text
Copy the pcap to ~/mcp-work/pcaps/trace.pcap on the machine running the
MCP server. Then ask me to analyze ~/mcp-work/pcaps/trace.pcap.
```

Suggested follow-up prompt:

```text
Use cute-pcap-mcp to validate and analyze /work/pcaps/trace.pcap with
max_packet_rows=50 and write_artifacts=true. Tell me what the packet
evidence proves and what it does not prove.
```

Use the host path instead of `/work/...` for native runs.
