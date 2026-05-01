# Capture Recipes

Use this reference when the user wants commands for a specific vantage
point.

## Linux Server

```sh
sudo timeout 60 tcpdump -s0 -nni any -w /tmp/trace.pcap \
  'tcp and host TARGET_IP and port TARGET_PORT'
```

## macOS Client

Find interfaces:

```sh
networksetup -listallhardwareports
```

Capture:

```sh
sudo tcpdump -s0 -nni en0 -w /tmp/trace.pcap \
  'tcp and host TARGET_IP and port TARGET_PORT'
```

## Ring Buffer

```sh
sudo tcpdump -s0 -nni any -G 60 -W 10 -w '/tmp/trace-%Y%m%d%H%M%S.pcap' \
  'host TARGET_IP'
```

## Copy To MCP Workspace

Docker runtime:

```sh
cp /tmp/trace.pcap "$HOME/mcp-work/pcaps/trace.pcap"
```

Analyze path: `/work/pcaps/trace.pcap`.

Native runtime:

```sh
cp /tmp/trace.pcap "$HOME/mcp-work/pcaps/trace.pcap"
```

Analyze path: `$HOME/mcp-work/pcaps/trace.pcap`.
