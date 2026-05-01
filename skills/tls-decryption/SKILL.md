---
name: tls-decryption
description: Use when the user asks to decrypt TLS/SSL/HTTPS traffic, mentions SSLKEYLOGFILE, keylog, premaster secret, session secrets, Wireshark decryption, encrypted packets, SNI/cert/cipher visibility, or asks why TLS payloads are not visible in a pcap. Guides safe keylog capture and cute-pcap-mcp tls_keylog_path usage.
---

# TLS Decryption

Use this skill to explain and attempt TLS decryption. Be direct:
modern TLS cannot be decrypted from packet bytes alone. A matching
SSLKEYLOGFILE from the client process is the normal path.

For browser/curl keylog workflows, read
`references/keylog-workflows.md`. To summarize a keylog without printing
secret material, run `scripts/keylog_summary.py`.

## What Is Possible

- TLS handshakes, SNI, certificates, versions, and ciphers may be
  visible without decryption.
- HTTP payload inside TLS requires key material.
- TLS 1.3 and TLS 1.2 with ECDHE/DHE are forward-secret. The server
  private key alone will not decrypt old sessions.
- A keylog only helps for sessions whose keys it contains.

## Safe Workflow

1. Put keylogs under the configured `workspace.keylog_dir`.
2. Treat keylogs as secrets.
3. Capture traffic and generate the keylog at the same time.
4. Analyze with `tls_keylog_path`.
5. Use `display_filter: "tls || http || http2"` so decrypted rows can
   surface in packet summaries.

If the user starts with a normal encrypted pcap, first analyze it to
show handshake/SNI/cert/cipher evidence. If they need inside-HTTPS
evidence, explain that they need to reproduce the traffic while key
logging is enabled, then provide the commands.

## curl Keylog Example

Homebrew curl on macOS normally uses OpenSSL and honors
`SSLKEYLOGFILE`:

```sh
KEYLOG="$HOME/mcp-work/keylogs/curl.keys"
: > "$KEYLOG"
chmod 600 "$KEYLOG"

SSLKEYLOGFILE="$KEYLOG" /opt/homebrew/opt/curl/bin/curl \
  --http1.1 \
  --resolve example.test:443:192.0.2.10 \
  https://example.test/ -o /dev/null
```

Capture at the same time from another terminal or host:

```sh
sudo timeout 60 tcpdump -s0 -nni any -w /tmp/tls-test.pcap \
  'tcp and host 192.0.2.10 and port 443'
```

Then copy files into the MCP workspace:

```sh
cp /tmp/tls-test.pcap "$HOME/mcp-work/pcaps/tls-test.pcap"
cp "$KEYLOG" "$HOME/mcp-work/keylogs/curl.keys"
```

## MCP Analysis Prompt

```text
Analyze /work/pcaps/tls-test.pcap with tls_keylog_path=/work/keylogs/curl.keys.
Use display_filter="tls || http || http2" and max_packet_rows=100.
Tell me whether decrypted HTTP/HTTP2 packet rows are visible. Cite frame numbers.
```

Use host paths instead of `/work/...` for native runs.

## Status Interpretation

- `not_requested`: no keylog was supplied.
- `unavailable`: keylog support is not configured or the path is
  outside the keylog allowlist.
- `keylog_missing`: the file does not exist.
- `attempted`: the keylog was passed to tshark/Zeek without subprocess
  errors. This does not prove decryption worked.
- `failed`: tshark or Zeek errored while the keylog was applied.
- `succeeded`: reserved for a future implementation with a reliable
  decrypted-evidence signal.

Until `succeeded` is implemented, look for decrypted `HTTP` or `HTTP2`
packet rows, or Zeek HTTP records, as the actual proof.
