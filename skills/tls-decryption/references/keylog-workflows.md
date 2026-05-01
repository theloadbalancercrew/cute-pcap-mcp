# Keylog Workflows

Use this reference when HTTPS payloads matter.

## Browser

Start the browser with `SSLKEYLOGFILE` set before reproducing. The
exact launch command is OS/browser-specific; keep the keylog under
`mcp-work/keylogs`.

## curl

Homebrew curl on macOS normally honors `SSLKEYLOGFILE`:

```sh
KEYLOG="$HOME/mcp-work/keylogs/curl.keys"
: > "$KEYLOG"
chmod 600 "$KEYLOG"

SSLKEYLOGFILE="$KEYLOG" /opt/homebrew/opt/curl/bin/curl --http1.1 \
  https://TARGET/ -o /dev/null
```

## Verify Before Claiming Success

Use a display filter that can surface decrypted rows:

```text
tls || http || http2
```

Treat `tls_decryption.status: attempted` as "keylog applied", not
"decryption proved". Proof is visible decrypted HTTP/HTTP2 rows or
Zeek HTTP records.
