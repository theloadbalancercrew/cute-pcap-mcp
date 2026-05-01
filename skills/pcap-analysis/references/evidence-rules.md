# Evidence Rules

Use this reference when a capture has conflicting clues or the user asks
for conclusions.

## Strong Evidence

- TCP flags and packet order for handshake, FIN, and RST claims.
- Zeek `conn.log` state plus packet rows for flow lifecycle.
- DNS response code and answer records for resolution claims.
- HTTP status/method/host/URI when visible in Zeek or decrypted packet
  rows.
- TLS SNI/version/cipher/cert metadata for handshake claims.

## Weak Evidence

- ASCII strings in raw capture bytes. Useful hints, not proof of an
  application transaction.
- Filenames and capture labels. Never use them as packet evidence.
- Topology assumptions supplied by the user. Treat as context until
  packets show the path.

## Language

- Use "shows" for packet-proven claims.
- Use "consistent with" for likely but not proven interpretations.
- Use "does not show" for missing vantage point, missing reverse path,
  encryption without keylog, or output truncation.
