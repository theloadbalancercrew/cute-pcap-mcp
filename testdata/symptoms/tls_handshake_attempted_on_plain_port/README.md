Positive fixture: a TCP flow to port 80 completes the handshake, sends a syntactically valid TLS Client Hello, and receives a TCP RST instead of a TLS Server Hello.

Negative fixture: the same flow receives a TLS Server Hello, so the symptom must not fire.
