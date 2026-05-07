Positive fixture: a TCP three-way handshake completes and the responder sends RST before either side exchanges application bytes.

Negative fixture: the client sends an HTTP request before the responder resets, so the zero-application-byte symptom must not fire.
