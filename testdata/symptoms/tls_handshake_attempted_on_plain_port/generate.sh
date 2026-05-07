#!/usr/bin/env sh
set -eu
python3 "$(dirname "$0")/../generate_fixture.py" tls_handshake_attempted_on_plain_port
