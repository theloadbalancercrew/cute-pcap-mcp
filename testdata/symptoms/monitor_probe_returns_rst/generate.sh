#!/usr/bin/env sh
set -eu
python3 "$(dirname "$0")/../generate_fixture.py" monitor_probe_returns_rst
