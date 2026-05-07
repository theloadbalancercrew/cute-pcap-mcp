#!/usr/bin/env sh
set -eu
python3 "$(dirname "$0")/../generate_fixture.py" tcp_rst_after_synack_no_app_data
