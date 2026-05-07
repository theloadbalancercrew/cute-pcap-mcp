#!/usr/bin/env sh
set -eu
python3 "$(dirname "$0")/../generate_fixture.py" asymmetric_return_path_observed
