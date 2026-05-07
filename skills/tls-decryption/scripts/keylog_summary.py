#!/usr/bin/env python3
"""Summarize an SSLKEYLOGFILE without printing secret values."""

import argparse
import collections
import re

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
TRAFFIC_SECRET_RE = re.compile(r"^(?:CLIENT|SERVER)_TRAFFIC_SECRET_[0-9]+$")

KNOWN_LABELS = {
    "CLIENT_RANDOM",
    "CLIENT_EARLY_TRAFFIC_SECRET",
    "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
    "SERVER_HANDSHAKE_TRAFFIC_SECRET",
    "EXPORTER_SECRET",
    "EARLY_EXPORTER_SECRET",
    "RSA",
}


def usable_secret_line(parts: list[str]) -> bool:
    if len(parts) != 3:
        return False
    label, client_random, secret = parts
    if label not in KNOWN_LABELS and not TRAFFIC_SECRET_RE.match(label):
        return False
    if not even_hex(client_random) or not even_hex(secret):
        return False
    if len(secret) < 64:
        return False
    if label != "RSA" and len(client_random) != 64:
        return False
    return True


def even_hex(value: str) -> bool:
    return len(value) > 0 and len(value) % 2 == 0 and bool(HEX_RE.match(value))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("path")
    args = parser.parse_args()

    labels = collections.Counter()
    malformed = 0
    total = 0
    usable = 0

    with open(args.path, "r", encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            total += 1
            parts = line.split()
            if not usable_secret_line(parts):
                malformed += 1
                continue
            labels[parts[0]] += 1
            usable += 1

    print(f"non_comment_lines={total}")
    print(f"usable_secret_lines={usable}")
    print(f"malformed_lines={malformed}")
    for label, count in sorted(labels.items()):
        print(f"label.{label}={count}")


if __name__ == "__main__":
    main()
