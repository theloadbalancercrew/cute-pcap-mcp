#!/usr/bin/env python3
"""Summarize an SSLKEYLOGFILE without printing secret values."""

import argparse
import collections
import re

HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


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
            if len(parts) != 3 or not HEX_RE.match(parts[1]) or not HEX_RE.match(parts[2]):
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
