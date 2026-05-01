#!/usr/bin/env python3
"""Render a small tcpdump plan without guessing packet-analysis facts."""

import argparse


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interface", default="any")
    parser.add_argument("--output", default="/tmp/trace.pcap")
    parser.add_argument("--host", required=True)
    parser.add_argument("--port")
    parser.add_argument("--duration", default="60")
    args = parser.parse_args()

    flt = f"host {args.host}"
    if args.port:
        flt = f"tcp and {flt} and port {args.port}"

    print("Run while reproducing the issue:")
    print()
    print(
        f"sudo timeout {args.duration} tcpdump -s0 -nni {args.interface} "
        f"-w {args.output} '{flt}'"
    )


if __name__ == "__main__":
    main()
