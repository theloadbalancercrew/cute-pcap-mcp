#!/usr/bin/env python3
"""Generate deterministic symptom fixture pcaps without external deps.

The fixtures are intentionally tiny and synthetic. They exercise the
diagnose extractor's wire-shape contract, not full endpoint stacks.
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def tcp_segment(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    header = bytearray(20)
    struct.pack_into("!HHII", header, 0, src_port, dst_port, seq, ack)
    header[12] = 5 << 4
    header[13] = flags
    struct.pack_into("!H", header, 14, 64240)
    pseudo = (
        socket.inet_aton(src_ip)
        + socket.inet_aton(dst_ip)
        + bytes([0, 6])
        + struct.pack("!H", len(header) + len(payload))
    )
    struct.pack_into("!H", header, 16, checksum(pseudo + bytes(header) + payload))
    return bytes(header) + payload


def ipv4_packet(src_ip: str, dst_ip: str, payload: bytes, ident: int = 1) -> bytes:
    header = bytearray(20)
    header[0] = 0x45
    struct.pack_into("!H", header, 2, len(header) + len(payload))
    struct.pack_into("!H", header, 4, ident)
    struct.pack_into("!H", header, 6, 0x4000)
    header[8] = 64
    header[9] = 6
    header[12:16] = socket.inet_aton(src_ip)
    header[16:20] = socket.inet_aton(dst_ip)
    struct.pack_into("!H", header, 10, checksum(bytes(header)))
    return bytes(header) + payload


def ethernet_frame(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    flags: int,
    payload: bytes = b"",
) -> bytes:
    eth = (
        bytes.fromhex("020000000002")
        + bytes.fromhex("020000000001")
        + struct.pack("!H", 0x0800)
    )
    tcp = tcp_segment(src_ip, dst_ip, src_port, dst_port, seq, ack, flags, payload)
    return eth + ipv4_packet(src_ip, dst_ip, tcp)


def tls_client_hello() -> bytes:
    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x00\x2f"
        + b"\x01\x00"
        + struct.pack("!H", 0)
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def tls_server_hello() -> bytes:
    body = (
        b"\x03\x03"
        + b"\x22" * 32
        + b"\x00"
        + b"\x00\x2f"
        + b"\x00"
        + struct.pack("!H", 0)
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def write_pcap(path: Path, frames: list[tuple[float, bytes]]) -> None:
    out = bytearray()
    out += struct.pack("<IHHiiii", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for timestamp, frame in frames:
        sec = int(timestamp)
        usec = int((timestamp - sec) * 1_000_000)
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
    path.write_bytes(out)


def pad4(value: bytes) -> bytes:
    return value + b"\0" * ((-len(value)) % 4)


def block(block_type: int, body: bytes) -> bytes:
    total_len = 12 + len(body)
    return struct.pack("<II", block_type, total_len) + body + struct.pack("<I", total_len)


def pcapng_option_string(code: int, value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack("<HH", code, len(raw)) + pad4(raw)


def pcapng_options(options: list[bytes]) -> bytes:
    return b"".join(options) + struct.pack("<HH", 0, 0)


def pcapng_section_header() -> bytes:
    body = struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + struct.pack("<HH", 0, 0)
    return block(0x0A0D0D0A, body)


def pcapng_interface(name: str) -> bytes:
    body = struct.pack("<HHI", 1, 0, 65535) + pcapng_options([pcapng_option_string(2, name)])
    return block(1, body)


def pcapng_packet(interface_id: int, timestamp: float, frame: bytes) -> bytes:
    usec = int(timestamp * 1_000_000)
    body = (
        struct.pack("<IIIII", interface_id, usec >> 32, usec & 0xFFFFFFFF, len(frame), len(frame))
        + pad4(frame)
        + struct.pack("<HH", 0, 0)
    )
    return block(6, body)


def write_pcapng(
    path: Path,
    interfaces: list[str],
    frames: list[tuple[int, float, bytes]],
) -> None:
    out = bytearray()
    out += pcapng_section_header()
    for name in interfaces:
        out += pcapng_interface(name)
    for interface_id, timestamp, frame in frames:
        out += pcapng_packet(interface_id, timestamp, frame)
    path.write_bytes(out)


def flow(
    client: str,
    server: str,
    client_port: int,
    server_port: int,
    start: float,
    server_response: str,
) -> list[tuple[float, bytes]]:
    client_hello = tls_client_hello()
    frames = [
        (start + 0.000, ethernet_frame(client, server, client_port, server_port, 1, 0, 0x02)),
        (start + 0.001, ethernet_frame(server, client, server_port, client_port, 100, 2, 0x12)),
        (start + 0.002, ethernet_frame(client, server, client_port, server_port, 2, 101, 0x10)),
        (start + 0.003, ethernet_frame(client, server, client_port, server_port, 2, 101, 0x18, client_hello)),
    ]
    if server_response == "rst":
        frames.append((start + 0.004, ethernet_frame(server, client, server_port, client_port, 101, 2 + len(client_hello), 0x14)))
    elif server_response == "server_hello":
        frames.append((start + 0.004, ethernet_frame(server, client, server_port, client_port, 101, 2 + len(client_hello), 0x18, tls_server_hello())))
    elif server_response == "http":
        frames.append((start + 0.004, ethernet_frame(server, client, server_port, client_port, 101, 2 + len(client_hello), 0x18, b"HTTP/1.1 400 Bad Request\r\n\r\n")))
    return frames


def tcp_rst_no_app_fixture(path: Path, positive: bool) -> None:
    client = "192.0.2.10"
    server = "198.51.100.20"
    cp = 41000
    sp = 443
    frames = [
        (0.000, ethernet_frame(client, server, cp, sp, 1, 0, 0x02)),
        (0.001, ethernet_frame(server, client, sp, cp, 100, 2, 0x12)),
        (0.002, ethernet_frame(client, server, cp, sp, 2, 101, 0x10)),
    ]
    if positive:
        frames.append((0.003, ethernet_frame(server, client, sp, cp, 101, 2, 0x14)))
    else:
        frames.append((0.003, ethernet_frame(client, server, cp, sp, 2, 101, 0x18, b"GET /ok HTTP/1.1\r\n\r\n")))
        frames.append((0.004, ethernet_frame(server, client, sp, cp, 101, 21, 0x14)))
    write_pcap(path, frames)


def monitor_fixture(path: Path, positive: bool) -> None:
    client = "192.0.2.30"
    server = "198.51.100.30"
    frames: list[tuple[float, bytes]] = []
    for idx, timestamp in enumerate([0.0, 30.0, 60.0, 90.0]):
        cp = 42000 + idx
        frames.append((timestamp, ethernet_frame(client, server, cp, 8080, 1, 0, 0x02)))
        if positive or idx < 2:
            frames.append((timestamp + 0.001, ethernet_frame(server, client, 8080, cp, 100, 2, 0x14)))
        else:
            frames.append((timestamp + 0.001, ethernet_frame(server, client, 8080, cp, 100, 2, 0x12)))
            frames.append((timestamp + 0.002, ethernet_frame(client, server, cp, 8080, 2, 101, 0x10)))
    write_pcap(path, frames)


def asymmetric_fixture(path: Path, positive: bool) -> None:
    client = "10.0.0.1"
    server = "10.0.0.2"
    syn = ethernet_frame(client, server, 43000, 443, 1, 0, 0x02)
    synack = ethernet_frame(server, client, 443, 43000, 100, 2, 0x12)
    if positive:
        write_pcapng(path, ["client_vlan", "server_vlan"], [(0, 0.0, syn), (1, 0.001, synack)])
    else:
        write_pcapng(path, ["client_vlan"], [(0, 0.0, syn), (0, 0.001, synack)])


def generate(token: str) -> None:
    directory = ROOT / token
    if token == "tls_handshake_attempted_on_plain_port":
        write_pcap(directory / "positive.pcap", flow("192.0.2.10", "198.51.100.20", 40000, 80, 0.0, "rst"))
        write_pcap(directory / "negative.pcap", flow("192.0.2.10", "198.51.100.20", 40000, 80, 0.0, "server_hello"))
    elif token == "tcp_rst_after_synack_no_app_data":
        tcp_rst_no_app_fixture(directory / "positive.pcap", True)
        tcp_rst_no_app_fixture(directory / "negative.pcap", False)
    elif token == "monitor_probe_returns_rst":
        monitor_fixture(directory / "positive.pcap", True)
        monitor_fixture(directory / "negative.pcap", False)
    elif token == "asymmetric_return_path_observed":
        asymmetric_fixture(directory / "positive.pcap", True)
        asymmetric_fixture(directory / "negative.pcap", False)
    else:
        raise SystemExit(f"unknown symptom token: {token}")


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: generate_fixture.py <symptom_token>")
    generate(sys.argv[1])


if __name__ == "__main__":
    main()
