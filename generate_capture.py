#!/usr/bin/env python3
"""
generate_capture.py
───────────────────
Generates a fake .pcap file for the SecureBank SOC Challenge (Stage 2).
Students open this file in Wireshark and race to find the hidden admin
credentials embedded in an HTTP POST request.

Usage:
    python generate_capture.py

Output:
    securebank_capture.pcap  (distribute this to students via USB / Drive)

No external dependencies — uses only Python stdlib (struct, time, random).
"""

import struct
import time
import random
import sys
from pathlib import Path

OUT = Path(__file__).parent / "securebank_capture.pcap"

# ── Target credentials (embedded in the capture) ─────────────────
TARGET_ENDPOINT = "/internal/soc/login"
TARGET_USER     = "soc.admin.rowe"
TARGET_PASS_RAW = "Sb@nk#S3cure99"            # decoded form
TARGET_PASS_ENC = "Sb%40nk%23S3cure99"        # URL-encoded form (in packet)

# ── Network constants ─────────────────────────────────────────────
SERVER_IP   = "10.0.1.100"
SERVER_PORT = 8081

CLIENTS = [
    ("192.168.10.45", "aa:bb:cc:11:22:33"),
    ("192.168.10.67", "aa:bb:cc:44:55:66"),
    ("192.168.10.89", "aa:bb:cc:77:88:99"),
    ("192.168.10.102","aa:bb:cc:aa:bb:cc"),
    ("10.0.1.34",     "aa:bb:cc:dd:ee:ff"),
]
SERVER_MAC = "00:11:22:33:44:55"


# ══════════════════════════════════════════════════════════════════
#  PCAP BINARY BUILDING UTILITIES
# ══════════════════════════════════════════════════════════════════

def chk(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def mac_bytes(mac_str: str) -> bytes:
    return bytes(int(x, 16) for x in mac_str.split(':'))


def ip_bytes(ip_str: str) -> bytes:
    return bytes(int(x) for x in ip_str.split('.'))


def build_ipv4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    ihl = 5
    total = 20 + len(payload)
    ident = random.randint(1, 65535)
    hdr = struct.pack('!BBHHHBBH4s4s',
        (4 << 4) | ihl, 0, total,
        ident, 0x4000,           # DF flag
        64, proto, 0,
        ip_bytes(src), ip_bytes(dst)
    )
    csum = chk(hdr)
    return hdr[:10] + struct.pack('!H', csum) + hdr[12:] + payload


def build_tcp(src_ip: str, dst_ip: str,
              sport: int, dport: int,
              seq: int, ack: int,
              flags: int, payload: bytes) -> bytes:
    data_offset = 5
    win   = 65535
    hdr   = struct.pack('!HHIIBBHHH',
        sport, dport, seq, ack,
        (data_offset << 4), flags, win, 0, 0
    )
    # TCP pseudo-header checksum
    pseudo = (ip_bytes(src_ip) + ip_bytes(dst_ip) +
              b'\x00\x06' +
              struct.pack('!H', len(hdr) + len(payload)))
    csum = chk(pseudo + hdr + payload)
    return hdr[:16] + struct.pack('!H', csum) + hdr[18:] + payload


def build_eth(src_mac: str, dst_mac: str, payload: bytes) -> bytes:
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + b'\x08\x00' + payload


def pcap_global_header() -> bytes:
    return struct.pack('<IHHiIII',
        0xa1b2c3d4,  # magic (little-endian timestamps)
        2, 4,        # version 2.4
        0,           # thiszone
        0,           # sigfigs
        65535,       # snaplen
        1            # link-type: Ethernet
    )


def pcap_packet(data: bytes, ts: float) -> bytes:
    ts_s  = int(ts)
    ts_us = int((ts - ts_s) * 1_000_000)
    return struct.pack('<IIII', ts_s, ts_us, len(data), len(data)) + data


# ══════════════════════════════════════════════════════════════════
#  PACKET CONSTRUCTION HELPERS
# ══════════════════════════════════════════════════════════════════

_seq = 1000

def next_seq(n: int = 0) -> int:
    global _seq
    _seq += random.randint(1, 200) + n
    return _seq


def http_request_packet(
    src_ip: str, src_mac: str,
    method: str, path: str,
    host: str, body: str,
    ts: float,
    extra_headers: dict | None = None,
) -> bytes:
    headers = {
        "Host": host,
        "User-Agent": "Mozilla/5.0 (SecureBank-SOC/2.4)",
        "Accept": "application/json",
        "Connection": "keep-alive",
    }
    if body:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    if extra_headers:
        headers.update(extra_headers)

    raw_headers = "\r\n".join(f"{k}: {v}" for k, v in headers.items())
    http = f"{method} {path} HTTP/1.1\r\n{raw_headers}\r\n\r\n{body}".encode()

    sport = random.randint(49152, 65535)
    tcp   = build_tcp(src_ip, SERVER_IP, sport, SERVER_PORT,
                      next_seq(), 0, 0x018, http)
    ip    = build_ipv4(src_ip, SERVER_IP, 6, tcp)
    return build_eth(src_mac, SERVER_MAC, ip)


def http_response_packet(
    dst_ip: str, dst_mac: str,
    status: str, body: str, ts: float
) -> bytes:
    body_bytes = body.encode()
    http = (
        f"HTTP/1.1 {status}\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body_bytes)}\r\n"
        f"Server: SecureBank-SOC/2.4\r\n"
        f"Connection: keep-alive\r\n\r\n"
    ).encode() + body_bytes

    dport = random.randint(49152, 65535)
    tcp   = build_tcp(SERVER_IP, dst_ip, SERVER_PORT, dport,
                      next_seq(), 0, 0x018, http)
    ip    = build_ipv4(SERVER_IP, dst_ip, 6, tcp)
    return build_eth(SERVER_MAC, dst_mac, ip)


# ══════════════════════════════════════════════════════════════════
#  MAIN — BUILD THE CAPTURE FILE
# ══════════════════════════════════════════════════════════════════

def main():
    print("Generating SecureBank SOC capture file …")

    host = f"{SERVER_IP}:{SERVER_PORT}"
    # Base time: roughly 4 hours ago (feels like an overnight incident log)
    base_ts = time.time() - (4 * 3600)
    t = base_ts

    packets = []

    def add(pkt_bytes: bytes, delta: float = 0.0):
        nonlocal t
        t += delta
        packets.append(pcap_packet(pkt_bytes, t))

    c1_ip, c1_mac = CLIENTS[0]
    c2_ip, c2_mac = CLIENTS[1]
    c3_ip, c3_mac = CLIENTS[2]
    c4_ip, c4_mac = CLIENTS[3]
    c5_ip, c5_mac = CLIENTS[4]

    # ── Phase 1: Normal-looking background traffic ────────────────
    # Health-check GETs
    add(http_request_packet(c1_ip, c1_mac, "GET", "/api/status", host, "", t), 0)
    add(http_response_packet(c1_ip, c1_mac, "200 OK",
        '{"status":"operational","ts":"2025-05-26T02:01:12Z"}', t), 0.18)

    add(http_request_packet(c3_ip, c3_mac, "GET", "/dashboard", host, "", t), 1.4)
    add(http_response_packet(c3_ip, c3_mac, "200 OK",
        '{"dashboard":"SOC-v2","alerts":7}', t), 0.22)

    add(http_request_packet(c2_ip, c2_mac, "GET", "/api/accounts", host, "", t), 2.1)
    add(http_response_packet(c2_ip, c2_mac, "200 OK",
        '{"accounts":["support.helpdesk","analyst.tran","audit.chen"]}', t), 0.19)

    # ── Phase 2: Decoy login attempt — support.helpdesk ──────────
    body_d1 = "username=support.helpdesk&password=Help%40Desk2024&remember=false"
    add(http_request_packet(c2_ip, c2_mac, "POST", "/api/auth", host, body_d1,
        t, {"X-Forwarded-For": c2_ip}), 3.7)
    add(http_response_packet(c2_ip, c2_mac, "401 Unauthorized",
        '{"error":"invalid_credentials","account":"support.helpdesk"}', t), 0.31)

    # ── Phase 3: More noise ───────────────────────────────────────
    add(http_request_packet(c4_ip, c4_mac, "GET", "/api/health", host, "", t), 2.9)
    add(http_response_packet(c4_ip, c4_mac, "200 OK", '{"ok":true}', t), 0.11)

    body_transfer = "account=SB-4421-0099&amount=5000&currency=AUD&auth_token=eyJ0eXAiOiJKV1QifQ"
    add(http_request_packet(c5_ip, c5_mac, "POST", "/api/transfer", host,
        body_transfer, t), 1.8)
    add(http_response_packet(c5_ip, c5_mac, "200 OK",
        '{"txid":"TX-20250526-00441","status":"queued"}', t), 0.24)

    # ── Phase 4: Decoy login attempt — audit.chen ────────────────
    body_d2 = "username=audit.chen&password=Audit%23Chen99&otp=382910"
    add(http_request_packet(c3_ip, c3_mac, "POST", "/api/auth", host, body_d2, t), 5.2)
    add(http_response_packet(c3_ip, c3_mac, "401 Unauthorized",
        '{"error":"invalid_credentials","account":"audit.chen"}', t), 0.28)

    add(http_request_packet(c1_ip, c1_mac, "GET", "/internal/reports/q1", host, "", t), 3.1)
    add(http_response_packet(c1_ip, c1_mac, "403 Forbidden",
        '{"error":"insufficient_privileges"}', t), 0.14)

    # ── Phase 5: Decoy login attempt — analyst.tran ──────────────
    body_d3 = "username=analyst.tran&password=Tr%40nSOC2024&department=soc"
    add(http_request_packet(c4_ip, c4_mac, "POST", "/api/auth", host, body_d3, t), 4.4)
    add(http_response_packet(c4_ip, c4_mac, "401 Unauthorized",
        '{"error":"invalid_credentials","account":"analyst.tran"}', t), 0.22)

    # ── Gap: a quiet period ───────────────────────────────────────
    add(http_request_packet(c2_ip, c2_mac, "GET", "/api/status", host, "", t), 12.6)
    add(http_response_packet(c2_ip, c2_mac, "200 OK",
        '{"status":"operational"}', t), 0.13)

    # ── Phase 6: THE TARGET PACKET ── admin credentials ──────────
    # This is what students are hunting for.
    target_body = (
        f"username={TARGET_USER}"
        f"&password={TARGET_PASS_ENC}"
        f"&endpoint={TARGET_ENDPOINT}"
        f"&remember=false"
        f"&session_type=admin"
    )
    add(http_request_packet(
        c1_ip, c1_mac,
        "POST", TARGET_ENDPOINT, host,
        target_body, t,
        {
            "X-SOC-Role":    "administrator",
            "X-Auth-Source": "soc-console",
        }
    ), 8.3)
    add(http_response_packet(c1_ip, c1_mac, "200 OK",
        '{"status":"authenticated","role":"soc_admin","token":"REDACTED"}', t), 0.38)

    # ── Phase 7: Post-login admin activity ───────────────────────
    add(http_request_packet(c1_ip, c1_mac, "GET", "/internal/soc/dashboard",
        host, "", t), 1.7)
    add(http_response_packet(c1_ip, c1_mac, "200 OK",
        '{"alerts":7,"incidents":2,"analysts_online":3}', t), 0.21)

    add(http_request_packet(c3_ip, c3_mac, "GET", "/api/status", host, "", t), 3.4)
    add(http_response_packet(c3_ip, c3_mac, "200 OK",
        '{"status":"operational"}', t), 0.12)

    # ── Write file ────────────────────────────────────────────────
    with open(OUT, "wb") as f:
        f.write(pcap_global_header())
        for pkt in packets:
            f.write(pkt)

    size_kb = OUT.stat().st_size / 1024
    print(f"\n  ✅  Created: {OUT}")
    print(f"      Packets  : {len(packets)}")
    print(f"      File size: {size_kb:.1f} KB")
    print(f"\n  Distribute this file to students via USB or Google Drive.")
    print(f"  They should open it in Wireshark and filter by:")
    print(f'      http.request.method == "POST"')
    print(f"\n  The target POST is to: {TARGET_ENDPOINT}")
    print(f"  Credentials in capture:")
    print(f"      Username : {TARGET_USER}")
    print(f"      Password : {TARGET_PASS_RAW}  (URL-encoded as: {TARGET_PASS_ENC})")
    print()


if __name__ == "__main__":
    main()
