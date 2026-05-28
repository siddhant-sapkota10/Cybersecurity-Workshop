#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║         CYBERSECURITY WORKSHOP — LOCAL SERVER LAUNCHER          ║
║                                                                  ║
║  Stage 1 · BrewNet Cafe Portal    → Port 8080  (HTTP)           ║
║  Stage 2 · SecureBank SOC Race    → Port 8081  (HTTP)           ║
║  Stage 3 · SecureBank Secure      → Port 8443  (HTTPS)          ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python start_workshop.py

Requires: Python 3.7+, openssl (for cert generation)
"""

import http.server
import ssl
import threading
import socket
import os
import subprocess
import sys
import time
import signal
from pathlib import Path
from urllib.parse import parse_qs, urlparse, unquote_plus

# ── Paths ──────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent.resolve()
CERTS_DIR     = BASE_DIR / "certs"
CERT_FILE     = CERTS_DIR / "workshop.crt"
KEY_FILE      = CERTS_DIR / "workshop.key"
OPENSSL_CNF   = CERTS_DIR / "openssl.cnf"

BREWNET_DIR   = BASE_DIR / "brewnet"
SECBANK_DIR   = BASE_DIR / "securebank"
HTTPS_DIR     = BASE_DIR / "securebank-https"

# ── Ports ──────────────────────────────────────────────────────────
BREWNET_PORT  = 8080
SECBANK_PORT  = 8081
HTTPS_PORT    = 8443

# ── ANSI colours ───────────────────────────────────────────────────
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
C  = "\033[96m"   # cyan
B  = "\033[94m"   # blue
BL = "\033[1m"    # bold
DM = "\033[2m"    # dim
RS = "\033[0m"    # reset


# ── Helpers ────────────────────────────────────────────────────────

def get_local_ip() -> str:
    """Return the machine's LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def generate_cert(local_ip: str) -> None:
    """Generate a self-signed TLS certificate for the HTTPS server."""
    CERTS_DIR.mkdir(exist_ok=True)

    if CERT_FILE.exists() and KEY_FILE.exists():
        print(f"  {DM}→ Certificate already exists — reusing.{RS}")
        return

    print(f"  → Generating self-signed TLS certificate for {local_ip} …")

    # Write an openssl config with proper SANs (works on LibreSSL & OpenSSL)
    cnf = f"""[req]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
x509_extensions    = v3_req

[dn]
C  = AU
ST = NSW
L  = Sydney
O  = Cybersecurity Workshop
CN = {local_ip}

[v3_req]
subjectAltName = @alt_names
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment

[alt_names]
IP.1  = {local_ip}
IP.2  = 127.0.0.1
DNS.1 = localhost
"""
    OPENSSL_CNF.write_text(cnf)

    try:
        result = subprocess.run(
            [
                "openssl", "req", "-x509",
                "-newkey", "rsa:2048",
                "-keyout", str(KEY_FILE),
                "-out",    str(CERT_FILE),
                "-days",   "1",
                "-nodes",
                "-config", str(OPENSSL_CNF),
            ],
            check=True, capture_output=True,
        )
        print(f"  {G}→ Certificate generated successfully.{RS}")
    except subprocess.CalledProcessError as e:
        print(f"  {R}→ openssl failed:{RS}\n{e.stderr.decode()}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"  {R}→ openssl not found on PATH.{RS}")
        print(f"      macOS: already installed via LibreSSL")
        print(f"      Linux: sudo apt install openssl")
        sys.exit(1)


# ── Request Handlers ───────────────────────────────────────────────

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    """Suppress default access-log noise; only print credential captures."""
    def log_message(self, fmt, *args):
        pass
    def log_error(self, fmt, *args):
        pass


class BrewNetHandler(QuietHandler):
    """
    HTTP handler for the BrewNet Cafe portal (port 8080).
    Serves static files from brewnet/ AND handles POST /login,
    logging captured credentials to stdout so the presenter can
    display them alongside the Wireshark capture.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BREWNET_DIR), **kwargs)

    def do_POST(self):
        if self.path != "/login":
            self.send_error(404, "Not Found")
            return

        length  = int(self.headers.get("Content-Length", 0))
        raw     = self.rfile.read(length).decode("utf-8", errors="replace")
        params  = parse_qs(raw)
        user    = unquote_plus(params.get("username", [""])[0])
        passwd  = unquote_plus(params.get("password", [""])[0])
        role    = unquote_plus(params.get("role",     ["unknown"])[0])

        # ── Print captured credentials to presenter's terminal ──
        print(f"\n{R}{'━'*60}{RS}")
        print(f"{R}{BL}  ⚠   HTTP CREDENTIALS CAPTURED IN PLAINTEXT   ⚠{RS}")
        print(f"{R}{'━'*60}{RS}")
        print(f"  {BL}Source IP :{RS}  {self.client_address[0]}")
        print(f"  {BL}Endpoint  :{RS}  POST /login  (HTTP — unencrypted)")
        print(f"  {BL}Username  :{RS}  {Y}{user}{RS}")
        print(f"  {BL}Password  :{RS}  {Y}{passwd}{RS}")
        print(f"  {BL}Role      :{RS}  {Y}{role}{RS}")
        print(f"  {BL}Raw body  :{RS}  {DM}{raw[:200]}{RS}")
        print(f"{R}{'━'*60}{RS}\n")

        # Redirect back to the portal — JS will detect ?logged_in=true
        # and render the admin dashboard modal
        self.send_response(302)
        self.send_header("Location",
            f"/?logged_in=true&role={role}&user={user}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()


class SecureBankHandler(QuietHandler):
    """HTTP handler for the SecureBank SOC challenge (port 8081 — plain HTTP)."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(SECBANK_DIR), **kwargs)


class SecureBankHTTPSHandler(QuietHandler):
    """HTTPS handler for the SecureBank secure portal (port 8443 — TLS)."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(HTTPS_DIR), **kwargs)


# ── Server Factory ─────────────────────────────────────────────────

def make_server(handler_cls, port: int, use_ssl: bool = False):
    server = http.server.HTTPServer(("", port), handler_cls)
    if use_ssl:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(CERT_FILE), str(KEY_FILE))
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    return server


def run_server(server):
    try:
        server.serve_forever()
    except Exception as exc:
        print(f"{R}Server error: {exc}{RS}")


# ── Main ───────────────────────────────────────────────────────────

def main():
    local_ip = get_local_ip()

    print(f"\n{C}{'═'*62}{RS}")
    print(f"{C}{BL}  🛡  CYBERSECURITY WORKSHOP SERVER  🛡{RS}")
    print(f"{C}{'═'*62}{RS}\n")

    # Step 1 — TLS certificate
    print(f"{BL}[1/3] Preparing TLS certificate …{RS}")
    generate_cert(local_ip)

    # Step 2 — Start servers
    print(f"\n{BL}[2/3] Starting servers …{RS}")
    try:
        srv_brew  = make_server(BrewNetHandler,          BREWNET_PORT)
        srv_soc   = make_server(SecureBankHandler,       SECBANK_PORT)
        srv_https = make_server(SecureBankHTTPSHandler,  HTTPS_PORT, use_ssl=True)
    except OSError as e:
        print(f"\n{R}  ✖ Could not bind to a port: {e}{RS}")
        print(f"    Check that ports {BREWNET_PORT}, {SECBANK_PORT}, {HTTPS_PORT} are free.\n")
        sys.exit(1)

    for srv in (srv_brew, srv_soc, srv_https):
        t = threading.Thread(target=run_server, args=(srv,), daemon=True)
        t.start()

    # Step 3 — Print URLs
    print(f"\n{G}{'═'*62}{RS}")
    print(f"{G}{BL}  ✅  ALL THREE SERVERS ARE RUNNING{RS}")
    print(f"{G}{'═'*62}{RS}\n")

    print(f"  {BL}STAGE 1 — BrewNet Cafe Staff Portal (HTTP){RS}")
    print(f"  {Y}http://{local_ip}:{BREWNET_PORT}{RS}")
    print(f"  {DM}Wireshark filter: http.request.method == \"POST\"{RS}\n")

    print(f"  {BL}STAGE 2 — SecureBank SOC Credential Race (HTTP){RS}")
    print(f"  {Y}http://{local_ip}:{SECBANK_PORT}{RS}")
    print(f"  {DM}Wireshark filter: http contains \"password\"{RS}\n")

    print(f"  {BL}STAGE 3 — SecureBank Secure Portal (HTTPS){RS}")
    print(f"  {C}https://{local_ip}:{HTTPS_PORT}{RS}")
    print(f"  {DM}Wireshark filter: tcp.port == {HTTPS_PORT}  (only TLS handshake visible){RS}\n")

    print(f"  {DM}Students connecting to Stage 3 must click through the{RS}")
    print(f"  {DM}certificate warning: Advanced → Proceed to {local_ip} (unsafe){RS}\n")

    print(f"{'─'*62}")
    print(f"  Captured credentials will print here in real time.")
    print(f"  Press {BL}Ctrl+C{RS} to stop all servers.")
    print(f"{'─'*62}\n")

    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass

    print(f"\n{Y}Shutting down …{RS}")
    for srv in (srv_brew, srv_soc, srv_https):
        srv.shutdown()
    print(f"{G}All servers stopped. Goodbye.{RS}\n")


if __name__ == "__main__":
    main()
