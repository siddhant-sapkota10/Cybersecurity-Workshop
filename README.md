# 🛡️ Cybersecurity Workshop — Local Server

A three-stage workshop demonstrating how HTTP exposes credentials in plaintext
and how HTTPS prevents this, using Wireshark packet analysis.

---

## Quick Start

```bash
# 1. Generate the pcap file for Stage 2 (do this once, distribute to students)
python generate_capture.py

# 2. Start all three servers
python start_workshop.py
```

The server will print the exact URLs to share with students.

---

## Stage Overview

| Stage | Page | Port | Protocol | URL |
|-------|------|------|----------|-----|
| 1 | BrewNet Cafe Staff Portal | 8080 | **HTTP** | `http://<your-ip>:8080` |
| 2 | SecureBank SOC Race | 8081 | **HTTP** | `http://<your-ip>:8081` |
| 3 | SecureBank Secure Portal | 8443 | **HTTPS** | `https://<your-ip>:8443` |

---

## Stage 1 — BrewNet Cafe Portal

**Goal:** Demonstrate that a real HTML form POST over HTTP sends credentials
in plaintext — readable by anyone with Wireshark on the same network.

### What to do

1. Give students `http://<your-ip>:8080`
2. Open Wireshark, select your WiFi interface
3. Apply filter: `http.request.method == "POST"`
4. Have a student click **Admin**, then click **Sign In to BrewNet Portal**
5. In Wireshark, click the captured POST packet → inspect the **HTTP** layer
6. The credentials appear in plain text in the packet body

Credentials are also printed to the server terminal in real time.

### Hardcoded credentials (visible in page HTML source too)

| Role | Username | Password |
|------|----------|----------|
| Barista | `staff.sophie` | `coffee2024` |
| Manager | `manager.brew` | `BrewNet@99` |
| Admin ⭐ | `admin.brewnet` | `C4feN3t!2025` |

> **Workshop tip:** Right-click the page → View Source. Show students the HTML
> comment block near the top containing all credentials. Point out that this
> plaintext comment also travels across the network in the HTTP response.

### Wireshark filter

```
http.request.method == "POST"
```

Follow HTTP stream to see:
```
username=admin.brewnet&password=C4feN3t%212025&role=admin
```
(`%21` decodes to `!`)

---

## Stage 2 — SecureBank SOC Credential Race

**Goal:** Students compete to find credentials hidden in a pre-made packet
capture file using Wireshark, then submit them on the race page.

### Setup (before the session)

1. Run `python generate_capture.py` — this creates `securebank_capture.pcap`
2. Distribute this file to each student's laptop via USB or Google Drive
3. Open `http://<your-ip>:8081` on the classroom display / each student device
4. Click **▶ START** to begin the 10-minute countdown

### Student instructions

1. Open `securebank_capture.pcap` in Wireshark
2. Apply filter: `http.request.method == "POST"`
3. Find the POST to `/internal/soc/login`
4. Right-click → **Follow** → **HTTP Stream**
5. Read the URL-encoded body — decode `%40` → `@` and `%23` → `#`
6. Submit on the race page — first correct entry gets the 🥇

### Correct answer

| Field | Value |
|-------|-------|
| Endpoint | `/internal/soc/login` |
| Username | `soc.admin.rowe` |
| Password | `Sb@nk#S3cure99` |

### Decoy accounts (wrong answers — visible in capture)

- `support.helpdesk`
- `analyst.tran`
- `audit.chen`

---

## Stage 3 — SecureBank HTTPS Portal

**Goal:** Show that applying the same Wireshark technique to the HTTPS port
reveals nothing — only TLS handshake frames, no readable credentials.

### What to do

1. Give students `https://<your-ip>:8443`
2. **Certificate warning:** Students must click *Advanced* → *Proceed to `<ip>` (unsafe)*
   - In Chrome: *Advanced* → *Proceed*
   - In Firefox: *Advanced* → *Accept the Risk and Continue*
   - In Safari: *Show Details* → *visit this website*
3. Open Wireshark, apply filter: `tcp.port == 8443`
4. Have a student log in with any credentials
5. Wireshark shows only TLS handshake packets — no readable content

> **The self-signed cert warning is intentional.** It gives you an opportunity
> to explain: "A real bank would have a CA-signed cert — your browser would
> show a padlock, not a warning. The warning here means the cert isn't trusted
> by a Certificate Authority, but the encryption still works."

---

## Requirements

- Python 3.7+ (stdlib only — no pip installs needed)
- `openssl` on PATH (for cert generation — pre-installed on macOS and most Linux)
- Wireshark installed on each student device (for Stage 1 & 2 demos)
- All devices on the same WiFi network

### macOS notes

macOS ships with LibreSSL (not OpenSSL). The server uses a config-file approach
for cert generation that is compatible with LibreSSL. If cert generation fails,
you can generate it manually:

```bash
openssl req -x509 -newkey rsa:2048 -keyout certs/workshop.key \
  -out certs/workshop.crt -days 1 -nodes \
  -subj "/CN=$(ipconfig getifaddr en0)"
```

---

## File Structure

```
workshop/
├── start_workshop.py          ← Run this to start everything
├── generate_capture.py        ← Run once to generate the pcap file
├── README.md
├── brewnet/
│   └── index.html             ← Stage 1: BrewNet Cafe (HTTP :8080)
├── securebank/
│   └── index.html             ← Stage 2: SOC Race (HTTP :8081)
├── securebank-https/
│   └── index.html             ← Stage 3: Secure Portal (HTTPS :8443)
├── certs/
│   ├── workshop.crt           ← Auto-generated
│   ├── workshop.key           ← Auto-generated
│   └── openssl.cnf            ← Auto-generated
└── securebank_capture.pcap    ← Generated by generate_capture.py
```

---

## Key Teaching Points

### Why HTTP is dangerous
- Form POST bodies are transmitted as plain `application/x-www-form-urlencoded` text
- On a shared network (like school WiFi), any device can capture this with Wireshark
- This is a passive attack — the server never knows it happened
- HTML comment blocks in the page source also travel unencrypted in the HTTP response

### Why HTTPS fixes this
- TLS encrypts the entire HTTP payload before any bytes leave the device
- Wireshark can see the connection exists (IP/TCP headers) but not what was said
- Even the URL path is hidden once the TLS handshake completes
- A self-signed cert provides the same encryption strength — it just isn't verified by a CA

### URL encoding note
When form data contains special characters, the browser URL-encodes them:
- `@` → `%40`
- `#` → `%23`
- `!` → `%21`
- Space → `%20` or `+`

Students need to decode these to read the true password. This is visible in
Wireshark's "Follow HTTP Stream" view.

---

## Credential Quick Reference

| Stage | Username | Password | Endpoint |
|-------|----------|----------|----------|
| BrewNet Admin | `admin.brewnet` | `C4feN3t!2025` | form POST |
| SOC Admin | `soc.admin.rowe` | `Sb@nk#S3cure99` | `/internal/soc/login` |

---

*Built for Year 11/12 Cybersecurity Workshop — all credentials and scenarios are fictional.*
