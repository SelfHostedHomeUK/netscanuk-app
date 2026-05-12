# Netscan

**Home network security scanning with nmap and AI-powered analysis.**

Netscan scans a device on your home LAN with nmap, sends the results to Claude AI for analysis, and produces a plain English security report with a prioritised remediation plan and a downloadable bash fix script.

Built for self-hosters running Raspberry Pis, home servers, NAS boxes, and Docker stacks — not for enterprise security teams.

**Live at [netscan.uk](https://netscan.uk)**

---

## What it does

1. **Scans** — nmap scans the top 1000 ports on a target IP, runs service fingerprinting, version detection, NSE vulnerability scripts, SSL/TLS checks, and SSH auth method detection
2. **Analyses** — findings go to Claude AI, which acts as a home-network-aware security analyst and produces a structured report
3. **Reports** — executive summary, technical breakdown, attack path analysis, prioritised remediation plan, and a downloadable bash script to fix what it found

Scan time: **2–5 minutes** per host.

---

## What it finds

In real scans across a typical home setup, Netscan found:

- InfluxDB instance with no authentication enabled
- qBittorrent web UI serving credentials over plain HTTP
- NFS shares open to the entire LAN
- SSH password authentication left enabled
- Services running in development mode (verbose error output)
- Docker ports unnecessarily bound to `0.0.0.0`

---

## Requirements

- Docker and Docker Compose
- An [Anthropic API key](https://console.anthropic.com)
- Linux host (the container uses `network_mode: host` so nmap can reach your LAN)

---

## Quick start

```bash
git clone https://github.com/SelfHostedHomeUK/netscanuk-app.git
cd netscanuk-app
```

Create `app/.env`:

```env
ANTHROPIC_API_KEY=sk-ant-...
PORT=3004
```

Start the container:

```bash
docker compose up -d
```

Open `http://localhost:3004`, enter a target IP on your LAN, and start a scan.

---

## Stack

| Component | Role |
|-----------|------|
| **nmap** | Port scanning, service detection, NSE scripts |
| **Node.js / Express** | Backend, scan orchestration, API |
| **Claude AI** | Security analysis and report generation |
| **Docker** | Single container deployment |

The container runs as `node:18-alpine` with nmap installed. `network_mode: host` gives nmap direct access to the physical LAN — required for accurate scanning.

---

## Project structure

```
netscanuk-app/
├── app/
│   ├── server.js          # Express backend — scan, analyse, remediate
│   ├── Dockerfile         # node:18-alpine + nmap
│   ├── package.json
│   ├── .env.example
│   └── public/
│       └── index.html     # Frontend UI
├── compose.yaml           # Single-container stack
└── README.md
```

---

## How the scan works

nmap is called with:

```
-sV                   # Service and version detection
-sC                   # Default NSE scripts
--script=...          # Additional targeted scripts (SSL, SSH, HTTP, FTP, SNMP)
--top-ports 1000      # Top 1000 ports for speed
--host-timeout 5m     # 5 minute max per host
--open                # Only report open ports
-oX -                 # XML output to stdout for parsing
```

The XML output is parsed into a structured findings array and sent to Claude with a prompt focused on home network context.

---

## Security note

Only scan networks and devices you own or have explicit written permission to scan. Unauthorised scanning may be illegal in your jurisdiction.

---

## Licence

MIT — self-host it, fork it, improve it.

---

*Built by [Self Hosted Home UK](https://selfhostedhome.co.uk)*
