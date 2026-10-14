# Sentinel - Offline AI Endpoint Security (Windows & macOS)

A standalone, dark-themed desktop app that runs **fully offline** and:

| Feature | What it does |
|---|---|
| **Open ports** | Lists every listening TCP/UDP socket with the owning app (name, path, PID, user, parent, command line), how exposed it is (this PC only / network / all interfaces) and a 0-100 risk score. |
| **Close-port advice + one-click close** | Recommends **Close / Review / Keep**. On **"Yes, close port"** it blocks the port in the OS firewall (reversible), and can also terminate the process or stop & disable the Windows service behind it. |
| **Unauthorised IP/domain detection** | Watches outbound connections every 15 s. Flags apps that contact threat-intel IPs/domains (mining pools, tunnels, Tor, your imports), anything on your block list, anything outside your allowlist (Allowlist mode), C2-style ports, programs running from Temp/Downloads, and **AI anomaly detection**: a per-app baseline of normal destinations, so a new destination is flagged after the learning window. Native desktop notifications, plus one-click Block IP / Kill / Trust. |
| **Vulnerabilities & patching** | Audits the OS (support status, firewall, Defender/Gatekeeper, SMBv1, RDP, UAC, BitLocker/FileVault, SIP, Secure Boot, LLMNR, auto-update, guest/auto-login, patch age), and with **Deep scan** lists missing Windows/macOS updates. Matches installed apps against a bundled CVE list (importable). Each finding has a built-in **fix playbook**: why it matters, manual steps, the exact commands, and **Apply fix** where it's safe to automate. |
| **AI advisor** | Works **without any model**: risk scoring, a prioritised action plan (impact ÷ effort) and a TF-IDF knowledge-base Q&A over the playbooks, port intel, CVEs and your live scan. If [Ollama](https://ollama.com) is running locally, answers are rewritten by your local LLM, grounded on the same facts. Nothing leaves the machine. |

## Architecture

```
Electron UI (renderer/, vanilla JS, no CDN)  ──HTTP 127.0.0.1 + per-launch token──►  Python engine (backend/)
   electron/main.js  spawns engine, tray,                               ports.py      sockets → apps, risk
                     notifications, admin elevation                     network.py    connections, intel, baseline
                                                                        vulns.py      OS audit, missing patches
                                                                        inventory.py  installed apps, CVE match
                                                                        remediation.py fix playbooks, firewall rules
                                                                        advisor.py    scoring, planner, Q&A, Ollama
                                                                        store.py      local policy + SQLite
```

Data lives in `%APPDATA%\Sentinel` (Windows) or `~/Library/Application Support/Sentinel` (macOS).

## Run in development

```bash
npm install                      # Electron + electron-builder
pip install -r backend/requirements.txt
npm start
```

Engine only: `python backend/server.py --port 8765 --token dev` then e.g. `curl -H "X-Sentinel-Token: dev" localhost:8765/api/summary`.
Tests: `python backend/tests/test_core.py`.

## Build the offline installers

The engine is frozen with PyInstaller, so **build on each target OS** (PyInstaller can't cross-compile).

* **Windows** (PowerShell, Python 3.10+, Node 18+): `npm install; npm run dist:win` → `dist\Sentinel Setup 1.0.0.exe`
  The app requests administrator rights at launch (needed to see every process's sockets and change firewall rules).
* **macOS** (Python 3.10+, Node 18+): `npm install && npm run dist:mac` → `dist/Sentinel-1.0.0.dmg`
  Build on Apple silicon for arm64, on Intel for x64. Use **Grant admin access** in the top bar to let the engine see all processes. For distribution outside your own Macs, sign & notarise (set `CSC_LINK`, `APPLE_ID` etc. for electron-builder).

The installer contains everything; no internet is needed to install or run it.

## How closing a port works

| OS | Block port | Block IP | Undo |
|---|---|---|---|
| Windows | `New-NetFirewallRule -Direction Inbound -Action Block -LocalPort N` | inbound + outbound rules on `-RemoteAddress` | Settings → *Firewall rules created by Sentinel* → Remove |
| macOS | `pf` rule loaded into anchor `com.apple/250.Sentinel` (no edit to `/etc/pf.conf`) | `block drop in/out` rules | Same; macOS clears pf on reboot - use *Re-apply after reboot* |

Every change asks for confirmation and OS admin approval, and is written to the Activity Log.

## Offline knowledge you can extend

* `backend/sentinel/knowledge/ports.json` - risk & advice per port.
* `backend/sentinel/knowledge/blocklist.txt` - seed threat-intel (mining pools, tunnels, Tor, dynamic DNS). Import bigger feeds (FireHOL level1, abuse.ch URLhaus hosts) from **Settings → Import threat feed** whenever you're online.
* `backend/sentinel/knowledge/cve_db.json` - seed list of high-impact CVEs (Chrome/Edge/Firefox libwebp, 7-Zip, WinRAR, PuTTY, VLC, KeePass, Git, Docker Desktop, Zoom, xz, OpenSSH). **This is a starter set, not full coverage** - import a larger JSON in the same schema from **Vulnerabilities → Import CVE database**.
* `backend/sentinel/knowledge/os_lifecycle.json` - OS end-of-support dates.

## Limits worth knowing

* Installing patches (Windows Update, `softwareupdate`, `winget`, `brew`) needs internet; detection, advice and every other fix work offline.
* Domain names for connections come from the Windows DNS cache or reverse DNS; a CDN IP may show a generic hostname.
* BitLocker/FileVault, Tamper Protection, SIP and Secure Boot are deliberately **manual** (recovery keys / firmware), with step-by-step guidance.
* Use it only on machines you own or administer.
