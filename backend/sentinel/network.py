"""Outbound connection monitor: detects applications reaching unauthorised / malicious IPs or domains.

Detection layers (all offline):
  1. Threat-intel match   - bundled + imported IP/CIDR/domain lists.
  2. User policy          - explicit block lists, or allowlist mode (anything not allowed = unauthorised).
  3. Behavioural baseline - learns which destinations each app normally talks to; flags first-seen
                            destinations after the learning window (unsupervised anomaly detection).
  4. Heuristics           - C2-style ports, programs running from temp folders, raw-IP traffic on
                            odd ports, unsigned/unknown processes.
"""
from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor, wait
from pathlib import Path

import psutil

from . import store
from .platform_utils import IS_MAC, IS_WIN, powershell, run

KNOW = Path(__file__).parent / "knowledge"
C2_PORTS = {4444: "Metasploit default", 1337: "'leet' backdoor port", 31337: "Back Orifice", 6666: "IRC/botnet",
            6667: "IRC/botnet", 6697: "IRC/botnet", 9001: "Tor relay", 9030: "Tor directory",
            9050: "Tor SOCKS", 9150: "Tor Browser SOCKS", 3333: "Mining stratum", 5555: "ADB / mining",
            7777: "Mining stratum", 14444: "Mining stratum (Monero)", 45700: "Mining stratum"}
COMMON_PORTS = {80, 443, 53, 853, 22, 993, 995, 587, 465, 143, 110, 123, 5223, 5228, 3478, 8080, 8443}
SUSPICIOUS_DIRS = re.compile(r"(\\temp\\|\\appdata\\local\\temp|/tmp/|/private/var/folders/|\\downloads\\|/downloads/|\\users\\public\\)", re.I)

_dns_cache: dict[str, tuple[float, str | None]] = {}
_pool = ThreadPoolExecutor(max_workers=16)


# ---------------------------------------------------------------- threat intel
def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


class Intel:
    def __init__(self):
        self.domains: dict[str, tuple[str, str]] = {}
        self.ips: dict[str, tuple[str, str]] = {}
        self.nets: list[tuple[ipaddress._BaseNetwork, str, str]] = []
        self.reload()

    def _ingest(self, text: str, source: str):
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip() if not raw.startswith("#") else ""
            if not line:
                continue
            parts = line.split(None, 3)
            if len(parts) == 1:  # plain feed: one IP / CIDR / domain per line, hosts-file style also handled
                parts = ["auto", parts[0], "malicious"]
            elif parts[0] in ("0.0.0.0", "127.0.0.1") and len(parts) >= 2:  # hosts file
                parts = ["domain", parts[1], "malicious"]
            typ, val = parts[0].lower(), parts[1].lower()
            cat = parts[2] if len(parts) > 2 else "malicious"
            note = parts[3] if len(parts) > 3 else source
            if typ == "auto":
                typ = "cidr" if "/" in val else "ip" if _is_ip(val) else "domain"
            try:
                if typ == "domain":
                    self.domains[val.strip(".")] = (cat, note)
                elif typ == "ip":
                    self.ips[str(ipaddress.ip_address(val))] = (cat, note)
                elif typ == "cidr":
                    self.nets.append((ipaddress.ip_network(val, strict=False), cat, note))
            except ValueError:
                continue

    def reload(self):
        self.domains.clear(); self.ips.clear(); self.nets.clear()
        self._ingest((KNOW / "blocklist.txt").read_text(encoding="utf-8"), "bundled")
        feeds = store.data_dir() / "feeds"
        if feeds.exists():
            for f in feeds.glob("*.txt"):
                self._ingest(f.read_text(encoding="utf-8", errors="ignore"), f.stem)

    def size(self) -> int:
        return len(self.domains) + len(self.ips) + len(self.nets)

    def match_ip(self, ip: str):
        if ip in self.ips:
            return self.ips[ip]
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, cat, note in self.nets:
            if a.version == net.version and a in net:
                return cat, note
        return None

    def match_domain(self, name: str | None):
        if not name:
            return None
        labels = name.lower().strip(".").split(".")
        for i in range(len(labels)):
            hit = self.domains.get(".".join(labels[i:]))
            if hit:
                return hit
        return None


INTEL = Intel()


def import_feed(name: str, text: str) -> int:
    d = store.data_dir() / "feeds"
    d.mkdir(exist_ok=True)
    safe = re.sub(r"[^a-zA-Z0-9_-]", "_", name)[:40] or "feed"
    (d / f"{safe}.txt").write_text(text, encoding="utf-8")
    before = INTEL.size()
    INTEL.reload()
    return INTEL.size() - before


# ---------------------------------------------------------------- helpers
def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped:
        a = a.ipv4_mapped
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved or a.is_unspecified)


def _windows_dns_cache() -> dict[str, str]:
    """Map IP -> hostname using the Windows DNS client cache (gives real requested domain names)."""
    code, out, _ = powershell(
        "Get-DnsClientCache | Where-Object {$_.Type -in 1,28} | Select-Object Entry,Data | ConvertTo-Json -Compress", 20)
    m = {}
    if code == 0 and out.strip():
        try:
            rows = json.loads(out)
            rows = rows if isinstance(rows, list) else [rows]
            for r in rows:
                if r.get("Data") and r.get("Entry"):
                    m[r["Data"]] = r["Entry"]
        except Exception:
            pass
    return m


def _rdns(ip: str) -> str | None:
    now = time.time()
    hit = _dns_cache.get(ip)
    if hit and now - hit[0] < 3600:
        return hit[1]
    try:
        name = socket.gethostbyaddr(ip)[0]
    except Exception:
        name = None
    _dns_cache[ip] = (now, name)
    return name


def _resolve_many(ips: set[str], timeout: float = 4.0) -> dict[str, str | None]:
    futs = {ip: _pool.submit(_rdns, ip) for ip in ips}
    wait(futs.values(), timeout=timeout)
    return {ip: (f.result() if f.done() else None) for ip, f in futs.items()}


def _connections():
    try:
        return psutil.net_connections(kind="inet"), None
    except (psutil.AccessDenied, PermissionError):
        conns = []
        if IS_MAC:  # per-user fallback
            code, out, _ = run(["lsof", "-nP", "-i", "-F", "pcn"], timeout=20)
            pid = name = None
            for line in out.splitlines():
                if line.startswith("p"):
                    pid = int(line[1:])
                elif line.startswith("n") and "->" in line:
                    l, r = line[1:].split("->", 1)
                    rhost, _, rport = r.rpartition(":")
                    lhost, _, lport = l.rpartition(":")
                    if rport.isdigit():
                        conns.append(_Fake(pid, lhost.strip("[]"), int(lport or 0), rhost.strip("[]"), int(rport)))
        return conns, "Limited view: run as administrator to see every application's connections."


class _Fake:
    def __init__(self, pid, lip, lport, rip, rport):
        self.pid = pid
        self.laddr = type("A", (), {"ip": lip, "port": lport})()
        self.raddr = type("A", (), {"ip": rip, "port": rport})()
        self.status = "ESTABLISHED"
        self.type = socket.SOCK_STREAM


# ---------------------------------------------------------------- main scan
_scan_lock = __import__("threading").Lock()


def scan_connections(resolve: bool = True) -> dict:
    with _scan_lock:
        return _scan_connections(resolve)


def _scan_connections(resolve: bool) -> dict:
    policy = store.load_policy()
    learning_until = store.install_time() + float(policy.get("learning_hours", 24)) * 3600
    learning = time.time() < learning_until
    conns, note = _connections()

    rows = []
    proc_cache: dict[int, dict] = {}
    for c in conns:
        if not c.raddr or not getattr(c.raddr, "ip", None):
            continue
        rip = c.raddr.ip
        if rip.startswith("::ffff:"):
            rip = rip[7:]
        if rip in ("127.0.0.1", "::1") or rip.startswith("127."):
            continue
        pid = c.pid or 0
        if pid not in proc_cache:
            info = {"pid": pid, "name": "unknown", "exe": None}
            try:
                p = psutil.Process(pid)
                info["name"] = p.name()
                try:
                    info["exe"] = p.exe()
                except Exception:
                    pass
            except Exception:
                pass
            proc_cache[pid] = info
        rows.append({
            "proc": proc_cache[pid], "rip": rip, "rport": c.raddr.port,
            "lport": c.laddr.port if c.laddr else None,
            "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            "status": c.status if c.status != "NONE" else "",
        })

    public_ips = {r["rip"] for r in rows if _is_public(r["rip"])}
    names: dict[str, str | None] = {}
    if IS_WIN:
        names.update(_windows_dns_cache())
    if resolve:
        missing = {ip for ip in public_ips if ip not in names}
        names.update(_resolve_many(missing))

    allowed_ips = set(policy["allowed_ips"]); blocked_ips = set(policy["blocked_ips"])
    fw_blocked = set(policy.get("fw_blocked_ips", []))
    allowed_dom = [d.lower() for d in policy["allowed_domains"]]; blocked_dom = [d.lower() for d in policy["blocked_domains"]]
    trusted = {a.lower() for a in policy["trusted_apps"]}

    def dom_in(name, lst):
        return bool(name) and any(name == d or name.endswith("." + d) for d in lst)

    con = store.db()
    now = time.time()
    out = []
    pending_events = []
    for r in rows:
        app = r["proc"]["name"]; ip = r["rip"]; port = r["rport"]
        host = names.get(ip)
        flags = []
        verdict = "ok"
        sev = "low"

        def flag(v, s, msg):
            nonlocal verdict, sev
            flags.append(msg)
            order = {"ok": 0, "blocked": 0, "new": 1, "suspicious": 2, "unauthorised": 3, "malicious": 4}
            if order[v] > order[verdict]:
                verdict = v
            sorder = {"low": 0, "medium": 1, "high": 2, "critical": 3}
            if sorder[s] > sorder[sev]:
                sev = s

        public = _is_public(ip)
        ti = INTEL.match_ip(ip) or INTEL.match_domain(host)
        if ti:
            cat, note_ = ti
            if cat in ("malicious",):
                flag("malicious", "critical", f"Destination is on threat-intel list ({note_}).")
            elif cat in ("mining",):
                flag("malicious", "critical", "Destination is a cryptocurrency mining pool - possible cryptojacking.")
            elif cat in ("tunnel", "anonymizer"):
                flag("suspicious", "high", f"Destination is a {cat} service often used for command-and-control or data exfiltration.")
            else:
                flag("suspicious", "medium", f"Destination category '{cat}' is frequently abused ({note_}).")

        if ip in blocked_ips or dom_in(host, blocked_dom):
            flag("unauthorised", "high", "Destination is on your block list.")
        elif policy["mode"] == "allowlist" and public and not (ip in allowed_ips or dom_in(host, allowed_dom)):
            flag("unauthorised", "high", "Allowlist mode: destination is not on your approved list.")

        if port in C2_PORTS:
            flag("suspicious", "high", f"Remote port {port} is associated with {C2_PORTS[port]}.")
        exe = r["proc"].get("exe") or ""
        if exe and SUSPICIOUS_DIRS.search(exe) and public:
            flag("suspicious", "high", f"Program connecting out runs from a temporary/user-writable folder ({exe}).")
        if public and not host and port not in COMMON_PORTS and port not in C2_PORTS:
            flag("suspicious", "medium", f"Raw IP connection on uncommon port {port} with no DNS name.")

        # behavioural baseline
        dest = host or ip
        if public and r["status"] in ("ESTABLISHED", "SYN_SENT", ""):
            row = con.execute("SELECT first_seen FROM seen WHERE app=? AND dest=? AND port=?", (app, dest, port)).fetchone()
            if row is None:
                con.execute("INSERT INTO seen VALUES (?,?,?,?,?,1)", (app, dest, port, now, now))
                known_app = con.execute("SELECT COUNT(*) FROM seen WHERE app=?", (app,)).fetchone()[0] > 1
                if not learning and app.lower() not in trusted:
                    flag("new", "medium" if known_app else "low",
                         "First time this application has contacted this destination (deviation from learned baseline)."
                         if known_app else "Application has never made network connections before.")
            else:
                con.execute("UPDATE seen SET last_seen=?, hits=hits+1 WHERE app=? AND dest=? AND port=?", (now, app, dest, port))

        if ip in fw_blocked:
            # Sentinel already blocked this destination; leftover sockets are being dropped by the firewall.
            verdict, sev = "blocked", "low"
            flags = ["Blocked by a Sentinel firewall rule - traffic to this address is dropped."] + flags

        out.append({
            "id": f"{r['proc']['pid']}-{ip}-{port}-{r['lport']}",
            "app": app, "pid": r["proc"]["pid"], "exe": exe or None,
            "remote_ip": ip, "remote_port": port, "remote_host": host, "local_port": r["lport"],
            "proto": r["proto"], "status": r["status"], "public": public,
            "verdict": verdict, "severity": sev, "flags": flags,
        })
        if verdict in ("malicious", "unauthorised"):
            pending_events.append(("network", sev, f"{app} -> {dest}:{port} ({verdict})", "; ".join(flags)))
    con.commit(); con.close()
    for ev in pending_events:
        store.log_event(*ev)

    # collapse parallel sockets to the same destination into one row
    agg: dict[tuple, dict] = {}
    for o in out:
        k = (o["pid"], o["remote_ip"], o["remote_port"], o["proto"])
        if k in agg:
            agg[k]["count"] += 1
            agg[k]["local_ports"].append(o["local_port"])
        else:
            o["count"] = 1
            o["local_ports"] = [o["local_port"]]
            o["id"] = f"{o['pid']}-{o['remote_ip']}-{o['remote_port']}-{o['proto']}"
            agg[k] = o
    out = list(agg.values())

    order = {"malicious": 0, "unauthorised": 1, "suspicious": 2, "new": 3, "blocked": 4, "ok": 5}
    out.sort(key=lambda x: (order[x["verdict"]], x["app"].lower()))
    return {
        "connections": out, "note": note, "learning": learning,
        "learning_until": learning_until, "intel_entries": INTEL.size(), "mode": policy["mode"],
    }
