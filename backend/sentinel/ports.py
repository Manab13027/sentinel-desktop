"""Open-port discovery with owning-application details and risk scoring."""
from __future__ import annotations

import json
import os
import re
import socket
from pathlib import Path

import psutil

from . import store
from .platform_utils import IS_MAC, IS_WIN, run

KB = json.loads((Path(__file__).parent / "knowledge" / "ports.json").read_text(encoding="utf-8"))
KB.pop("_comment", None)

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
WILDCARD = {"0.0.0.0", "::", "*", ""}
SUSPICIOUS_DIRS = re.compile(r"(\\temp\\|\\appdata\\local\\temp|/tmp/|/private/var/folders/|\\downloads\\|/downloads/|\\users\\public\\)", re.I)


def _proc_info(pid: int | None) -> dict:
    info = {"pid": pid, "name": None, "exe": None, "user": None, "cmdline": None, "parent": None}
    if not pid:
        return info
    try:
        p = psutil.Process(pid)
        with p.oneshot():
            info["name"] = p.name()
            try:
                info["exe"] = p.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            try:
                info["user"] = p.username()
            except (psutil.AccessDenied, KeyError):
                pass
            try:
                info["cmdline"] = " ".join(p.cmdline())[:400]
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            try:
                pp = p.parent()
                info["parent"] = pp.name() if pp else None
            except Exception:
                pass
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return info


def _sockets_psutil() -> list[dict]:
    out = []
    for c in psutil.net_connections(kind="inet"):
        is_tcp = c.type == socket.SOCK_STREAM
        if is_tcp and c.status != psutil.CONN_LISTEN:
            continue
        if not is_tcp and c.raddr:  # connected UDP is not a listener
            continue
        if not c.laddr:
            continue
        out.append({"proto": "TCP" if is_tcp else "UDP", "ip": c.laddr.ip, "port": c.laddr.port, "pid": c.pid})
    return out


def _sockets_lsof() -> list[dict]:
    """macOS fallback when psutil needs root for system-wide sockets."""
    out = []
    for flags, proto in ((["-iTCP", "-sTCP:LISTEN"], "TCP"), (["-iUDP"], "UDP")):
        code, stdout, _ = run(["lsof", "-nP", *flags, "-F", "pn"], timeout=20)
        pid = None
        for line in stdout.splitlines():
            if line.startswith("p"):
                pid = int(line[1:])
            elif line.startswith("n"):
                addr = line[1:]
                if "->" in addr:
                    continue
                host, _, port = addr.rpartition(":")
                if port.isdigit():
                    out.append({"proto": proto, "ip": host.strip("[]"), "port": int(port), "pid": pid})
    return out


def _exposure(ips: set[str]) -> str:
    if ips and all(ip in LOOPBACK or ip.startswith("127.") for ip in ips):
        return "loopback"
    if ips & WILDCARD:
        return "all-interfaces"
    return "network"


def score_port(port: int, proto: str, exposure: str, proc: dict) -> dict:
    kb = KB.get(str(port))
    reasons = []
    if kb:
        risk = kb["risk"]
        service = kb["service"]
        reasons.append(kb["why"])
    else:
        service = "Unknown"
        if port < 1024:
            risk = 40
            reasons.append("Privileged port with no known service mapping.")
        elif port >= 49152:
            risk = 15
            reasons.append("Ephemeral/dynamic port, usually opened by an app temporarily.")
        else:
            risk = 25
            reasons.append("Non-standard port; verify the owning application is expected.")

    if exposure == "loopback":
        risk *= 0.2
        reasons.append("Only reachable from this machine (loopback) - low exposure.")
    elif exposure == "all-interfaces":
        reasons.append("Listening on ALL network interfaces - reachable from the network.")
        risk += 5

    exe = (proc.get("exe") or "")
    if exe and SUSPICIOUS_DIRS.search(exe):
        risk += 30
        reasons.append(f"Owning program runs from a temporary/user-writable folder: {exe}")
    if not proc.get("name"):
        risk += 10
        reasons.append("Owning process could not be identified (run as admin for full details).")
    risk = int(max(0, min(100, round(risk))))
    if risk >= 70:
        rec = "close"
    elif risk >= 40:
        rec = "review"
    else:
        rec = "keep"
    if kb and kb["action"] == "close" and exposure != "loopback":
        rec = "close"
    severity = "critical" if risk >= 85 else "high" if risk >= 70 else "medium" if risk >= 40 else "low"
    return {"service": service, "risk": risk, "severity": severity, "recommendation": rec, "reasons": reasons}


def scan_ports() -> dict:
    note = None
    try:
        socks = _sockets_psutil()
    except (psutil.AccessDenied, PermissionError):
        socks = _sockets_lsof() if IS_MAC else []
        note = "Limited view: run Sentinel as administrator to see sockets owned by every user."

    grouped: dict[tuple, dict] = {}
    for s in socks:
        key = (s["proto"], s["port"], s["pid"])
        g = grouped.setdefault(key, {"proto": s["proto"], "port": s["port"], "pid": s["pid"], "ips": set()})
        g["ips"].add(s["ip"])

    blocked = set(store.load_policy().get("fw_blocked_ports", []))
    results = []
    for (proto, port, pid), g in grouped.items():
        proc = _proc_info(pid)
        exposure = _exposure(g["ips"])
        sc = score_port(port, proto, exposure, proc)
        is_blocked = f"{proto}/{port}" in blocked
        if is_blocked:
            # The program still listens, but the firewall now drops incoming connections to it.
            sc["reasons"].insert(0, "Blocked by a Sentinel firewall rule - other devices can no longer connect to it.")
            sc.update(risk=min(sc["risk"], 10), severity="low", recommendation="blocked")
        results.append({
            "id": f"{proto}-{port}-{pid or 0}",
            "proto": proto,
            "port": port,
            "addresses": sorted(g["ips"]),
            "exposure": exposure,
            "process": proc,
            "blocked": is_blocked,
            **sc,
        })
    results.sort(key=lambda r: (-r["risk"], r["port"]))
    return {"ports": results, "note": note}
