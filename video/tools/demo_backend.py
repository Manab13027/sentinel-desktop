"""Sentinel engine with realistic, scripted Windows demo data for recording the tutorial video.

Real server/UI code paths are used; only the OS probes are replaced with fixtures, and fixes/blocks
update that fixture state so the UI reacts exactly as it would on a real machine.
"""
import sys
import time

sys.path.insert(0, "/home/claude/sentinel-desktop/backend")
sys.argv = ["server", "--port", sys.argv[1] if len(sys.argv) > 1 else "8781", "--token", "demo", "--no-monitor"]

import server  # noqa: E402
from sentinel import advisor, inventory, network, platform_utils, ports, remediation, store, vulns  # noqa: E402

# ------------------------------------------------------------- pretend to be Windows 11
for mod in (remediation, advisor, inventory):
    mod.os_key = lambda: "windows"
server.platform_utils.host_info = lambda: {
    "hostname": "FIGHTER-PC", "os": "Windows", "os_key": "windows", "os_release": "11",
    "os_version": "11 Pro 23H2", "arch": "AMD64", "python": "3.12", "admin": True}
store.meta_set("install_time", str(time.time() - 3 * 86400))  # baseline already learned

FIXED: set[str] = set()
F = vulns.F

PASS_TITLES = {
    "win-firewall": "Windows Firewall enabled on all profiles",
    "win-smb1": "SMBv1 is disabled",
    "win-rdp": "Remote Desktop is disabled",
    "win-llmnr": "LLMNR is disabled",
    "win-autorun": "AutoRun is disabled for all drives",
}


def fake_audit(deep=False, open_ports=None):
    fs = [
        F("win-eos", "Operating system", "Windows 11 23H2 is out of support", "critical", "fail",
          "Security updates for this release ended on 11 Nov 2025. Upgrade to Windows 11 25H2.", "upgrade_os"),
        F("win-firewall", "Firewall", "Windows Firewall disabled on: Public", "critical", "fail",
          "A disabled firewall exposes every listening port to anyone on the same network.", "enable_firewall"),
        F("win-smb1", "Network services", "SMBv1 protocol is enabled", "critical", "fail",
          "SMBv1 is exploited by WannaCry and NotPetya (EternalBlue, MS17-010).", "disable_smb1"),
        F("win-rdp", "Remote access", "Remote Desktop is enabled", "medium", "fail",
          "RDP is the most common ransomware entry point.", "disable_rdp"),
        F("win-llmnr", "Network services", "LLMNR name resolution is enabled", "medium", "fail",
          "Attackers on the LAN can poison LLMNR to capture password hashes.", "disable_llmnr"),
        F("win-bitlocker", "Encryption", "System drive is not encrypted (BitLocker off)", "high", "fail",
          "A lost or stolen laptop exposes all of its data.", "enable_bitlocker"),
        F("win-patchage", "Patching", "Last Windows update installed 71 days ago", "high", "fail",
          "Microsoft ships security fixes every month; 71 days means at least two missed cycles.", "windows_update"),
        F("win-defender", "Antivirus", "Defender real-time protection is on", "low", "pass", ""),
        F("win-uac", "Accounts", "User Account Control is enabled", "low", "pass", ""),
    ]
    if deep:
        fs += [
            F("win-kb-5044285", "Missing patches", "2026-10 Cumulative Update for Windows 11 23H2 (KB5044285)", "critical", "fail",
              "KB5044285 is available but not installed.", "windows_update"),
            F("win-kb-890830", "Missing patches", "Windows Malicious Software Removal Tool x64 - v5.130 (KB890830)", "high", "fail",
              "KB890830 is available but not installed.", "windows_update"),
            F("win-kb-2267602", "Missing patches", "Security Intelligence Update for Microsoft Defender (KB2267602)", "high", "fail",
              "KB2267602 is available but not installed.", "windows_update"),
        ]
    for f in fs:
        if f["id"] in FIXED:
            f.update(status="pass", severity="low", fix_id=None, title=PASS_TITLES.get(f["id"], f["title"]), detail="")
    apps = [{"name": "Google Chrome", "version": "114.0.5735.199", "source": "registry"},
            {"name": "7-Zip 23.01 (x64)", "version": "23.01", "source": "registry"},
            {"name": "PuTTY release 0.79 (64-bit)", "version": "0.79.0.0", "source": "registry"},
            {"name": "VLC media player", "version": "3.0.21", "source": "registry"}]
    cves = [c for c in inventory.match_cves(apps) if c["id"] not in FIXED]
    return {"findings": fs + cves, "apps_scanned": 184, "cve_db_entries": 14, "cve_db_updated": "2026-10-01",
            "admin": True, "apps": apps}


vulns.audit = fake_audit


def fake_apply_fix(fix_id, args=None):
    time.sleep(3.5)
    for k, fid in {"win-firewall": "enable_firewall", "win-smb1": "disable_smb1", "win-rdp": "disable_rdp",
                   "win-llmnr": "disable_llmnr"}.items():
        if fid == fix_id:
            FIXED.add(k)
    store.log_action(fix_id, "{}", True, "ok")
    return {"ok": True, "code": 0, "output": "Completed successfully."}


remediation.apply_fix = fake_apply_fix


# ------------------------------------------------------------- ports
def P(port, proto, name, exe, pid, user, exposure, parent="services.exe"):
    proc = {"pid": pid, "name": name, "exe": exe, "user": user, "cmdline": exe, "parent": parent}
    sc = ports.score_port(port, proto, exposure, proc)
    return {"id": f"{proto}-{port}-{pid}", "proto": proto, "port": port,
            "addresses": ["127.0.0.1"] if exposure == "loopback" else ["0.0.0.0"], "exposure": exposure,
            "process": proc, "blocked": False, **sc}


def fake_ports():
    rows = [
        P(4444, "TCP", "svc_helper.exe", r"C:\Users\Fighter\AppData\Local\Temp\svc_helper.exe", 6612, "Fighter", "all-interfaces", "explorer.exe"),
        P(445, "TCP", "System", None, 4, "SYSTEM", "all-interfaces", "-"),
        P(3389, "TCP", "svchost.exe", r"C:\Windows\System32\svchost.exe", 1120, "NETWORK SERVICE", "all-interfaces"),
        P(139, "TCP", "System", None, 4, "SYSTEM", "network", "-"),
        P(135, "TCP", "svchost.exe", r"C:\Windows\System32\svchost.exe", 988, "NETWORK SERVICE", "all-interfaces"),
        P(1900, "UDP", "svchost.exe", r"C:\Windows\System32\svchost.exe", 2216, "LOCAL SERVICE", "all-interfaces"),
        P(8080, "TCP", "node.exe", r"C:\Program Files\nodejs\node.exe", 9120, "Fighter", "all-interfaces", "Code.exe"),
        P(5353, "UDP", "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe", 7012, "Fighter", "all-interfaces", "explorer.exe"),
        P(7680, "TCP", "svchost.exe", r"C:\Windows\System32\svchost.exe", 3304, "NETWORK SERVICE", "all-interfaces"),
        P(49664, "TCP", "lsass.exe", r"C:\Windows\System32\lsass.exe", 812, "SYSTEM", "loopback", "wininit.exe"),
        P(5040, "TCP", "svchost.exe", r"C:\Windows\System32\svchost.exe", 5040, "SYSTEM", "loopback"),
        P(27017, "TCP", "mongod.exe", r"C:\Program Files\MongoDB\Server\7.0\bin\mongod.exe", 4410, "SYSTEM", "loopback"),
    ]
    blocked = set(store.load_policy().get("fw_blocked_ports", []))
    for r in rows:
        if f"{r['proto']}/{r['port']}" in blocked:
            r["blocked"] = True
            r["reasons"].insert(0, "Blocked by a Sentinel firewall rule - other devices can no longer connect to it.")
            r.update(risk=min(r["risk"], 10), severity="low", recommendation="blocked")
    rows.sort(key=lambda x: (-x["risk"], x["port"]))
    return {"ports": rows, "note": None}


ports.scan_ports = fake_ports


def _pol_add(key, val):
    pol = store.load_policy()
    if val not in pol[key]:
        pol[key].append(val)
    store.save_policy({key: pol[key]})


def _pol_del(key, val):
    pol = store.load_policy()
    store.save_policy({key: [x for x in pol[key] if x != val]})


remediation.block_port = lambda port, proto: (_pol_add("fw_blocked_ports", f"{proto}/{port}"), time.sleep(1.2),
                                              {"ok": True, "output": f"Inbound {proto} {port} blocked", "note": None})[-1]
remediation.unblock_port = lambda port, proto: (_pol_del("fw_blocked_ports", f"{proto}/{port}"),
                                                {"ok": True, "output": "Rule removed"})[-1]
remediation.block_ip = lambda ip: (_pol_add("fw_blocked_ips", ip), time.sleep(1.0),
                                   {"ok": True, "output": "Traffic to/from this IP is now blocked."})[-1]
remediation.unblock_ip = lambda ip: (_pol_del("fw_blocked_ips", ip), {"ok": True, "output": "Rule removed"})[-1]
remediation.kill_process = lambda pid: {"ok": True, "output": f"Terminated process {pid}."}
remediation.firewall_rules = lambda: [{"name": f"Sentinel Block {x.replace('/', ' ')}"} for x in store.load_policy()["fw_blocked_ports"]] + \
                                     [{"name": f"Sentinel Block IP {x}"} for x in store.load_policy()["fw_blocked_ips"]]


# ------------------------------------------------------------- connections
def C(app, pid, exe, ip, port, host, verdict="ok", sev="low", flags=(), count=1):
    return {"id": f"{pid}-{ip}-{port}-TCP", "app": app, "pid": pid, "exe": exe, "remote_ip": ip, "remote_port": port,
            "remote_host": host, "local_port": 50000 + pid % 9000, "proto": "TCP", "status": "ESTABLISHED", "public": True,
            "verdict": verdict, "severity": sev, "flags": list(flags), "count": count, "local_ports": []}


TEMP = r"C:\Users\Fighter\AppData\Local\Temp\update.exe"
DL = r"C:\Users\Fighter\Downloads\invoice_viewer.exe"


def fake_conns(resolve=True):
    pol = store.load_policy()
    rows = [
        C("update.exe", 6688, TEMP, "141.94.96.144", 3333, "pool.supportxmr.com", "malicious", "critical", [
            "Destination is a cryptocurrency mining pool - possible cryptojacking.",
            "Remote port 3333 is associated with Mining stratum.",
            f"Program connecting out runs from a temporary/user-writable folder ({TEMP})."]),
        C("invoice_viewer.exe", 7340, DL, "45.137.21.9", 4444, None, "suspicious", "high", [
            "Remote port 4444 is associated with Metasploit default.",
            f"Program connecting out runs from a temporary/user-writable folder ({DL})."]),
        C("python.exe", 5120, r"C:\Users\Fighter\AppData\Local\Programs\Python\Python312\python.exe", "3.125.102.39", 443,
          "7f3a-82-12.ngrok-free.app", "suspicious", "high",
          ["Destination is a tunnel service often used for command-and-control or data exfiltration."]),
        C("OneDrive.exe", 8820, r"C:\Program Files\Microsoft OneDrive\OneDrive.exe", "13.107.42.12", 443,
          "storage-weu.blob.core.windows.net", "new", "medium",
          ["First time this application has contacted this destination (deviation from learned baseline)."]),
        C("chrome.exe", 7012, None, "142.250.183.4", 443, "www.google.com", count=4),
        C("chrome.exe", 7012, None, "20.207.73.82", 443, "github.com", count=2),
        C("Teams.exe", 9312, None, "52.113.194.132", 443, "teams.microsoft.com", count=3),
        C("msedge.exe", 4020, None, "20.190.160.20", 443, "login.microsoftonline.com"),
        C("svchost.exe", 1504, r"C:\Windows\System32\svchost.exe", "13.107.4.50", 443, "fe2cr.update.microsoft.com"),
        C("Spotify.exe", 3388, None, "35.186.224.25", 443, "spclient.wg.spotify.com", count=2),
        C("Zoom.exe", 6020, None, "170.114.52.2", 443, "us05web.zoom.us"),
    ]
    allowed = set(pol["allowed_domains"])
    for r in rows:
        if r["remote_ip"] in pol.get("fw_blocked_ips", []):
            r.update(verdict="blocked", severity="low",
                     flags=["Blocked by a Sentinel firewall rule - traffic to this address is dropped."] + r["flags"])
        elif pol["mode"] == "allowlist" and r["verdict"] in ("ok", "new") and not (
                r["remote_host"] and any(r["remote_host"].endswith(d) for d in allowed)):
            r.update(verdict="unauthorised", severity="high",
                     flags=["Allowlist mode: destination is not on your approved list."] + r["flags"])
    order = {"malicious": 0, "unauthorised": 1, "suspicious": 2, "new": 3, "blocked": 4, "ok": 5}
    rows.sort(key=lambda x: (order[x["verdict"]], x["app"].lower()))
    return {"connections": rows, "note": None, "learning": False, "learning_until": time.time() - 86400,
            "intel_entries": 18342, "mode": pol["mode"]}


network.scan_connections = fake_conns

server.main()
