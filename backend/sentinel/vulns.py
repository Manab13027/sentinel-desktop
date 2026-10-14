"""System security-configuration audit (Windows / macOS / Linux) + vulnerable-software matching."""
from __future__ import annotations

import datetime as dt
import json
import platform
import re
from pathlib import Path

from . import inventory
from .platform_utils import IS_LINUX, IS_MAC, IS_WIN, is_admin, powershell, run

KNOW = Path(__file__).parent / "knowledge"
LIFE = json.loads((KNOW / "os_lifecycle.json").read_text(encoding="utf-8"))


def F(fid, category, title, severity, status, detail, fix_id=None, **extra):
    return {"id": fid, "category": category, "title": title, "severity": severity,
            "status": status, "detail": detail, "fix_id": fix_id if status == "fail" else None, **extra}


# ------------------------------------------------------------------ Windows
WIN_PS = r"""
$r = @{}
function T($k, $sb) { try { $r[$k] = & $sb } catch { $r[$k] = "ERR: " + $_.Exception.Message } }
T 'build'      { [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber }
T 'ubr'        { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR }
T 'product'    { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').ProductName }
T 'display'    { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion }
T 'firewall'   { Get-NetFirewallProfile | ForEach-Object { @{name=$_.Name; enabled=[bool]$_.Enabled} } }
T 'defender'   { $m = Get-MpComputerStatus; @{av=$m.AntivirusEnabled; rtp=$m.RealTimeProtectionEnabled; tamper=$m.IsTamperProtected; sigAge=$m.AntivirusSignatureAge} }
T 'smb1'       { (Get-SmbServerConfiguration).EnableSMB1Protocol }
T 'rdp'        { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections }
T 'nla'        { (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication }
T 'uac'        { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA }
T 'guest'      { (Get-LocalUser -Name Guest -ErrorAction Stop).Enabled }
T 'autorun'    { (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -ErrorAction Stop).NoDriveTypeAutoRun }
T 'llmnr'      { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -ErrorAction Stop).EnableMulticast }
T 'bitlocker'  { (Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop).ProtectionStatus.ToString() }
T 'secureboot' { Confirm-SecureBootUEFI }
T 'psv2'       { (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -ErrorAction Stop).State.ToString() }
T 'lasthotfix' { (Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn.ToString('yyyy-MM-dd') }
T 'wuauto'     { (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -ErrorAction Stop).NoAutoUpdate }
$r | ConvertTo-Json -Depth 4 -Compress
"""

WIN_UPDATES_PS = r"""
$s = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
$res = $s.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
$res.Updates | ForEach-Object { @{title=$_.Title; kb=($_.KBArticleIDs -join ','); severity=$_.MsrcSeverity; security=[bool]($_.Categories | Where-Object { $_.Name -match 'Security' })} } | ConvertTo-Json -Compress
"""


def _err(v):
    return isinstance(v, str) and v.startswith("ERR")


def audit_windows(deep: bool) -> list[dict]:
    code, out, err = powershell(WIN_PS, timeout=90)
    try:
        d = json.loads(out)
    except Exception:
        return [F("win-audit", "System", "Windows audit could not run", "medium", "unknown", (err or out)[:500])]
    res = []

    build = d.get("build") if isinstance(d.get("build"), int) else 0
    name = f"{d.get('product')} {d.get('display') or ''} (build {build}.{d.get('ubr')})"
    life = next((x for x in LIFE["windows_builds"] if x["min_build"] <= build <= x["max_build"]), None)
    if life:
        eos = dt.date.fromisoformat(life["eos"])
        days = (eos - dt.date.today()).days
        if days < 0:
            res.append(F("win-eos", "Operating system", f"{life['name']} is out of support", "critical", "fail",
                         life.get("note") or f"Security updates ended {life['eos']}. Upgrade to a supported Windows 11 release.",
                         "upgrade_os", os_name=name))
        elif days < 60:
            res.append(F("win-eos", "Operating system", f"{life['name']} support ends in {days} days", "medium", "fail",
                         f"Plan the feature update before {life['eos']}.", "upgrade_os", os_name=name))
        else:
            res.append(F("win-eos", "Operating system", f"{name} is supported", "low", "pass", f"Supported until {life['eos']}."))

    fw = d.get("firewall")
    if isinstance(fw, list) or isinstance(fw, dict):
        fw = fw if isinstance(fw, list) else [fw]
        off = [p["name"] for p in fw if not p.get("enabled")]
        res.append(F("win-firewall", "Firewall", "Windows Firewall disabled on: " + ", ".join(off) if off else "Windows Firewall enabled on all profiles",
                     "critical" if off else "low", "fail" if off else "pass",
                     "A disabled firewall exposes every listening port to the network." if off else "Domain, Private and Public profiles are on.",
                     "enable_firewall"))

    df = d.get("defender")
    if isinstance(df, dict):
        if not df.get("av") or not df.get("rtp"):
            res.append(F("win-defender", "Antivirus", "Microsoft Defender real-time protection is off", "critical", "fail",
                         "Real-time scanning is the main defence against malware execution. (Ignore if another AV is installed and active.)",
                         "enable_defender"))
        else:
            res.append(F("win-defender", "Antivirus", "Defender real-time protection is on", "low", "pass", ""))
        if isinstance(df.get("sigAge"), int) and df["sigAge"] > 7:
            res.append(F("win-defsig", "Antivirus", f"Antivirus signatures are {df['sigAge']} days old", "high", "fail",
                         "Out-of-date signatures miss recent malware.", "update_defender"))
        if df.get("tamper") is False:
            res.append(F("win-tamper", "Antivirus", "Defender Tamper Protection is off", "medium", "fail",
                         "Malware can switch off Defender. Enable it in Windows Security > Virus & threat protection settings.", "manual_tamper"))

    if d.get("smb1") is True:
        res.append(F("win-smb1", "Network services", "SMBv1 protocol is enabled", "critical", "fail",
                     "SMBv1 is exploited by WannaCry/NotPetya (EternalBlue, MS17-010).", "disable_smb1"))
    elif d.get("smb1") is False:
        res.append(F("win-smb1", "Network services", "SMBv1 is disabled", "low", "pass", ""))

    if d.get("rdp") == 0:
        nla = d.get("nla") == 1
        res.append(F("win-rdp", "Remote access", "Remote Desktop is enabled" + ("" if nla else " WITHOUT Network Level Authentication"),
                     "medium" if nla else "critical", "fail",
                     "RDP is the most common ransomware entry point. Disable it unless you need it; if you do, require NLA and a VPN.",
                     "disable_rdp"))
    elif d.get("rdp") == 1:
        res.append(F("win-rdp", "Remote access", "Remote Desktop is disabled", "low", "pass", ""))

    if d.get("uac") == 0:
        res.append(F("win-uac", "Accounts", "User Account Control is disabled", "high", "fail",
                     "Without UAC every program runs with full admin rights.", "enable_uac"))
    if d.get("guest") is True:
        res.append(F("win-guest", "Accounts", "Guest account is enabled", "high", "fail", "Allows unauthenticated local access.", "disable_guest"))
    if d.get("autorun") != 255:
        res.append(F("win-autorun", "Hardening", "AutoRun is not disabled for all drives", "low", "fail",
                     "USB malware can launch automatically.", "disable_autorun"))
    if d.get("llmnr") != 0:
        res.append(F("win-llmnr", "Network services", "LLMNR name resolution is enabled", "medium", "fail",
                     "Attackers on the LAN can poison LLMNR to capture password hashes (Responder).", "disable_llmnr"))
    bl = d.get("bitlocker")
    if bl == "Off":
        res.append(F("win-bitlocker", "Encryption", "System drive is not encrypted (BitLocker off)", "high", "fail",
                     "A lost or stolen device exposes all data.", "enable_bitlocker"))
    elif bl == "On":
        res.append(F("win-bitlocker", "Encryption", "BitLocker protects the system drive", "low", "pass", ""))
    if d.get("secureboot") is False:
        res.append(F("win-secureboot", "Boot integrity", "Secure Boot is disabled", "medium", "fail",
                     "Bootkits can load before Windows. Enable Secure Boot in UEFI firmware settings.", "manual_secureboot"))
    if d.get("psv2") == "Enabled":
        res.append(F("win-psv2", "Hardening", "PowerShell 2.0 engine is installed", "medium", "fail",
                     "Attackers downgrade to PowerShell 2.0 to bypass logging and AMSI.", "disable_psv2"))
    if d.get("wuauto") == 1:
        res.append(F("win-wuauto", "Patching", "Automatic Windows Update is disabled by policy", "high", "fail", "", "enable_wu"))
    lh = d.get("lasthotfix")
    if isinstance(lh, str) and re.match(r"\d{4}-\d{2}-\d{2}$", lh):
        age = (dt.date.today() - dt.date.fromisoformat(lh)).days
        res.append(F("win-patchage", "Patching", f"Last Windows update installed {age} days ago ({lh})",
                     "high" if age > 45 else "low", "fail" if age > 45 else "pass",
                     "Microsoft releases security fixes every second Tuesday; more than ~45 days means at least one missed cycle.",
                     "windows_update"))

    if deep:
        code, out, err = powershell(WIN_UPDATES_PS, timeout=240)
        try:
            ups = json.loads(out) if out.strip() else []
            ups = ups if isinstance(ups, list) else [ups]
            for u in ups:
                sev = (u.get("severity") or "").lower()
                s = "critical" if sev == "critical" else "high" if sev == "important" or u.get("security") else "medium"
                res.append(F(f"win-kb-{u.get('kb') or abs(hash(u['title'])) % 10**6}", "Missing patches", u["title"], s, "fail",
                             f"KB{u.get('kb')} is available but not installed.", "windows_update"))
            if not ups:
                res.append(F("win-pending", "Missing patches", "No pending Windows updates found", "low", "pass",
                             "Note: the update search uses Windows' cached catalogue when offline."))
        except Exception:
            res.append(F("win-pending", "Missing patches", "Could not query Windows Update", "low", "unknown", (err or out)[:300]))
    return res


# ------------------------------------------------------------------ macOS
def _rd(domain, key):
    code, out, _ = run(["defaults", "read", domain, key], timeout=10)
    return out.strip() if code == 0 else None


def audit_macos(deep: bool, open_ports: set[int]) -> list[dict]:
    res = []
    ver = platform.mac_ver()[0]
    major = int(ver.split(".")[0]) if ver else 0
    if major and major < LIFE["macos_min_supported_major"]:
        res.append(F("mac-eos", "Operating system", f"macOS {ver} no longer receives full security updates", "critical", "fail",
                     LIFE["macos_note"], "upgrade_os", os_name=f"macOS {ver}"))
    elif major:
        res.append(F("mac-eos", "Operating system", f"macOS {ver} is a supported release", "low", "pass", ""))

    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    _, out, _ = run([fw, "--getglobalstate"], 10)
    on = "enabled" in out.lower() or "state = 1" in out.lower() or "state = 2" in out.lower()
    res.append(F("mac-firewall", "Firewall", "Application Firewall is " + ("on" if on else "OFF"),
                 "low" if on else "high", "pass" if on else "fail",
                 "" if on else "Incoming connections to any app are allowed.", "enable_firewall"))
    _, out, _ = run([fw, "--getstealthmode"], 10)
    st = "enabled" in out.lower() or "on" in out.lower().split()
    if not st:
        res.append(F("mac-stealth", "Firewall", "Firewall stealth mode is off", "low", "fail",
                     "The Mac answers pings/probes, making it easier to discover on hostile networks.", "enable_stealth"))

    _, out, _ = run(["fdesetup", "status"], 10)
    fv = "is On" in out
    res.append(F("mac-filevault", "Encryption", "FileVault disk encryption is " + ("on" if fv else "OFF"),
                 "low" if fv else "high", "pass" if fv else "fail", "" if fv else "A lost or stolen Mac exposes all data.", "enable_filevault"))

    _, out, _ = run(["csrutil", "status"], 10)
    sip = "enabled" in out.lower()
    res.append(F("mac-sip", "Boot integrity", "System Integrity Protection is " + ("enabled" if sip else "DISABLED"),
                 "low" if sip else "critical", "pass" if sip else "fail",
                 "" if sip else "SIP protects system files from modification even by root. Re-enable from Recovery: csrutil enable.", "manual_sip"))

    _, out, err = run(["spctl", "--status"], 10)
    gk = "enabled" in (out + err).lower()
    res.append(F("mac-gatekeeper", "Hardening", "Gatekeeper is " + ("enabled" if gk else "DISABLED"),
                 "low" if gk else "high", "pass" if gk else "fail", "" if gk else "Unsigned/unnotarised apps can run without warning.", "enable_gatekeeper"))

    su = "/Library/Preferences/com.apple.SoftwareUpdate"
    auto = {k: _rd(su, k) for k in ("AutomaticCheckEnabled", "CriticalUpdateInstall", "ConfigDataInstall", "AutomaticallyInstallMacOSUpdates")}
    bad = [k for k in ("AutomaticCheckEnabled", "CriticalUpdateInstall", "ConfigDataInstall") if auto[k] == "0"]
    res.append(F("mac-autoupdate", "Patching", "Automatic security updates are " + ("partly disabled" if bad else "on"),
                 "high" if bad else "low", "fail" if bad else "pass",
                 ("Disabled: " + ", ".join(bad) + ". Rapid Security Responses and XProtect updates will not install.") if bad else "",
                 "enable_autoupdate"))

    if _rd("/Library/Preferences/com.apple.loginwindow", "GuestEnabled") == "1":
        res.append(F("mac-guest", "Accounts", "Guest user is enabled", "medium", "fail", "", "disable_guest"))
    if _rd("/Library/Preferences/com.apple.loginwindow", "autoLoginUser"):
        res.append(F("mac-autologin", "Accounts", "Automatic login is enabled", "high", "fail",
                     "Anyone who powers on the Mac is logged in without a password.", "disable_autologin"))

    if 22 in open_ports:
        res.append(F("mac-ssh", "Remote access", "Remote Login (SSH) is on", "medium", "fail",
                     "Disable in System Settings > General > Sharing unless you need it.", "disable_ssh"))
    if 5900 in open_ports:
        res.append(F("mac-vnc", "Remote access", "Screen Sharing / Remote Management is on", "high", "fail", "", "disable_screensharing"))
    if 445 in open_ports:
        res.append(F("mac-smb", "Network services", "File Sharing (SMB) is on", "medium", "fail", "", "disable_filesharing"))

    if deep:
        code, out, err = run(["softwareupdate", "-l"], timeout=180)
        text = out + err
        items = re.findall(r"\* Label: (.+)\n\s*Title: ([^,]+)", text)
        if items:
            for label, title in items:
                res.append(F(f"mac-su-{re.sub(r'[^a-z0-9]', '', label.lower())[:30]}", "Missing patches",
                             f"Update available: {title.strip()}", "high", "fail", f"Label: {label.strip()}",
                             "macos_update", fix_args={"label": label.strip()}))
        elif "No new software available" in text:
            res.append(F("mac-pending", "Missing patches", "macOS is up to date", "low", "pass", ""))
        else:
            res.append(F("mac-pending", "Missing patches", "Could not check Apple updates (offline?)", "low", "unknown", text[:300]))
    return res


# ------------------------------------------------------------------ Linux (dev/test)
def audit_linux(deep: bool, open_ports: set[int]) -> list[dict]:
    res = []
    code, out, _ = run(["ufw", "status"], 10)
    if code == 0:
        on = "Status: active" in out
        res.append(F("lx-firewall", "Firewall", "UFW firewall is " + ("active" if on else "inactive"), "low" if on else "high",
                     "pass" if on else "fail", "", "enable_firewall"))
    if 22 in open_ports:
        res.append(F("lx-ssh", "Remote access", "SSH server is listening", "medium", "fail", "Ensure key-only auth.", "disable_ssh"))
    return res


def audit(deep: bool = False, open_ports: set[int] | None = None) -> dict:
    open_ports = open_ports or set()
    if IS_WIN:
        sys_findings = audit_windows(deep)
    elif IS_MAC:
        sys_findings = audit_macos(deep, open_ports)
    else:
        sys_findings = audit_linux(deep, open_ports)
    apps = inventory.list_apps()
    cves = inventory.match_cves(apps)
    db = inventory.load_cve_db()
    return {
        "findings": sys_findings + cves,
        "apps_scanned": len(apps),
        "cve_db_entries": len(db["entries"]),
        "cve_db_updated": db.get("updated"),
        "admin": is_admin(),
        "apps": apps,
    }
