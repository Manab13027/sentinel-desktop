"""Remediation playbooks: built-in, offline fix knowledge for every finding type.

Each playbook gives a plain-language explanation, manual steps, and (where safe) a
one-click command set per OS. Commands are fixed templates; the only user-derived
values are integers (ports, PIDs), validated IPs, or names checked against a strict regex.
Nothing here runs unless the user clicks a Fix/Close button and confirms.
"""
from __future__ import annotations

import ipaddress
import json
import re
import time

import psutil

from . import store
from .platform_utils import IS_LINUX, IS_MAC, IS_WIN, is_admin, os_key, powershell, quote, run, run_elevated

PB: dict[str, dict] = {
    # ------------------------------------------------ firewall / AV
    "enable_firewall": {
        "title": "Turn on the firewall",
        "why": "The firewall blocks unsolicited inbound connections to every listening port.",
        "windows": {"cmd": ["Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"],
                    "manual": ["Open Windows Security > Firewall & network protection", "Turn on Domain, Private and Public networks"]},
        "macos": {"cmd": ["/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"],
                  "manual": ["System Settings > Network > Firewall", "Turn Firewall on"]},
        "linux": {"cmd": ["ufw --force enable"], "manual": ["sudo ufw enable"]},
    },
    "enable_stealth": {
        "title": "Enable firewall stealth mode", "why": "Stops the Mac answering network probes.",
        "macos": {"cmd": ["/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on"],
                  "manual": ["System Settings > Network > Firewall > Options", "Enable stealth mode"]},
    },
    "enable_defender": {
        "title": "Enable Microsoft Defender real-time protection", "why": "Blocks malware as files are written or executed.",
        "windows": {"cmd": ["Set-MpPreference -DisableRealtimeMonitoring $false", "Set-MpPreference -DisableIOAVProtection $false"],
                    "manual": ["Windows Security > Virus & threat protection > Manage settings", "Turn on Real-time protection"]},
    },
    "update_defender": {
        "title": "Update antivirus signatures", "why": "New malware is detected only with current definitions.",
        "windows": {"cmd": ["Update-MpSignature"], "manual": ["Windows Security > Virus & threat protection > Protection updates > Check for updates"],
                    "needs_internet": True},
    },
    "manual_tamper": {
        "title": "Enable Tamper Protection", "why": "Prevents malware from disabling Defender. Windows only allows this via the UI.",
        "windows": {"manual": ["Windows Security > Virus & threat protection > Manage settings", "Turn on Tamper Protection"]},
    },
    # ------------------------------------------------ network services
    "disable_smb1": {
        "title": "Disable SMBv1", "why": "Removes the protocol exploited by EternalBlue/WannaCry. Very old NAS/printers may need SMBv2+ enabled on their side.",
        "windows": {"cmd": ["Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
                            "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"],
                    "manual": ["Control Panel > Programs > Turn Windows features on or off", "Untick 'SMB 1.0/CIFS File Sharing Support'"],
                    "undo": ["Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force"]},
    },
    "disable_rdp": {
        "title": "Disable Remote Desktop", "why": "Closes TCP 3389, the most common ransomware entry point.",
        "windows": {"cmd": ["Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1",
                            "Disable-NetFirewallRule -DisplayGroup 'Remote Desktop'"],
                    "manual": ["Settings > System > Remote Desktop", "Turn Remote Desktop off"],
                    "undo": ["Set-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 0"]},
    },
    "disable_llmnr": {
        "title": "Disable LLMNR", "why": "Prevents LAN attackers from poisoning name lookups to steal password hashes.",
        "windows": {"cmd": ["New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null",
                            "Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0 -Type DWord"],
                    "manual": ["gpedit.msc > Computer Configuration > Administrative Templates > Network > DNS Client", "Enable 'Turn off multicast name resolution'"]},
    },
    "disable_psv2": {
        "title": "Remove PowerShell 2.0", "why": "Stops downgrade attacks that bypass script logging.",
        "windows": {"cmd": ["Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart"],
                    "manual": ["Turn Windows features on or off", "Untick 'Windows PowerShell 2.0'"]},
    },
    "disable_ssh": {
        "title": "Turn off Remote Login (SSH)", "why": "Closes port 22 if you don't log in remotely.",
        "macos": {"cmd": ["systemsetup -f -setremotelogin off"], "manual": ["System Settings > General > Sharing", "Turn off Remote Login"]},
        "linux": {"cmd": ["systemctl disable --now ssh || systemctl disable --now sshd"], "manual": ["sudo systemctl disable --now ssh"]},
    },
    "disable_screensharing": {
        "title": "Turn off Screen Sharing / Remote Management", "why": "Closes VNC port 5900.",
        "macos": {"cmd": ["launchctl disable system/com.apple.screensharing", "launchctl bootout system/com.apple.screensharing || true"],
                  "manual": ["System Settings > General > Sharing", "Turn off Screen Sharing and Remote Management"]},
    },
    "disable_filesharing": {
        "title": "Turn off File Sharing", "why": "Closes SMB port 445.",
        "macos": {"cmd": ["launchctl disable system/com.apple.smbd", "launchctl bootout system/com.apple.smbd || true"],
                  "manual": ["System Settings > General > Sharing", "Turn off File Sharing"]},
    },
    # ------------------------------------------------ accounts / hardening
    "enable_uac": {
        "title": "Enable User Account Control", "why": "Programs will need your approval to gain admin rights. Requires restart.",
        "windows": {"cmd": ["Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1"],
                    "manual": ["Control Panel > User Accounts > Change User Account Control settings", "Move the slider to the default level", "Restart"]},
    },
    "disable_guest": {
        "title": "Disable the Guest account", "why": "Removes unauthenticated local access.",
        "windows": {"cmd": ["Disable-LocalUser -Name Guest"], "manual": ["lusrmgr.msc > Users > Guest > Account is disabled"]},
        "macos": {"cmd": ["defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false"],
                  "manual": ["System Settings > Users & Groups > Guest User", "Turn off 'Allow guests to log in'"]},
    },
    "disable_autologin": {
        "title": "Disable automatic login", "why": "Requires a password at startup.",
        "macos": {"cmd": ["defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser"],
                  "manual": ["System Settings > Users & Groups", "Set 'Automatically log in as' to Off"]},
    },
    "disable_autorun": {
        "title": "Disable AutoRun on all drives", "why": "Stops USB/CD malware from launching automatically.",
        "windows": {"cmd": ["New-Item 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Force | Out-Null",
                            "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer' -Name NoDriveTypeAutoRun -Value 255 -Type DWord"],
                    "manual": ["Settings > Bluetooth & devices > AutoPlay", "Turn off 'Use AutoPlay for all media and devices'"]},
    },
    "enable_gatekeeper": {
        "title": "Re-enable Gatekeeper", "why": "Blocks unsigned/unnotarised apps by default.",
        "macos": {"cmd": ["spctl --global-enable || spctl --master-enable"], "manual": ["System Settings > Privacy & Security", "Allow apps from: App Store and identified developers"]},
    },
    "manual_sip": {
        "title": "Re-enable System Integrity Protection", "why": "SIP can only be changed from macOS Recovery.",
        "macos": {"manual": ["Shut down the Mac", "Apple silicon: hold the power button > Options. Intel: hold Cmd+R at startup",
                             "Utilities > Terminal", "Run: csrutil enable", "Restart"]},
    },
    "manual_secureboot": {
        "title": "Enable Secure Boot", "why": "Must be changed in the UEFI firmware.",
        "windows": {"manual": ["Settings > System > Recovery > Advanced startup > Restart now",
                               "Troubleshoot > Advanced options > UEFI Firmware Settings", "Enable Secure Boot, save and exit"]},
    },
    # ------------------------------------------------ encryption
    "enable_bitlocker": {
        "title": "Turn on BitLocker", "why": "Encrypts the system drive. SAVE THE RECOVERY KEY it shows you.",
        "windows": {"manual": ["Control Panel > BitLocker Drive Encryption", "Turn on BitLocker for the system drive",
                               "Back up the recovery key to your Microsoft account, a USB drive, or print it"],
                    "note": "Not automated: you must store the recovery key yourself."},
    },
    "enable_filevault": {
        "title": "Turn on FileVault", "why": "Encrypts the startup disk. SAVE THE RECOVERY KEY.",
        "macos": {"manual": ["System Settings > Privacy & Security > FileVault", "Click Turn On and store the recovery key safely"],
                  "note": "Not automated: you must store the recovery key yourself."},
    },
    # ------------------------------------------------ patching
    "windows_update": {
        "title": "Install pending Windows updates", "why": "Applies Microsoft security patches. A restart may be required.",
        "windows": {"cmd": ["$s=New-Object -ComObject Microsoft.Update.Session",
                            "$r=$s.CreateUpdateSearcher().Search(\"IsInstalled=0 and IsHidden=0 and Type='Software'\")",
                            "if($r.Updates.Count -gt 0){$d=$s.CreateUpdateDownloader();$d.Updates=$r.Updates;$d.Download()|Out-Null;"
                            "$i=$s.CreateUpdateInstaller();$i.Updates=$r.Updates;$x=$i.Install();"
                            "'Installed '+$r.Updates.Count+' update(s). Result code: '+$x.ResultCode+'. Reboot required: '+$x.RebootRequired}else{'No updates pending'}"],
                    "manual": ["Settings > Windows Update > Check for updates", "Install all, then restart"], "needs_internet": True,
                    "timeout": 3600},
    },
    "enable_wu": {
        "title": "Re-enable automatic Windows Update",
        "why": "A policy has switched automatic updates off.",
        "windows": {"cmd": ["Remove-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU' -Name NoAutoUpdate -ErrorAction SilentlyContinue"],
                    "manual": ["If your PC is managed by an organisation, ask IT."]},
    },
    "macos_update": {
        "title": "Install macOS update", "why": "Applies Apple security fixes. May restart the Mac.",
        # Apple silicon only lets the command-line updater install macOS updates with interactive owner
        # credentials, so Sentinel opens Software Update for you instead of hanging in the background.
        "macos": {"open_url": "x-apple.systempreferences:com.apple.Software-Update-Settings.extension",
                  "manual": ["System Settings > General > Software Update", "Click 'Update Now' / 'Restart Now' and enter your password"],
                  "needs_internet": True},
    },
    "enable_autoupdate": {
        "title": "Enable automatic security updates", "why": "Installs Rapid Security Responses and XProtect definitions automatically.",
        "macos": {"cmd": ["defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true",
                          "defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true",
                          "defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true"],
                  "manual": ["System Settings > General > Software Update > Automatic updates (i)", "Enable 'Install Security Responses and system files'"]},
    },
    "upgrade_os": {
        "title": "Upgrade the operating system", "why": "Unsupported OS versions no longer receive security fixes, so new vulnerabilities stay open forever.",
        "windows": {"manual": ["Settings > Windows Update > check for the latest Windows 11 feature update",
                               "If the PC does not meet Windows 11 requirements, consider Extended Security Updates or replacing the device"]},
        "macos": {"manual": ["System Settings > General > Software Update > Upgrade Now",
                             "If your Mac is not supported by the latest macOS, consider replacing it or limiting its network exposure"]},
    },
    "update_app": {
        "title": "Update the vulnerable application", "why": "The installed version contains a publicly known vulnerability fixed in a later release.",
        "windows": {"cmd_template": ["winget upgrade --name {qname} --exact --silent --accept-package-agreements --accept-source-agreements"],
                    "manual": ["Open the app and use Help > Check for updates, or download the latest version from the vendor's official site",
                               "Or run: winget upgrade --all"], "needs_internet": True, "elevate": False, "timeout": 1800},
        "macos": {"cmd_template_brew": ["brew upgrade {name}"],
                  "manual": ["Open the app and use its 'Check for Updates' menu, or update it from the App Store / vendor site"],
                  "needs_internet": True, "elevate": False, "timeout": 1800, "as_user": True},
        "linux": {"cmd_template": ["apt-get install --only-upgrade -y {name}"], "manual": ["sudo apt update && sudo apt upgrade"], "needs_internet": True},
    },
}

NAME_RX = re.compile(r"^[\w .+()\-]{1,80}$")


def playbook(fix_id: str, args: dict | None = None) -> dict | None:
    pb = PB.get(fix_id)
    if not pb:
        return None
    osk = os_key()
    spec = pb.get(osk, {})
    cmds = list(spec.get("cmd", []))
    args = args or {}
    if "cmd_template" in spec or "cmd_template_brew" in spec:
        name = str(args.get("name", "") or args.get("label", ""))
        if NAME_RX.match(name):
            if fix_id == "update_app" and IS_MAC:
                if args.get("source") == "brew":
                    cmds = [c.format(name=quote(name)) for c in spec["cmd_template_brew"]]
            else:
                qn = "'" + name.replace("'", "''") + "'" if IS_WIN else quote(name)
                cmds = [c.format(qname=qn, name=quote(name)) for c in spec["cmd_template"]]
    return {
        "fix_id": fix_id, "title": pb["title"], "why": pb["why"],
        "manual": spec.get("manual", []), "commands": cmds, "automatable": bool(cmds),
        "undo": spec.get("undo", []), "needs_internet": spec.get("needs_internet", False),
        "note": spec.get("note"), "elevate": spec.get("elevate", True),
        "open_url": spec.get("open_url"), "automatable_ui": bool(cmds or spec.get("open_url")),
        "timeout": spec.get("timeout", 300), "as_user": spec.get("as_user", False),
    }


def _console_user() -> str | None:
    """macOS: the logged-in desktop user (used to drop root for tools like Homebrew)."""
    code, out, _ = run(["stat", "-f", "%Su", "/dev/console"], 5)
    u = out.strip()
    return u if code == 0 and re.match(r"^[A-Za-z0-9_.-]+$", u) and u != "root" else None


def apply_fix(fix_id: str, args: dict | None = None) -> dict:
    p = playbook(fix_id, args)
    if not p or not p["automatable"]:
        return {"ok": False, "output": "This fix must be applied manually - follow the steps shown."}
    t = int(p["timeout"])
    if p["elevate"]:
        code, out, err = run_elevated(p["commands"], timeout=t)
    elif IS_WIN:
        code, out, err = powershell("; ".join(p["commands"]), timeout=t)
    else:
        line = " && ".join(p["commands"])
        if p["as_user"] and IS_MAC and is_admin():
            # Homebrew refuses to run as root: run it as the logged-in user with their PATH.
            user = _console_user()
            if not user:
                return {"ok": False, "output": "Could not determine the logged-in user to run this update as."}
            cmd = ["sudo", "-u", user, "-H", "/bin/zsh", "-lc", line]
        else:
            cmd = ["/bin/sh", "-c", line] if not (IS_MAC and p["as_user"]) else ["/bin/zsh", "-lc", line]
        code, out, err = run(cmd, timeout=t)
    ok = code == 0
    if code == 124:
        err = (err + f"\nStopped after {t // 60} min. The download may be slow - try again, or use the manual steps.").strip()
    store.log_action(fix_id, json.dumps(args or {}), ok, (out + "\n" + err).strip())
    return {"ok": ok, "code": code, "output": (out + "\n" + err).strip()[-4000:]}


# ------------------------------------------------------------------ ports & connections
def _pf_rules_file():
    return store.data_dir() / "sentinel_pf.conf"


def _pf_apply(rules: list[str]) -> tuple[int, str, str]:
    f = _pf_rules_file()
    f.write_text("\n".join(rules) + "\n", encoding="utf-8")
    # macOS default pf.conf evaluates anchor "com.apple/*", so no edit of /etc/pf.conf is needed.
    return run_elevated([f"/sbin/pfctl -a com.apple/250.Sentinel -f {quote(str(f))}", "(/sbin/pfctl -E || true)"])


def _pf_current() -> list[str]:
    f = _pf_rules_file()
    return [l for l in f.read_text().splitlines() if l.strip()] if f.exists() else []


def block_port(port: int, proto: str) -> dict:
    port = int(port); proto = proto.upper()
    assert 0 < port < 65536 and proto in ("TCP", "UDP")
    name = f"Sentinel Block {proto} {port}"
    if IS_WIN:
        code, out, err = run_elevated([
            f"Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue",
            f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound -Action Block -Protocol {proto} -LocalPort {port} -Profile Any | Out-Null",
            f"'Inbound {proto} {port} blocked'"])
    elif IS_MAC:
        rule = f"block drop in quick proto {proto.lower()} from any to any port {port}"
        rules = [r for r in _pf_current() if r != rule] + [rule]
        code, out, err = _pf_apply(rules)
    else:
        code, out, err = run_elevated([f"ufw deny {port}/{proto.lower()}"])
    ok = code == 0
    if ok:
        pol = store.load_policy()
        if f"{proto}/{port}" not in pol["fw_blocked_ports"]:
            pol["fw_blocked_ports"].append(f"{proto}/{port}")
            store.save_policy(pol)
    store.log_action("block_port", f"{proto}/{port}", ok, out + err)
    return {"ok": ok, "output": (out + err).strip() or ("Port blocked by firewall." if ok else "Failed."),
            "note": None if not IS_MAC else "macOS clears pf rules on reboot - Sentinel will offer to re-apply them on next launch."}


def unblock_port(port: int, proto: str) -> dict:
    port = int(port); proto = proto.upper()
    assert 0 < port < 65536 and proto in ("TCP", "UDP")
    if IS_WIN:
        code, out, err = run_elevated([f"Remove-NetFirewallRule -DisplayName 'Sentinel Block {proto} {port}'"])
    elif IS_MAC:
        rule = f"block drop in quick proto {proto.lower()} from any to any port {port}"
        code, out, err = _pf_apply([r for r in _pf_current() if r != rule])
    else:
        code, out, err = run_elevated([f"ufw delete deny {port}/{proto.lower()}"])
    if code == 0:
        pol = store.load_policy()
        pol["fw_blocked_ports"] = [x for x in pol["fw_blocked_ports"] if x != f"{proto}/{port}"]
        store.save_policy(pol)
    store.log_action("unblock_port", f"{proto}/{port}", code == 0, out + err)
    return {"ok": code == 0, "output": (out + err).strip()}


def block_ip(ip: str) -> dict:
    ip = str(ipaddress.ip_address(ip))
    name = f"Sentinel Block IP {ip}"
    if IS_WIN:
        code, out, err = run_elevated([
            f"Remove-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue",
            f"New-NetFirewallRule -DisplayName '{name}' -Direction Outbound -Action Block -RemoteAddress {ip} | Out-Null",
            f"New-NetFirewallRule -DisplayName '{name}' -Direction Inbound -Action Block -RemoteAddress {ip} | Out-Null"])
    elif IS_MAC:
        rules = _pf_current()
        for r in (f"block drop out quick from any to {ip}", f"block drop in quick from {ip} to any"):
            if r not in rules:
                rules.append(r)
        code, out, err = _pf_apply(rules)
    else:
        code, out, err = run_elevated([f"ufw deny out to {ip}", f"ufw deny from {ip}"])
    ok = code == 0
    if ok:
        pol = store.load_policy()
        if ip not in pol["fw_blocked_ips"]:
            pol["fw_blocked_ips"].append(ip)
            store.save_policy(pol)
    store.log_action("block_ip", ip, ok, out + err)
    return {"ok": ok, "output": (out + err).strip() or ("Traffic to/from this IP is now blocked." if ok else "Failed.")}


def unblock_ip(ip: str) -> dict:
    ip = str(ipaddress.ip_address(ip))
    if IS_WIN:
        code, out, err = run_elevated([f"Remove-NetFirewallRule -DisplayName 'Sentinel Block IP {ip}'"])
    elif IS_MAC:
        code, out, err = _pf_apply([r for r in _pf_current() if ip not in r.split()])
    else:
        code, out, err = run_elevated([f"ufw delete deny out to {ip}", f"ufw delete deny from {ip}"])
    pol = store.load_policy()
    pol["blocked_ips"] = [x for x in pol["blocked_ips"] if x != ip]
    pol["fw_blocked_ips"] = [x for x in pol["fw_blocked_ips"] if x != ip]
    store.save_policy(pol)
    store.log_action("unblock_ip", ip, code == 0, out + err)
    return {"ok": code == 0, "output": (out + err).strip()}


def reapply_pf_rules() -> dict:
    """macOS resets pf on reboot; the UI offers this when saved rules exist."""
    if not IS_MAC:
        return {"ok": True, "output": "Not needed on this OS (rules are persistent)."}
    code, out, err = _pf_apply(_pf_current())
    return {"ok": code == 0, "output": (out + err).strip() or "Firewall rules re-applied."}


def kill_process(pid: int) -> dict:
    pid = int(pid)
    try:
        p = psutil.Process(pid)
        name = p.name()
        p.terminate()
        try:
            p.wait(5)
        except psutil.TimeoutExpired:
            p.kill()
        ok, out = True, f"Terminated {name} (PID {pid})."
    except psutil.NoSuchProcess:
        ok, out = True, "Process already exited."
    except psutil.AccessDenied:
        cmd = [f"Stop-Process -Id {pid} -Force"] if IS_WIN else [f"kill -9 {pid}"]
        code, o, e = run_elevated(cmd)
        ok, out = code == 0, (o + e).strip() or ("Terminated with admin rights." if code == 0 else "Failed.")
    store.log_action("kill_process", str(pid), ok, out)
    return {"ok": ok, "output": out}


def services_for_pid(pid: int) -> list[dict]:
    if not IS_WIN or not pid:
        return []
    code, out, _ = powershell(
        f"Get-CimInstance Win32_Service -Filter 'ProcessId={int(pid)}' | Select-Object Name,DisplayName,StartMode | ConvertTo-Json -Compress", 20)
    try:
        d = json.loads(out) if out.strip() else []
        return d if isinstance(d, list) else [d]
    except Exception:
        return []


def disable_service(name: str) -> dict:
    if not IS_WIN or not re.match(r"^[\w.\-$]{1,80}$", name):
        return {"ok": False, "output": "Invalid service."}
    code, out, err = run_elevated([f"Stop-Service -Name '{name}' -Force", f"Set-Service -Name '{name}' -StartupType Disabled",
                                   f"'Service {name} stopped and disabled'"])
    store.log_action("disable_service", name, code == 0, out + err)
    return {"ok": code == 0, "output": (out + err).strip()}


def firewall_rules() -> list[dict]:
    """Sentinel-created rules, so the user can review and undo them."""
    rules = []
    if IS_WIN:
        code, out, _ = powershell("Get-NetFirewallRule -DisplayName 'Sentinel Block*' | Select-Object DisplayName,Direction | ConvertTo-Json -Compress", 30)
        try:
            d = json.loads(out) if out.strip() else []
            d = d if isinstance(d, list) else [d]
            names = sorted({r["DisplayName"] for r in d})
            rules = [{"name": n} for n in names]
        except Exception:
            pass
    elif IS_MAC:
        rules = [{"name": r} for r in _pf_current()]
    return rules
