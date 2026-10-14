"""Installed-software inventory and offline CVE matching."""
from __future__ import annotations

import json
import plistlib
import re
from pathlib import Path

from . import store
from .platform_utils import IS_LINUX, IS_MAC, IS_WIN, os_key, run

KNOW = Path(__file__).parent / "knowledge"


def _vtuple(v: str) -> tuple:
    v = re.sub(r"^\d+:", "", v or "")          # strip dpkg epoch
    if "+really" in v:                           # Debian '5.6.1+really5.4.5' = actually 5.4.5
        v = v.split("+really", 1)[1]
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:6]) or (0,)


def version_lt(a: str, b: str) -> bool:
    ta, tb = _vtuple(a), _vtuple(b)
    n = max(len(ta), len(tb))
    return ta + (0,) * (n - len(ta)) < tb + (0,) * (n - len(tb))


def _windows_apps() -> list[dict]:
    import winreg  # type: ignore
    apps, seen = [], set()
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
    ]
    for hive, path, view in roots:
        try:
            key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view)
        except OSError:
            continue
        for i in range(winreg.QueryInfoKey(key)[0]):
            try:
                sub = winreg.OpenKey(key, winreg.EnumKey(key, i))
                def val(n):
                    try:
                        return str(winreg.QueryValueEx(sub, n)[0])
                    except OSError:
                        return None
                name = val("DisplayName")
                if not name or val("SystemComponent") == "1":
                    continue
                ver = val("DisplayVersion") or ""
                k = (name, ver)
                if k in seen:
                    continue
                seen.add(k)
                apps.append({"name": name, "version": ver, "publisher": val("Publisher"),
                             "location": val("InstallLocation"), "source": "registry"})
            except OSError:
                continue
    return apps


def _mac_apps() -> list[dict]:
    apps = []
    dirs = [Path("/Applications"), Path("/Applications/Utilities"), Path.home() / "Applications"]
    for d in dirs:
        if not d.exists():
            continue
        for app in d.glob("*.app"):
            info = app / "Contents" / "Info.plist"
            try:
                with open(info, "rb") as fh:
                    pl = plistlib.load(fh)
                apps.append({
                    "name": pl.get("CFBundleName") or pl.get("CFBundleDisplayName") or app.stem,
                    "version": str(pl.get("CFBundleShortVersionString") or pl.get("CFBundleVersion") or ""),
                    "publisher": pl.get("CFBundleIdentifier"), "location": str(app), "source": "app",
                })
            except Exception:
                continue
    code, out, _ = run(["brew", "list", "--versions"], timeout=30)
    if code == 0:
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                apps.append({"name": parts[0], "version": parts[-1], "publisher": "Homebrew", "location": None, "source": "brew"})
    code, out, _ = run(["git", "--version"], timeout=10)
    if code == 0:
        m = re.search(r"(\d+\.\d+\.\d+)", out)
        if m:
            apps.append({"name": "git", "version": m.group(1), "publisher": out.strip(), "location": None, "source": "cli"})
    return apps


def _linux_apps() -> list[dict]:
    code, out, _ = run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"], timeout=30)
    apps = []
    if code == 0:
        for line in out.splitlines():
            if "\t" in line:
                n, v = line.split("\t", 1)
                apps.append({"name": n, "version": v, "publisher": "dpkg", "location": None, "source": "dpkg"})
    return apps


def list_apps() -> list[dict]:
    if IS_WIN:
        return _windows_apps()
    if IS_MAC:
        return _mac_apps()
    return _linux_apps()


def load_cve_db() -> dict:
    db = json.loads((KNOW / "cve_db.json").read_text(encoding="utf-8"))
    extra = store.data_dir() / "cve_extra.json"
    if extra.exists():
        try:
            more = json.loads(extra.read_text(encoding="utf-8"))
            ids = {e["id"] for e in db["entries"]}
            db["entries"] += [e for e in more.get("entries", []) if e.get("id") not in ids]
            db["updated"] = max(db.get("updated", ""), more.get("updated", ""))
        except Exception:
            pass
    return db


def import_cve_db(text: str) -> int:
    data = json.loads(text)
    entries = data.get("entries") if isinstance(data, dict) else data
    if not isinstance(entries, list):
        raise ValueError("expected {'entries': [...]} or a list")
    for e in entries:
        if not {"id", "product", "match"} <= set(e):
            raise ValueError(f"entry missing id/product/match: {e}")
        re.compile(e["match"])
    (store.data_dir() / "cve_extra.json").write_text(
        json.dumps({"updated": data.get("updated", "") if isinstance(data, dict) else "", "entries": entries}, indent=1),
        encoding="utf-8")
    return len(entries)


def _is_vulnerable(ver: str, e: dict) -> bool:
    if not ver:
        return False
    if "affected_versions" in e:
        return any(_vtuple(ver)[:3] == _vtuple(a)[:3] for a in e["affected_versions"])
    branches = e.get("fixed_branches")
    if branches:
        mm = _vtuple(ver)[:2]
        for b in branches:
            if _vtuple(b)[:2] == mm:
                return version_lt(ver, b)
        lowest = min(branches, key=_vtuple)
        return version_lt(ver, lowest)
    return "fixed" in e and version_lt(ver, e["fixed"])


def match_cves(apps: list[dict]) -> list[dict]:
    db = load_cve_db()
    osk = os_key()
    findings = []
    for e in db["entries"]:
        if e.get("platforms") and osk not in e["platforms"]:
            continue
        rx = re.compile(e["match"], re.I)
        for a in apps:
            # Linux distros backport fixes without bumping upstream versions; only exact-version
            # (affected_versions) entries are reliable for distro packages.
            if a.get("source") == "dpkg" and "affected_versions" not in e:
                continue
            if rx.search(a["name"] or "") and _is_vulnerable(a["version"], e):
                findings.append({
                    "id": f"cve-{e['id']}-{re.sub(r'[^a-z0-9]', '', a['name'].lower())[:20]}",
                    "category": "Vulnerable software",
                    "title": f"{a['name']} {a['version']} is vulnerable ({', '.join(e.get('cves', []))})",
                    "severity": e.get("severity", "high"),
                    "status": "fail",
                    "detail": e.get("summary", ""),
                    "exploited": e.get("exploited", False),
                    "cves": e.get("cves", []),
                    "app": a, "fixed": e.get("fixed"),
                    "fix_id": "update_app",
                    "fix_args": {"name": a["name"], "source": a.get("source"), "fixed": e.get("fixed")},
                })
    return findings
