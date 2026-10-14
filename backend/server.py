"""Sentinel backend: local-only JSON API on 127.0.0.1, protected by a per-launch token.

Started by the Electron main process. Prints `SENTINEL_READY <port>` once listening.
Run standalone for development:  python server.py --port 8765 --token dev
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# PyInstaller --noconsole builds have no stdio; give them a sink so print/traceback never crash.
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

from sentinel import advisor, inventory, network, platform_utils, ports, remediation, store, vulns  # noqa: E402

STATE: dict = {"ports": [], "connections": [], "findings": [], "apps": [], "scanned_at": {}}
ALERTS: list[dict] = []
JOBS: dict[str, dict] = {}
_alerted: set[str] = set()
LOCK = threading.Lock()
TOKEN = ""


def do_ports():
    r = ports.scan_ports()
    with LOCK:
        STATE["ports"] = r["ports"]; STATE["ports_note"] = r["note"]; STATE["scanned_at"]["ports"] = time.time()
    return r


def do_connections(resolve=True):
    r = network.scan_connections(resolve=resolve)
    with LOCK:
        STATE["connections"] = r["connections"]; STATE["scanned_at"]["connections"] = time.time()
        STATE["net_meta"] = {k: v for k, v in r.items() if k != "connections"}
        for c in r["connections"]:
            key = f"{c['app']}|{c['remote_ip']}|{c['remote_port']}|{c['verdict']}"
            if c["verdict"] in ("malicious", "unauthorised", "suspicious") and key not in _alerted:
                _alerted.add(key)
                ALERTS.append({"ts": time.time(), "severity": c["severity"], "verdict": c["verdict"],
                               "title": f"{c['app']} → {c['remote_host'] or c['remote_ip']}:{c['remote_port']}",
                               "detail": " ".join(c["flags"]), "conn": c})
                del ALERTS[:-200]
    return r


def do_audit(deep=False):
    open_ports = {p["port"] for p in STATE["ports"] if p["exposure"] != "loopback"} or \
                 {p["port"] for p in do_ports()["ports"] if p["exposure"] != "loopback"}
    r = vulns.audit(deep=deep, open_ports=open_ports)
    with LOCK:
        STATE["findings"] = r["findings"]; STATE["apps"] = r["apps"]; STATE["scanned_at"]["audit"] = time.time()
        STATE["audit_meta"] = {k: v for k, v in r.items() if k not in ("findings", "apps")}
    # forget "applied" markers for checks that now pass or no longer exist
    pol = store.load_policy()
    failing = {f["id"] for f in r["findings"] if f["status"] == "fail"}
    kept = {k: v for k, v in pol.get("applied_fixes", {}).items() if k in failing and time.time() - v < 7 * 86400}
    if kept != pol.get("applied_fixes", {}):
        store.save_policy({"applied_fixes": kept})
    for f in r["findings"]:
        if f["status"] == "fail" and f["severity"] in ("critical", "high"):
            store.log_event("vuln", f["severity"], f["title"], f.get("detail", ""))
    return r


def summary():
    with LOCK:
        st = {k: STATE.get(k, []) for k in ("ports", "connections", "findings")}
    sc = advisor.score(st)
    pc = st["ports"]
    cc = st["connections"]
    fails = [f for f in st["findings"] if f["status"] == "fail"]
    by_app: dict[str, int] = {}
    for c in cc:
        by_app[c["app"]] = by_app.get(c["app"], 0) + 1
    by_cat: dict[str, int] = {}
    for f in fails:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    return {
        "host": platform_utils.host_info(), "score": sc, "plan": advisor.plan(st, 8),
        "ports": {"total": len(pc), "exposed": sum(p["exposure"] != "loopback" for p in pc),
                  "close": sum(p["recommendation"] == "close" and p["exposure"] != "loopback" for p in pc),
                  "review": sum(p["recommendation"] == "review" for p in pc),
                  "by_severity": {s: sum(p["severity"] == s for p in pc) for s in ("critical", "high", "medium", "low")},
                  "top": pc[:8]},
        "connections": {"total": len(cc), "apps": len(by_app),
                        "by_verdict": {v: sum(c["verdict"] == v for c in cc) for v in ("malicious", "unauthorised", "suspicious", "new", "blocked", "ok")},
                        "top_apps": sorted(by_app.items(), key=lambda x: -x[1])[:6],
                        "meta": STATE.get("net_meta", {})},
        "vulns": {"fail": len(fails), "pass": sum(f["status"] == "pass" for f in st["findings"]),
                  "by_category": by_cat, "exploited": sum(bool(f.get("exploited")) for f in fails),
                  "meta": STATE.get("audit_meta", {})},
        "alerts": ALERTS[-10:][::-1],
        "scanned_at": STATE["scanned_at"],
    }


def monitor_loop():
    while True:
        try:
            do_connections(resolve=True)
        except Exception:
            traceback.print_exc()
        time.sleep(15)


class H(BaseHTTPRequestHandler):
    server_version = "Sentinel/1.0"

    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "content-type, x-sentinel-token")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "content-type, x-sentinel-token")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _auth(self):
        if self.headers.get("X-Sentinel-Token") != TOKEN:
            self._send(401, {"error": "unauthorised"})
            return False
        return True

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 20 * 1024 * 1024:
            raise ValueError("payload too large")
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if not self._auth():
            return
        u = urlparse(self.path); q = {k: v[0] for k, v in parse_qs(u.query).items()}
        try:
            p = u.path
            if p == "/api/health":
                return self._send(200, {"ok": True, "host": platform_utils.host_info()})
            if p == "/api/summary":
                return self._send(200, summary())
            if p == "/api/ports":
                return self._send(200, do_ports() if q.get("refresh") == "1" or not STATE["ports"] else {"ports": STATE["ports"], "note": STATE.get("ports_note")})
            if p == "/api/connections":
                if q.get("refresh") == "1" or not STATE["connections"]:
                    return self._send(200, do_connections())
                return self._send(200, {"connections": STATE["connections"], **STATE.get("net_meta", {})})
            if p == "/api/audit":
                if q.get("refresh") == "1" or not STATE["findings"]:
                    r = do_audit(deep=q.get("deep") == "1")
                else:
                    r = {"findings": STATE["findings"], **STATE.get("audit_meta", {})}
                r = {k: v for k, v in r.items() if k != "apps"}
                return self._send(200, r)
            if p == "/api/apps":
                return self._send(200, {"apps": STATE["apps"] or inventory.list_apps()})
            if p == "/api/playbook":
                args = json.loads(q.get("args") or "{}")
                return self._send(200, remediation.playbook(q["fix_id"], args) or {"error": "unknown fix"})
            if p == "/api/policy":
                return self._send(200, store.load_policy())
            if p == "/api/events":
                return self._send(200, {"events": store.recent("events"), "actions": store.recent("actions")})
            if p == "/api/alerts":
                since = float(q.get("since", 0))
                return self._send(200, {"alerts": [a for a in ALERTS if a["ts"] > since]})
            if p == "/api/job":
                j = JOBS.get(q.get("id", ""))
                return self._send(200, j or {"state": "unknown"})
            if p == "/api/ai/status":
                return self._send(200, advisor.ollama_status())
            if p == "/api/rules":
                return self._send(200, {"rules": remediation.firewall_rules()})
            if p == "/api/port/options":
                return self._send(200, {"services": remediation.services_for_pid(int(q.get("pid") or 0))})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            traceback.print_exc()
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        if not self._auth():
            return
        p = urlparse(self.path).path
        try:
            b = self._body()
            if p == "/api/shutdown":
                self._send(200, {"ok": True})
                threading.Timer(0.3, lambda: os._exit(0)).start()
                return
            if p == "/api/scan":
                do_ports(); do_connections(); do_audit(deep=bool(b.get("deep")))
                return self._send(200, summary())
            if p == "/api/fix":
                # Fixes can take a long time (updates), so run them as background jobs the UI polls.
                jid = secrets.token_hex(6)
                JOBS[jid] = {"id": jid, "state": "running", "started": time.time(), "fix_id": b["fix_id"]}

                def work(jid=jid, fid=b["fix_id"], args=b.get("args"), ref=b.get("ref")):
                    try:
                        r = remediation.apply_fix(fid, args)
                        if r.get("ok"):
                            if ref:
                                pol = store.load_policy()
                                pol["applied_fixes"][ref] = time.time()
                                store.save_policy({"applied_fixes": pol["applied_fixes"]})
                            do_audit()  # re-check so the dashboard and plan reflect the new state
                            r["still_failing"] = any(f["id"] == ref and f["status"] == "fail" for f in STATE["findings"])
                    except Exception as e:
                        r = {"ok": False, "output": str(e)}
                    JOBS[jid].update(state="done", finished=time.time(), result=r)
                threading.Thread(target=work, daemon=True).start()
                return self._send(200, {"job": jid})
            if p == "/api/port/block":
                r = remediation.block_port(b["port"], b.get("proto", "TCP"))
                if r["ok"] and b.get("kill") and b.get("pid"):
                    r["kill"] = remediation.kill_process(b["pid"])
                do_ports()
                return self._send(200, r)
            if p == "/api/port/unblock":
                r = remediation.unblock_port(b["port"], b.get("proto", "TCP"))
                do_ports()
                return self._send(200, r)
            if p == "/api/process/kill":
                return self._send(200, remediation.kill_process(b["pid"]))
            if p == "/api/service/disable":
                return self._send(200, remediation.disable_service(b["name"]))
            if p == "/api/ip/block":
                r = remediation.block_ip(b["ip"])
                if r["ok"] and b.get("kill") and b.get("pid"):
                    r["kill"] = remediation.kill_process(b["pid"])
                do_connections(resolve=False)
                return self._send(200, r)
            if p == "/api/ip/unblock":
                r = remediation.unblock_ip(b["ip"])
                do_connections(resolve=False)
                return self._send(200, r)
            if p == "/api/pf/reapply":
                return self._send(200, remediation.reapply_pf_rules())
            if p == "/api/policy":
                return self._send(200, store.save_policy(b))
            if p == "/api/policy/allow":
                pol = store.load_policy()
                if b.get("ip") and b["ip"] not in pol["allowed_ips"]:
                    pol["allowed_ips"].append(b["ip"])
                if b.get("domain") and b["domain"] not in pol["allowed_domains"]:
                    pol["allowed_domains"].append(b["domain"])
                if b.get("app") and b["app"] not in pol["trusted_apps"]:
                    pol["trusted_apps"].append(b["app"])
                return self._send(200, store.save_policy(pol))
            if p == "/api/ask":
                with LOCK:
                    st = {k: STATE.get(k, []) for k in ("ports", "connections", "findings")}
                return self._send(200, advisor.ask(b["question"][:1000], st, use_llm=b.get("llm", True)))
            if p == "/api/explain":
                return self._send(200, {"text": advisor.explain(b["kind"], b["item"])})
            if p == "/api/intel/import":
                added = network.import_feed(b.get("name", "feed"), b["text"])
                return self._send(200, {"ok": True, "added": added, "total": network.INTEL.size()})
            if p == "/api/cve/import":
                return self._send(200, {"ok": True, "entries": inventory.import_cve_db(b["text"])})
            return self._send(404, {"error": "not found"})
        except Exception as e:
            traceback.print_exc()
            return self._send(500, {"ok": False, "error": str(e), "output": str(e)})


def main():
    global TOKEN
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--token", default=os.environ.get("SENTINEL_TOKEN") or secrets.token_hex(16))
    ap.add_argument("--no-monitor", action="store_true")
    ap.add_argument("--parent-pid", type=int, default=0, help="exit when this process (the UI) exits")
    a = ap.parse_args()
    TOKEN = a.token
    store.install_time()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    print(f"SENTINEL_READY {srv.server_address[1]}", flush=True)
    if a.parent_pid:
        import psutil

        def watchdog():
            while psutil.pid_exists(a.parent_pid):
                time.sleep(3)
            os._exit(0)
        threading.Thread(target=watchdog, daemon=True).start()
    if not a.no_monitor:
        threading.Thread(target=monitor_loop, daemon=True).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
