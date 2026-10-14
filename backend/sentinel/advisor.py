"""Offline AI advisor.

Tier 1 (always available, no model needed):
  * Risk engine     - weighted scoring of every finding, port and connection -> security score & grade.
  * Planner         - ranks remediation actions by (impact x exploitability x exposure) / effort.
  * Retrieval Q&A   - TF-IDF search over the built-in security knowledge base (playbooks, port
                      intel, CVE notes) + your live scan, answering questions with concrete steps.
Tier 2 (optional): if a local Ollama server is running, answers are rewritten by a local LLM that is
  grounded on the same retrieved facts. Nothing ever leaves the machine.
"""
from __future__ import annotations

import json
import math
import re
import urllib.request
from collections import Counter

from . import inventory, remediation, store
from .ports import KB as PORT_KB
from .platform_utils import os_key

SEV_W = {"critical": 10, "high": 6, "medium": 3, "low": 1}
EFFORT = {  # 1 = one click, 3 = manual / reboot / key backup
    "enable_firewall": 1, "enable_defender": 1, "disable_smb1": 1, "disable_rdp": 1, "disable_llmnr": 1,
    "disable_guest": 1, "disable_autorun": 1, "enable_stealth": 1, "enable_gatekeeper": 1, "enable_autoupdate": 1,
    "update_defender": 1, "disable_ssh": 1, "disable_screensharing": 1, "disable_filesharing": 1,
    "update_app": 2, "windows_update": 2, "macos_update": 2, "enable_uac": 2, "disable_psv2": 2,
    "enable_bitlocker": 3, "enable_filevault": 3, "upgrade_os": 3, "manual_sip": 3, "manual_secureboot": 3, "manual_tamper": 2,
    "block_port": 1, "block_ip": 1,
}


# ------------------------------------------------------------------ risk engine
def score(state: dict) -> dict:
    findings = [f for f in state.get("findings", []) if f.get("status") == "fail"]
    ports = state.get("ports", [])
    conns = state.get("connections", [])
    penalty = 0.0
    for f in findings:
        w = SEV_W.get(f["severity"], 1)
        if f.get("exploited"):
            w *= 1.5
        penalty += w
    for p in ports:
        if p["exposure"] != "loopback":
            penalty += {"critical": 6, "high": 4, "medium": 1.5}.get(p["severity"], 0)
    for c in conns:
        penalty += {"malicious": 15, "unauthorised": 6, "suspicious": 2}.get(c["verdict"], 0)
    s = max(0, round(100 * math.exp(-penalty / 60)))
    grade = "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"
    counts = Counter(f["severity"] for f in findings)
    return {"score": s, "grade": grade, "penalty": round(penalty, 1),
            "by_severity": {k: counts.get(k, 0) for k in ("critical", "high", "medium", "low")}}


def plan(state: dict, limit: int = 12) -> list[dict]:
    items = []
    applied = store.load_policy().get("applied_fixes", {})
    for f in state.get("findings", []):
        if f.get("status") != "fail" or not f.get("fix_id"):
            continue
        impact = SEV_W.get(f["severity"], 1) * (1.6 if f.get("exploited") else 1)
        eff = EFFORT.get(f["fix_id"], 2)
        pb = remediation.playbook(f["fix_id"], f.get("fix_args"))
        items.append({
            "kind": "finding", "ref": f["id"],
            "title": (f"Update {f['app']['name']} to {f.get('fixed') or 'the latest version'}" if f["fix_id"] == "update_app"
                      else pb["title"] if pb else f["title"]), "target": f["title"],
            "severity": f["severity"], "priority": round(impact / eff, 2), "automatable": bool(pb and pb["automatable"]),
            "fix_id": f["fix_id"], "fix_args": f.get("fix_args"),
            "rationale": _rationale_finding(f, pb, eff),
        })
        if f["id"] in applied:
            items[-1].update(applied=True, priority=-1,
                             rationale="Fix applied, but the check still fails. Some changes only take effect after a restart "
                                       "(or the system rejected the change). Restart, then press Scan now.")
    for p in state.get("ports", []):
        if p["recommendation"] == "close" and p["exposure"] != "loopback":
            impact = SEV_W.get(p["severity"], 1)
            items.append({
                "kind": "port", "ref": p["id"], "title": f"Close {p['proto']} port {p['port']} ({p['service']})",
                "target": f"{p['process'].get('name') or 'unknown process'} (PID {p['process'].get('pid')})",
                "severity": p["severity"], "priority": round(impact / 1, 2), "automatable": True,
                "port": p["port"], "proto": p["proto"], "pid": p["process"].get("pid"),
                "rationale": f"Risk {p['risk']}/100. " + " ".join(p["reasons"][:2]) + " Blocking it in the firewall is instant and reversible.",
            })
    seen_dest = set()
    for c in state.get("connections", []):
        if c["verdict"] in ("malicious", "unauthorised") and (c["app"], c["remote_ip"]) not in seen_dest:
            seen_dest.add((c["app"], c["remote_ip"]))
            items.append({
                "kind": "connection", "ref": c["id"], "title": f"Block {c['remote_host'] or c['remote_ip']} and stop {c['app']}",
                "target": f"{c['app']} -> {c['remote_ip']}:{c['remote_port']}",
                "severity": c["severity"], "priority": SEV_W.get(c["severity"], 1) * 1.5, "automatable": True,
                "ip": c["remote_ip"], "pid": c["pid"],
                "rationale": " ".join(c["flags"]) + " Blocking the IP cuts the connection immediately; then investigate the program.",
            })
    items.sort(key=lambda x: -x["priority"])
    active = [i for i in items if not i.get("applied")]
    pending = [i for i in items if i.get("applied")]
    return active[:limit] + pending  # applied-but-unverified fixes stay visible at the bottom


def _rationale_finding(f, pb, eff) -> str:
    parts = []
    if f.get("exploited"):
        parts.append("This vulnerability is known to be actively exploited in the wild, so it is a top priority.")
    elif f["severity"] in ("critical", "high"):
        parts.append(f"This is a {f['severity']}-severity weakness.")
    if f.get("detail"):
        parts.append(f["detail"])
    if pb:
        parts.append(pb["why"])
        parts.append("It can be fixed in one click." if pb["automatable"] and eff == 1 else
                     "Sentinel can apply it for you." if pb["automatable"] else "It needs a few manual steps (shown below).")
        if pb.get("needs_internet"):
            parts.append("Requires an internet connection to download the patch.")
    return " ".join(parts)


def explain(kind: str, item: dict) -> str:
    if kind == "port":
        proc = item.get("process", {})
        s = (f"{item['proto']} port {item['port']} ({item['service']}) is opened by {proc.get('name') or 'an unidentified process'}"
             f"{' (' + proc['exe'] + ')' if proc.get('exe') else ''}. ")
        s += {"loopback": "It only accepts connections from this computer, so outside exposure is minimal. ",
              "all-interfaces": "It listens on every network interface, so other devices on your network can reach it. ",
              "network": "It is bound to a specific network address and reachable from that network. "}[item["exposure"]]
        s += " ".join(item["reasons"]) + " "
        s += {"close": "Recommendation: CLOSE it - block it in the firewall, or stop the program/service if you don't use it.",
              "review": "Recommendation: REVIEW - keep it only if you recognise the program and need the feature.",
              "keep": "Recommendation: KEEP - low risk.",
              "blocked": "Status: BLOCKED by a Sentinel firewall rule - other devices can no longer reach it."}.get(item["recommendation"], "")
        return s
    if kind == "connection":
        s = (f"{item['app']} (PID {item['pid']}) is connected to {item.get('remote_host') or item['remote_ip']} "
             f"on port {item['remote_port']}. Verdict: {item['verdict'].upper()}. ")
        s += " ".join(item["flags"]) if item["flags"] else "Nothing unusual was detected about this destination."
        if item["verdict"] in ("malicious", "unauthorised", "suspicious"):
            s += (" Suggested response: (1) block the destination IP, (2) terminate the process if you don't recognise it, "
                  "(3) run a full antivirus scan, (4) check the program's file location and digital signature.")
        return s
    return item.get("detail", "")


# ------------------------------------------------------------------ retrieval Q&A
_TOK = re.compile(r"[a-z0-9]+")
STOP = set("the a an is are to of and or in on for it this that my how do i what why can be with should you me does".split())


def _tokens(t: str) -> list[str]:
    return [w for w in _TOK.findall(t.lower()) if w not in STOP]


def _docs(state: dict) -> list[tuple[str, str]]:
    osk = os_key()
    docs = []
    for fid, pb in remediation.PB.items():
        if osk not in pb:
            continue
        spec = pb[osk]
        steps = spec.get("manual", [])
        docs.append((f"How to: {pb['title']}", f"{pb['why']} Steps: " + " -> ".join(steps) +
                     (f" Command: {'; '.join(spec.get('cmd', []))}" if spec.get("cmd") else "")))
    for port, kb in PORT_KB.items():
        docs.append((f"Port {port} ({kb['service']})", f"{kb['why']} Base risk {kb['risk']}/100. Usual advice: {kb['action']}."))
    for e in inventory.load_cve_db()["entries"]:
        docs.append((f"{e['product']} {' '.join(e.get('cves', []))}", f"{e['product']}: {e.get('summary', '')} Fixed in {e.get('fixed', 'a later version')}. Update the application."))
    for f in state.get("findings", []):
        docs.append((f"Your system: {f['title']}", f"[{f['status']}/{f['severity']}] {f['title']}. {f.get('detail', '')}"))
    for p in state.get("ports", [])[:60]:
        docs.append((f"Your open port {p['port']}", explain("port", p)))
    for c in state.get("connections", [])[:80]:
        if c["verdict"] != "ok":
            docs.append((f"Connection {c['app']} -> {c['remote_ip']}", explain("connection", c)))
    return docs


def _retrieve(q: str, docs, k=4):
    qt = _tokens(q)
    if not qt:
        return []
    N = len(docs)
    toks = [_tokens(t + " " + b) for t, b in docs]
    df = Counter(w for ts in toks for w in set(ts))
    scored = []
    for (t, b), ts in zip(docs, toks):
        tf = Counter(ts)
        s = sum((tf[w] / (1 + len(ts)) ** 0.5) * math.log(1 + N / (1 + df[w])) for w in qt if w in tf)
        title_bonus = sum(1 for w in qt if w in _tokens(t)) * 0.3
        if s > 0:
            scored.append((s + title_bonus, t, b))
    scored.sort(reverse=True)
    return scored[:k]


def ollama_status() -> dict:
    pol = store.load_policy()
    try:
        with urllib.request.urlopen(pol["ollama_url"].rstrip("/") + "/api/tags", timeout=1.5) as r:
            models = [m["name"] for m in json.loads(r.read()).get("models", [])]
        return {"available": True, "models": models, "model": pol["ollama_model"]}
    except Exception:
        return {"available": False, "models": [], "model": pol["ollama_model"]}


def _ollama(prompt: str) -> str | None:
    pol = store.load_policy()
    st = ollama_status()
    if not st["available"]:
        return None
    model = pol["ollama_model"] if pol["ollama_model"] in st["models"] or not st["models"] else st["models"][0]
    body = json.dumps({"model": model, "prompt": prompt, "stream": False, "options": {"temperature": 0.2}}).encode()
    req = urllib.request.Request(pol["ollama_url"].rstrip("/") + "/api/generate", data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read()).get("response")
    except Exception:
        return None


def ask(question: str, state: dict, use_llm: bool = True) -> dict:
    docs = _docs(state)
    hits = _retrieve(question, docs)
    sc = score(state)
    ql = question.lower()

    # built-in intents
    if re.search(r"\b(score|how (safe|secure)|overall|status|summary)\b", ql):
        top = plan(state, 3)
        ans = (f"Your security score is {sc['score']}/100 (grade {sc['grade']}). Open issues: "
               f"{sc['by_severity']['critical']} critical, {sc['by_severity']['high']} high, {sc['by_severity']['medium']} medium. ")
        if top:
            ans += "Do these first: " + "; ".join(f"{i + 1}) {t['title']}" for i, t in enumerate(top)) + "."
        hits = []
    elif re.search(r"\b(first|priorit|what should i (do|fix)|next)\b", ql):
        top = plan(state, 5)
        ans = ("Recommended order:\n" + "\n".join(f"{i + 1}. {t['title']} - {t['rationale']}" for i, t in enumerate(top))
               if top else "Nothing urgent - no failing checks with known fixes. Keep automatic updates on and re-scan weekly.")
        hits = []
    elif hits:
        best = hits[0]
        ans = f"{best[1]}\n{best[2]}"
        if len(hits) > 1 and hits[1][0] > best[0] * 0.6:
            ans += f"\n\nRelated - {hits[1][1]}: {hits[1][2]}"
    else:
        ans = ("I couldn't find that in the offline knowledge base. Try asking about a port number, an application, "
               "a finding title, or 'what should I fix first?'.")

    engine = "built-in"
    if use_llm:
        ctx = "\n".join(f"- {t}: {b}" for _, t, b in hits) or ans
        prompt = (
            "You are Sentinel, an offline desktop security assistant. Answer the user's question concisely using ONLY the facts "
            "below plus general security knowledge. Give concrete step-by-step fixes for their OS "
            f"({os_key()}). If unsure, say so.\n\nSystem score: {sc['score']}/100.\nFacts:\n{ctx}\n\nQuestion: {question}\nAnswer:")
        llm = _ollama(prompt)
        if llm:
            ans, engine = llm.strip(), "local-llm"
    return {"answer": ans, "engine": engine, "sources": [t for _, t, _ in hits]}
