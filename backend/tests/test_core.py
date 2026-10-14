"""Run: python -m pytest backend/tests  (or: python backend/tests/test_core.py)"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("SENTINEL_DATA", tempfile.mkdtemp())

from sentinel import advisor, inventory, network, ports, remediation  # noqa: E402


def test_version_compare():
    assert inventory.version_lt("114.0.5735.199", "116.0.5845.187")
    assert not inventory.version_lt("116.0.5845.190", "116.0.5845.187")
    assert inventory.version_lt("0.79", "0.81")
    assert inventory.version_lt("5.6.1+really5.4.5-1", "5.4.6")  # Debian '+really' = 5.4.5
    assert inventory.version_lt("1:2.39.0", "2.39.4")              # dpkg epoch ignored


def test_cve_matching_branches_and_exact():
    apps = [{"name": "git", "version": "2.39.5", "source": "cli"},       # fixed branch backport -> safe
            {"name": "git", "version": "2.38.1", "source": "cli"},       # below all branches -> vulnerable
            {"name": "xz", "version": "5.6.1", "source": "brew"},        # backdoored release
            {"name": "xz", "version": "5.6.1+really5.4.5", "source": "brew"}]  # Debian rollback -> safe
    found = {(f["app"]["name"], f["app"]["version"]) for f in inventory.match_cves(apps)}
    assert ("git", "2.38.1") in found and ("git", "2.39.5") not in found
    assert ("xz", "5.6.1") in found and ("xz", "5.6.1+really5.4.5") not in found


def test_intel_domain_suffix_and_cidr():
    assert network.INTEL.match_domain("eu.pool.supportxmr.com")[0] == "mining"
    assert network.INTEL.match_domain("example.com") is None
    assert network.INTEL.match_ip("240.1.2.3") is not None


def test_port_scoring():
    hi = ports.score_port(445, "TCP", "all-interfaces", {"name": "System", "exe": None})
    lo = ports.score_port(445, "TCP", "loopback", {"name": "System", "exe": None})
    tmp = ports.score_port(40123, "TCP", "all-interfaces", {"name": "x.exe", "exe": r"C:\Users\a\AppData\Local\Temp\x.exe"})
    assert hi["recommendation"] == "close" and hi["severity"] in ("high", "critical")
    assert hi["risk"] > lo["risk"] and lo["recommendation"] == "keep"
    assert tmp["risk"] >= 50


def test_playbooks_are_safe_templates():
    pb = remediation.playbook("update_app", {"name": "Evil; rm -rf /"})
    assert not any("rm -rf" in c for c in pb["commands"])  # rejected by NAME_RX
    for fid in remediation.PB:
        assert remediation.playbook(fid) is not None


def test_advisor_works_without_llm():
    state = {"findings": [{"id": "x", "category": "Firewall", "title": "Firewall off", "severity": "critical",
                           "status": "fail", "detail": "", "fix_id": "enable_firewall"}], "ports": [], "connections": []}
    sc = advisor.score(state)
    assert sc["score"] < 100 and advisor.plan(state)[0]["fix_id"] == "enable_firewall"
    ans = advisor.ask("how do I turn on the firewall", state, use_llm=False)
    assert ans["engine"] == "built-in" and "firewall" in ans["answer"].lower()


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn(); print("ok", name)
