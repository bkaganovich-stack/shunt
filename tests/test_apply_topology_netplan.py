"""
The netplan apply_topology writes. Run:  python -m pytest tests/ -v
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src" / "scripts"))

import apply_topology as at  # noqa: E402

TOPO = {"wan_if": "wan0", "lan_if": "lan0", "lan_ip": "192.168.100.1",
        "lan_cidr": 24, "router_ip": "192.168.1.1"}


def _blocks(text):
    """{iface: [its lines]} under `ethernets:`."""
    out, cur = {}, None
    for ln in text.splitlines():
        if ln.startswith("    ") and not ln.startswith("     ") and ln.strip().endswith(":"):
            cur = ln.strip()[:-1]
            out[cur] = []
        elif cur and ln.startswith("      "):
            out[cur].append(ln.strip())
    return out


def test_boot_does_not_wait_for_the_provider(monkeypatch):
    # 2026-11-13: WAN carrier 218 s into boot; the LAN stayed dark for 120 s.
    monkeypatch.setattr(at, "perm_mac_of", lambda i: "aa:bb:cc:dd:ee:ff")
    b = _blocks(at.netplan_inline(TOPO))
    assert "optional: true" in b["wan0"]


def test_boot_still_waits_for_the_house(monkeypatch):
    monkeypatch.setattr(at, "perm_mac_of", lambda i: "aa:bb:cc:dd:ee:ff")
    assert "optional: true" not in _blocks(at.netplan_inline(TOPO))["lan0"]
    assert "optional: true" not in _blocks(at.netplan_loop(TOPO))["lan0"]
