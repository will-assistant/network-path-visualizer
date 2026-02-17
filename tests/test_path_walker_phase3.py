import asyncio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from collectors import RouteEntry
from inventory import Inventory
from path_walker import PathWalker


INV = """
devices:
  pe-1:
    management_ip: 10.0.0.1
    role: pe
    domain: dc
    interfaces: {xe-0/0/0: 10.0.1.1}
    mpls:
      10.0.1.2:
        - {action: push, label: 1001, lsp_name: LSP-PE-AGG}
  fw-1:
    management_ip: 10.0.0.2
    role: firewall
    domain: dc
    interfaces: {xe-0/0/0: 10.0.1.2, xe-0/0/1: 10.0.2.1}
  agg-1:
    management_ip: 10.0.0.3
    role: agg
    domain: agg
    interfaces: {xe-0/0/0: 10.0.2.2, xe-0/0/1: 10.0.3.1}
    mpls:
      10.0.3.2:
        - {action: swap, label: 2002, lsp_name: LSP-AGG-EDGE}
  fw-2:
    management_ip: 10.0.0.4
    role: firewall
    domain: agg
    interfaces: {xe-0/0/0: 10.0.3.2, xe-0/0/1: 10.0.4.1}
  edge-1:
    management_ip: 10.0.0.5
    role: edge
    domain: edge
    interfaces: {xe-0/0/0: 10.0.4.2}
    mpls:
      0.0.0.0:
        - {action: pop, label: 3, lsp_name: LSP-POP}
boundaries:
  - firewall: fw-1
    upstream_domain: dc
    downstream_domain: agg
  - firewall: fw-2
    upstream_domain: agg
    downstream_domain: edge
"""


def _inv():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(INV)
        f.flush()
        return Inventory.from_yaml(f.name)


def run(coro):
    return asyncio.run(coro)


def test_mpls_and_domain_crossings_and_origin():
    inv = _inv()
    responses = {
        "pe-1": [RouteEntry(prefix="9.9.9.0/24", protocol="bgp", next_hop="10.0.1.2", active=True)],
        "fw-1": [RouteEntry(prefix="9.9.9.0/24", protocol="static", next_hop="10.0.2.2", active=True)],
        "agg-1": [RouteEntry(prefix="9.9.9.0/24", protocol="bgp", next_hop="10.0.3.2", active=True)],
        "fw-2": [RouteEntry(prefix="9.9.9.0/24", protocol="policy", next_hop="10.0.4.2", active=True)],
        "edge-1": [RouteEntry(prefix="9.9.9.0/24", protocol="connected", active=True)],
    }

    async def c(d, p, v):
        return responses.get(d, [])

    r = run(PathWalker(inv, c).trace("9.9.9.0/24", "pe-1"))
    assert r.origin_type == "connected"
    assert r.origin_router == "edge-1"
    assert len(r.domain_crossings) == 2
    # push at pe, swap at agg
    labels = [l.action for p in r.paths for h in p.hops for l in h.labels]
    assert "push" in labels
    assert "swap" in labels


def test_ecmp_cap_and_branch_metadata():
    inv = _inv()
    paths = [RouteEntry(prefix="1.1.1.0/24", protocol="bgp", next_hop=f"10.0.1.{x}", active=True) for x in range(2, 12)]
    e0 = paths[0]
    e0.paths = paths[1:]

    responses = {"pe-1": [e0]}

    async def c(d, p, v):
        return responses.get(d, [])

    r = run(PathWalker(inv, c, max_ecmp_branches=3).trace("1.1.1.0/24", "pe-1"))
    assert len(r.ecmp_branches) == 1
    assert len(r.ecmp_branches[0].selected_paths) == 3


def test_reverse_and_asymmetry():
    inv = _inv()

    async def c(d, p, v):
        if p == "9.9.9.0/24":
            m = {
                "pe-1": [RouteEntry(protocol="bgp", next_hop="10.0.1.2", active=True)],
                "fw-1": [RouteEntry(protocol="static", next_hop="10.0.2.2", active=True)],
                "agg-1": [RouteEntry(protocol="bgp", next_hop="10.0.3.2", active=True)],
                "fw-2": [RouteEntry(protocol="policy", next_hop="10.0.4.2", active=True)],
                "edge-1": [RouteEntry(protocol="connected", active=True)],
            }
            return m.get(d, [])
        if p == "pe-1":
            m = {
                "edge-1": [RouteEntry(protocol="bgp", next_hop="10.0.3.2", active=True)],
                "fw-2": [RouteEntry(protocol="policy", next_hop="10.0.2.2", active=True)],
                "agg-1": [RouteEntry(protocol="bgp", next_hop="10.0.1.2", active=True)],
                "fw-1": [RouteEntry(protocol="static", next_hop="10.0.1.1", active=True)],
                "pe-1": [RouteEntry(protocol="connected", active=True)],
            }
            return m.get(d, [])
        return []

    w = PathWalker(inv, c)
    a = run(w.trace_reverse("9.9.9.0/24", "pe-1"))
    assert a.symmetric is False
    assert a.divergence_points


def test_failure_simulation():
    inv = _inv()

    async def c(d, p, v):
        m = {
            "pe-1": [RouteEntry(protocol="bgp", next_hop="10.0.1.2", active=True)],
            "fw-1": [RouteEntry(protocol="static", next_hop="10.0.2.2", active=True)],
            "agg-1": [RouteEntry(protocol="bgp", next_hop="10.0.3.2", active=True)],
            "fw-2": [RouteEntry(protocol="policy", next_hop="10.0.4.2", active=True)],
            "edge-1": [RouteEntry(protocol="connected", active=True)],
        }
        return m.get(d, [])

    sim = run(PathWalker(inv, c).simulate_failure("pe-1", "9.9.9.0/24", "agg-1"))
    assert sim.failed_node == "agg-1"
    assert sim.impact_summary


def test_origin_detection_variants():
    inv = _inv()

    async def connected(d, p, v):
        return [RouteEntry(protocol="connected", active=True)] if d == "pe-1" else []

    r1 = run(PathWalker(inv, connected).find_origin("1.1.1.0/24", "pe-1"))
    assert r1["origin_type"] == "connected"

    async def static_case(d, p, v):
        return [RouteEntry(protocol="static", next_hop="99.99.99.99", active=True)] if d == "pe-1" else []

    r2 = run(PathWalker(inv, static_case).find_origin("2.2.2.0/24", "pe-1"))
    assert r2["origin_type"] in ("static", "unknown")

    async def bgp_case(d, p, v):
        return [RouteEntry(protocol="bgp", next_hop="99.99.99.99", active=True)] if d == "pe-1" else []

    r3 = run(PathWalker(inv, bgp_case).find_origin("3.3.3.0/24", "pe-1"))
    assert r3["origin_type"] in ("ebgp", "unknown")
