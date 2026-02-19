"""Integration test — end-to-end trace with mock data."""

import sys
import asyncio
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from path_walker import PathWalker
from inventory import Inventory
from collectors import RouteEntry
from plugins import CommunityDecoderPlugin


# Full mock network:
#   edge-1 → core-1 → core-2 → pe-1 (origin)
#                    ↘ pe-2 (ECMP, not in inventory beyond pe-2)

FULL_INVENTORY = """
devices:
  edge-1:
    management_ip: 10.0.1.1
    vendor: juniper
    role: edge
    loopbacks: [192.168.1.1]
    interfaces:
      et-0/0/0: 10.10.1.1

  core-1:
    management_ip: 10.0.1.2
    vendor: juniper
    role: core
    loopbacks: [192.168.1.2]
    interfaces:
      et-0/0/0: 10.10.1.2
      et-0/0/1: 10.10.2.1
      et-0/0/2: 10.10.3.1

  core-2:
    management_ip: 10.0.1.3
    vendor: juniper
    role: core
    loopbacks: [192.168.1.3]
    interfaces:
      et-0/0/0: 10.10.2.2
      et-0/0/1: 10.10.4.1

  pe-1:
    management_ip: 10.0.1.4
    vendor: juniper
    role: pe
    loopbacks: [192.168.1.4]
    interfaces:
      ge-0/0/0: 10.10.4.2
      ge-0/0/1: 172.16.0.1

  pe-2:
    management_ip: 10.0.1.5
    vendor: juniper
    role: pe
    loopbacks: [192.168.1.5]
    interfaces:
      ge-0/0/0: 10.10.3.2
"""


def _make_inv():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(FULL_INVENTORY)
        f.flush()
        return Inventory.from_yaml(f.name)


def run(coro):
    return asyncio.run(coro)


class MockPlugin(CommunityDecoderPlugin):
    def name(self): return "mock-decoder"
    def decode(self, communities, local_pref=None):
        labels = {}
        for c in communities:
            if c == "65000:100":
                labels["tag"] = "customer-route"
        if local_pref and local_pref >= 200:
            labels["preference"] = "primary"
        return labels


class TestEndToEndTrace:
    """Full integration: linear trace through mock network."""

    def test_linear_trace_to_origin(self):
        inv = _make_inv()
        responses = {
            "edge-1": [RouteEntry(prefix="172.16.0.0/24", protocol="bgp",
                                   next_hop="10.10.1.2", active=True,
                                   as_path=["65000"], local_pref=100,
                                   communities=["65000:100"])],
            "core-1": [RouteEntry(prefix="172.16.0.0/24", protocol="bgp",
                                   next_hop="10.10.2.2", active=True,
                                   as_path=["65000"], local_pref=200)],
            "core-2": [RouteEntry(prefix="172.16.0.0/24", protocol="bgp",
                                   next_hop="10.10.4.2", active=True,
                                   as_path=["65000"])],
            "pe-1":   [RouteEntry(prefix="172.16.0.0/24", protocol="connected", active=True)],
        }

        async def collector(dev, prefix, vrf):
            return responses.get(dev, [])

        walker = PathWalker(inv, collector, plugins=[MockPlugin()])
        result = run(walker.trace("172.16.0.0/24", "edge-1"))

        assert result.prefix == "172.16.0.0/24"
        assert result.start == "edge-1"
        assert len(result.paths) == 1

        path = result.paths[0]
        assert path.complete is True
        assert path.end_reason == "origin"
        assert len(path.hops) == 4

        devices = [h.device for h in path.hops]
        assert devices == ["edge-1", "core-1", "core-2", "pe-1"]

        # Check plugin labels
        assert "mock-decoder" in path.hops[0].plugin_labels
        assert path.hops[0].plugin_labels["mock-decoder"]["tag"] == "customer-route"
        assert path.hops[1].plugin_labels["mock-decoder"]["preference"] == "primary"

    def test_ecmp_trace(self):
        """ECMP at core-1: one path to core-2→pe-1, one to pe-2 (ends at pe-2, no further route)."""
        inv = _make_inv()

        ecmp_entry = RouteEntry(
            prefix="172.16.0.0/24", protocol="bgp",
            next_hop="10.10.2.2", active=True,
            paths=[RouteEntry(prefix="172.16.0.0/24", protocol="bgp",
                              next_hop="10.10.3.2", active=True)],
        )

        responses = {
            "edge-1": [RouteEntry(prefix="172.16.0.0/24", protocol="bgp",
                                   next_hop="10.10.1.2", active=True)],
            "core-1": [ecmp_entry],
            "core-2": [RouteEntry(prefix="172.16.0.0/24", protocol="bgp",
                                   next_hop="10.10.4.2", active=True)],
            "pe-1":   [RouteEntry(prefix="172.16.0.0/24", protocol="connected", active=True)],
            "pe-2":   [],  # blackhole
        }

        async def collector(dev, prefix, vrf):
            return responses.get(dev, [])

        walker = PathWalker(inv, collector)
        result = run(walker.trace("172.16.0.0/24", "edge-1"))

        assert len(result.paths) == 2

        reasons = {p.end_reason for p in result.paths}
        assert "origin" in reasons
        assert "blackhole" in reasons

    def test_hop_includes_all_entries_for_ecmp_visibility(self):
        """Ensure hop metadata retains all route entries, not only best path."""
        inv = _make_inv()
        responses = {
            "edge-1": [
                RouteEntry(prefix="8.8.8.0/24", protocol="bgp", next_hop="10.10.1.2", active=True, as_path=["65000", "15169"], local_pref=200, metric=10),
                RouteEntry(prefix="8.8.8.0/24", protocol="bgp", next_hop="10.10.1.3", active=False, as_path=["64512", "15169"], local_pref=150, metric=20),
            ],
        }

        async def collector(dev, prefix, vrf):
            return responses.get(dev, [])

        walker = PathWalker(inv, collector)
        result = run(walker.trace("8.8.8.0/24", "edge-1"))

        hop = result.paths[0].hops[0]
        assert len(hop.all_entries) == 2
        assert hop.all_entries[0]["next_hop"] == "10.10.1.2"
        assert hop.all_entries[1]["next_hop"] == "10.10.1.3"
        assert hop.all_entries[0]["active"] is True
        assert hop.all_entries[1]["active"] is False
        assert hop.all_entries[0]["metric"] == 10
        assert hop.all_entries[1]["metric"] == 20

    def test_serialization_format(self):
        """Verify the result can be serialized to the expected API format."""
        inv = _make_inv()
        responses = {
            "edge-1": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                                   next_hop="99.99.99.99", active=True,
                                   communities=["7018:2500"], local_pref=100,
                                   as_path=["7018", "15169"])],
        }

        async def collector(dev, prefix, vrf):
            return responses.get(dev, [])

        walker = PathWalker(inv, collector)
        result = run(walker.trace("8.8.8.0/24", "edge-1"))

        # Simulate serialization like main.py does
        serialized = {
            "prefix": result.prefix,
            "start": result.start,
            "paths": [
                {
                    "hops": [
                        {
                            "device": h.device,
                            "role": h.role,
                            "next_hop": h.next_hop,
                            "protocol": h.protocol,
                            "communities": h.communities,
                            "lp": h.lp,
                            "as_path": h.as_path,
                        }
                        for h in p.hops
                    ],
                    "complete": p.complete,
                    "end_reason": p.end_reason,
                }
                for p in result.paths
            ],
        }

        assert serialized["prefix"] == "8.8.8.0/24"
        assert serialized["start"] == "edge-1"
        assert len(serialized["paths"]) == 1
        assert serialized["paths"][0]["end_reason"] == "not_in_inventory"
        assert serialized["paths"][0]["hops"][0]["communities"] == ["7018:2500"]
