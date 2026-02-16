"""Tests for V3 Path Walker — generic next-hop follower."""

import sys
import asyncio
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from path_walker import PathWalker, TraceResult
from inventory import Inventory
from collectors import RouteEntry


# --- Test inventory ---

MOCK_INVENTORY = """
devices:
  router-a:
    management_ip: 10.0.0.1
    vendor: juniper
    role: edge
    loopbacks: [192.168.255.1]
    interfaces:
      et-0/0/0: 10.1.1.1

  router-b:
    management_ip: 10.0.0.2
    vendor: juniper
    role: core
    loopbacks: [192.168.255.2]
    interfaces:
      et-0/0/0: 10.1.1.2
      et-0/0/1: 10.2.1.1

  router-c:
    management_ip: 10.0.0.3
    vendor: juniper
    role: pe
    loopbacks: [192.168.255.3]
    interfaces:
      ge-0/0/0: 10.2.1.2
      ge-0/0/1: 10.3.1.1

  router-d:
    management_ip: 10.0.0.4
    vendor: juniper
    role: pe
    loopbacks: [192.168.255.4]
    interfaces:
      ge-0/0/0: 10.3.1.2
"""


def _make_inventory() -> Inventory:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(MOCK_INVENTORY)
        f.flush()
        return Inventory.from_yaml(f.name)


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


# --- Mock collector responses ---

def make_mock_collector(responses: dict):
    """Create a mock collector_fn from a dict of device→RouteEntry list."""
    async def collector_fn(device: str, prefix: str, vrf: str) -> list[RouteEntry]:
        if device in responses:
            return responses[device]
        return []
    return collector_fn


class TestLinearTrace:
    """Test a simple linear path: A → B → C → D (origin)."""

    def test_linear_path(self):
        inv = _make_inventory()
        responses = {
            "router-a": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp", next_hop="10.1.1.2",
                                     as_path=["7018", "15169"], local_pref=100, active=True)],
            "router-b": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp", next_hop="10.2.1.2",
                                     as_path=["15169"], local_pref=200, active=True)],
            "router-c": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp", next_hop="10.3.1.2",
                                     as_path=["15169"], active=True)],
            "router-d": [RouteEntry(prefix="8.8.8.0/24", protocol="connected", active=True)],
        }
        walker = PathWalker(inv, make_mock_collector(responses))
        result = run(walker.trace("8.8.8.0/24", "router-a"))

        assert len(result.paths) == 1
        path = result.paths[0]
        assert path.complete is True
        assert path.end_reason == "origin"
        # 3 BGP hops + 1 connected hop = 4 hops
        assert len(path.hops) == 4
        assert path.hops[0].device == "router-a"
        assert path.hops[1].device == "router-b"
        assert path.hops[2].device == "router-c"
        assert path.hops[3].device == "router-d"

    def test_hop_details(self):
        inv = _make_inventory()
        responses = {
            "router-a": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp", next_hop="10.1.1.2",
                                     as_path=["7018", "15169"], local_pref=100, active=True,
                                     communities=["7018:2500"])],
            "router-b": [RouteEntry(prefix="8.8.8.0/24", protocol="connected", active=True)],
        }
        walker = PathWalker(inv, make_mock_collector(responses))
        result = run(walker.trace("8.8.8.0/24", "router-a"))

        hop = result.paths[0].hops[0]
        assert hop.protocol == "bgp"
        assert hop.next_hop == "10.1.1.2"
        assert hop.as_path == ["7018", "15169"]
        assert hop.lp == 100
        assert hop.communities == ["7018:2500"]


class TestBlackhole:
    def test_no_route(self):
        inv = _make_inventory()
        responses = {
            "router-a": [],  # No route
        }
        walker = PathWalker(inv, make_mock_collector(responses))
        result = run(walker.trace("10.99.0.0/24", "router-a"))

        assert len(result.paths) == 1
        assert result.paths[0].end_reason == "blackhole"
        assert result.paths[0].complete is False


class TestNotInInventory:
    def test_next_hop_unknown(self):
        inv = _make_inventory()
        responses = {
            "router-a": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                                     next_hop="99.99.99.99", active=True)],
        }
        walker = PathWalker(inv, make_mock_collector(responses))
        result = run(walker.trace("8.8.8.0/24", "router-a"))

        assert len(result.paths) == 1
        assert result.paths[0].end_reason == "not_in_inventory"
        assert result.paths[0].complete is False
        # Should have 2 hops: router-a + unknown
        assert len(result.paths[0].hops) == 2
        assert "unknown" in result.paths[0].hops[1].device


class TestLoopDetection:
    def test_routing_loop(self):
        inv = _make_inventory()
        responses = {
            "router-a": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                                     next_hop="10.1.1.2", active=True)],
            "router-b": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                                     next_hop="10.1.1.1", active=True)],  # Points back to A
        }
        walker = PathWalker(inv, make_mock_collector(responses))
        result = run(walker.trace("8.8.8.0/24", "router-a"))

        assert len(result.paths) == 1
        assert result.paths[0].end_reason == "loop"
        assert result.paths[0].complete is False


class TestECMP:
    def test_ecmp_branching(self):
        """Two equal-cost next-hops should produce two paths."""
        inv = _make_inventory()

        # router-a has ECMP: two active entries pointing to B and C
        ecmp_entry = RouteEntry(
            prefix="8.8.8.0/24", protocol="bgp", next_hop="10.1.1.2",
            active=True, as_path=["15169"],
            paths=[RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                              next_hop="10.2.1.2", active=True)],
        )

        responses = {
            "router-a": [ecmp_entry],
            "router-b": [RouteEntry(prefix="8.8.8.0/24", protocol="connected", active=True)],
            "router-c": [RouteEntry(prefix="8.8.8.0/24", protocol="connected", active=True)],
        }
        walker = PathWalker(inv, make_mock_collector(responses))
        result = run(walker.trace("8.8.8.0/24", "router-a"))

        assert len(result.paths) == 2
        # Both should complete at origin
        reasons = {p.end_reason for p in result.paths}
        assert reasons == {"origin"}

        # One goes through B, one through C
        devices_per_path = [
            [h.device for h in p.hops]
            for p in result.paths
        ]
        # Both start with router-a
        assert all(d[0] == "router-a" for d in devices_per_path)

    def test_ecmp_mixed_outcomes(self):
        """ECMP where one path reaches origin and one hits unknown."""
        inv = _make_inventory()

        ecmp_entry = RouteEntry(
            prefix="8.8.8.0/24", protocol="bgp", next_hop="10.1.1.2",
            active=True,
            paths=[RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                              next_hop="99.99.99.99", active=True)],
        )

        responses = {
            "router-a": [ecmp_entry],
            "router-b": [RouteEntry(prefix="8.8.8.0/24", protocol="connected", active=True)],
        }
        walker = PathWalker(inv, make_mock_collector(responses))
        result = run(walker.trace("8.8.8.0/24", "router-a"))

        assert len(result.paths) == 2
        reasons = {p.end_reason for p in result.paths}
        assert "origin" in reasons
        assert "not_in_inventory" in reasons


class TestUnreachable:
    def test_device_unreachable(self):
        inv = _make_inventory()

        async def failing_collector(device, prefix, vrf):
            if device == "router-a":
                raise ConnectionError("Connection refused")
            return []

        walker = PathWalker(inv, failing_collector)
        result = run(walker.trace("8.8.8.0/24", "router-a"))

        assert len(result.paths) == 1
        assert result.paths[0].end_reason == "unreachable"


class TestPlugins:
    def test_plugin_labels_attached(self):
        from plugins import CommunityDecoderPlugin

        class MockPlugin(CommunityDecoderPlugin):
            def name(self): return "test-plugin"
            def decode(self, communities, local_pref=None):
                if "7018:2500" in communities:
                    return {"network": "AT&T"}
                return {}

        inv = _make_inventory()
        responses = {
            "router-a": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                                     next_hop="10.1.1.2", active=True,
                                     communities=["7018:2500"])],
            "router-b": [RouteEntry(prefix="8.8.8.0/24", protocol="connected", active=True)],
        }
        walker = PathWalker(inv, make_mock_collector(responses), plugins=[MockPlugin()])
        result = run(walker.trace("8.8.8.0/24", "router-a"))

        hop = result.paths[0].hops[0]
        assert "test-plugin" in hop.plugin_labels
        assert hop.plugin_labels["test-plugin"]["network"] == "AT&T"


class TestMaxHops:
    def test_max_hops_limit(self):
        inv = _make_inventory()
        # Create a chain that's too long (but uses real inventory IPs)
        # With only 4 devices, a loop would be caught first.
        # Test with max_hops=2
        responses = {
            "router-a": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                                     next_hop="10.1.1.2", active=True)],
            "router-b": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                                     next_hop="10.2.1.2", active=True)],
            "router-c": [RouteEntry(prefix="8.8.8.0/24", protocol="bgp",
                                     next_hop="10.3.1.2", active=True)],
            "router-d": [RouteEntry(prefix="8.8.8.0/24", protocol="connected", active=True)],
        }
        walker = PathWalker(inv, make_mock_collector(responses), max_hops=2)
        result = run(walker.trace("8.8.8.0/24", "router-a"))

        assert len(result.paths) == 1
        assert result.paths[0].end_reason == "max_hops"
