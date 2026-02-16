"""Tests for the 7-tier MPLS GraphEngine."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from graph_engine import GraphEngine
from models import DeviceRole, RRTier, VRFType

INVENTORY_PATH = str(Path(__file__).parent.parent / "data" / "inventory.yaml")


class TestGraphEngine:

    def setup_method(self):
        self.graph = GraphEngine()
        self.graph.load_inventory(INVENTORY_PATH)

    def test_loads_all_routers(self):
        # 2 DCCE + 2 DCPE + 2 SPE + 2 T2-FW + 2 AGG + 3 RR + 2 T1-FW + 2 IPE = 17
        assert len(self.graph.routers) == 17

    def test_loads_domains(self):
        assert len(self.graph.domains) == 6
        assert "agg-backbone" in self.graph.domains
        assert "dc-east" in self.graph.domains

    def test_loads_boundaries(self):
        assert len(self.graph.boundaries) == 4  # 2 T2 + 2 T1

    def test_boundary_tiers(self):
        t1 = [b for b in self.graph.boundaries if b.tier == "t1"]
        t2 = [b for b in self.graph.boundaries if b.tier == "t2"]
        assert len(t1) == 2
        assert len(t2) == 2


class TestSevenTiers:

    def setup_method(self):
        self.graph = GraphEngine()
        self.graph.load_inventory(INVENTORY_PATH)

    def test_tier_1_dcce(self):
        dcce = self.graph.get_routers_by_role(DeviceRole.DCCE)
        assert len(dcce) == 2
        assert all(r.tier == 1 for r in dcce)

    def test_tier_2_dcpe(self):
        dcpe = self.graph.get_routers_by_role(DeviceRole.DCPE)
        assert len(dcpe) == 2
        assert all(r.tier == 2 for r in dcpe)

    def test_tier_3_spe(self):
        spe = self.graph.get_routers_by_role(DeviceRole.SPE)
        assert len(spe) == 2
        assert all(r.tier == 3 for r in spe)

    def test_tier_4_t2fw(self):
        t2fw = self.graph.get_routers_by_role(DeviceRole.T2_FIREWALL)
        assert len(t2fw) == 2
        assert all(r.tier == 4 for r in t2fw)

    def test_tier_5_agg(self):
        agg = self.graph.get_routers_by_role(DeviceRole.AGG)
        assert len(agg) == 2
        assert all(r.tier == 5 for r in agg)

    def test_tier_6_t1fw(self):
        t1fw = self.graph.get_routers_by_role(DeviceRole.T1_FIREWALL)
        assert len(t1fw) == 2
        assert all(r.tier == 6 for r in t1fw)

    def test_tier_7_ipe(self):
        ipe = self.graph.get_routers_by_role(DeviceRole.IPE)
        assert len(ipe) == 2
        assert all(r.tier == 7 for r in ipe)

    def test_get_by_tier(self):
        tier5 = self.graph.get_routers_by_tier(5)
        # 2 AGG + 3 RR
        assert len(tier5) == 5


class TestRouteReflectors:

    def setup_method(self):
        self.graph = GraphEngine()
        self.graph.load_inventory(INVENTORY_PATH)

    def test_three_rr_tiers(self):
        rrs = self.graph.get_routers_by_role(DeviceRole.RR)
        assert len(rrs) == 3
        tiers = {r.rr_tier for r in rrs}
        assert tiers == {RRTier.CORE, RRTier.AGG, RRTier.INET}

    def test_get_rr_by_tier(self):
        core_rr = self.graph.get_rr_by_tier(RRTier.CORE)
        assert len(core_rr) == 1
        assert core_rr[0].hostname == "rr-core-01"

        inet_rr = self.graph.get_rr_by_tier(RRTier.INET)
        assert len(inet_rr) == 1
        assert inet_rr[0].hostname == "rr-inet-01"


class TestVRFs:

    def setup_method(self):
        self.graph = GraphEngine()
        self.graph.load_inventory(INVENTORY_PATH)

    def test_spe_has_vrfs(self):
        spe = self.graph.get_routers_by_role(DeviceRole.SPE)
        for r in spe:
            assert len(r.vrfs) == 2  # CUST-A (child) + GATEWAY (parent)

    def test_parent_child_relationship(self):
        spe = self.graph.routers["spe-east-01"]
        child = [v for v in spe.vrfs if v.vrf_type == VRFType.CHILD]
        parent = [v for v in spe.vrfs if v.vrf_type == VRFType.PARENT]
        assert len(child) == 1
        assert len(parent) == 1
        assert child[0].parent_vrf == parent[0].name

    def test_get_routers_with_vrf(self):
        routers = self.graph.get_routers_with_vrf("CUST-A")
        assert len(routers) == 2  # Both SPEs

    def test_get_child_vrfs(self):
        children = self.graph.get_child_vrfs("GATEWAY")
        assert len(children) == 2
        for router, vrf in children:
            assert vrf.name == "CUST-A"
            assert router.role == DeviceRole.SPE


class TestPaths:

    def setup_method(self):
        self.graph = GraphEngine()
        self.graph.load_inventory(INVENTORY_PATH)

    def test_full_south_to_north_path(self):
        """DCCE → DCPE → SPE → T2-FW → AGG → T1-FW → IPE."""
        path = self.graph.shortest_path("dcce-east-01", "ipe-east-01")
        assert len(path) == 7
        assert path[0] == "dcce-east-01"
        assert path[-1] == "ipe-east-01"

    def test_cross_site_path(self):
        path = self.graph.shortest_path("dcce-east-01", "ipe-west-01")
        assert len(path) > 0
        assert "agg-east-01" in path or "agg-west-01" in path

    def test_vis_json_output(self):
        data = self.graph.to_vis_json()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 17

    def test_vis_nodes_have_required_fields(self):
        data = self.graph.to_vis_json()
        for node in data["nodes"]:
            assert "id" in node
            assert "label" in node
            assert "color" in node
            assert "shape" in node

    def test_sites(self):
        east = self.graph.get_routers_by_site("east")
        west = self.graph.get_routers_by_site("west")
        assert len(east) >= 7
        assert len(west) >= 7

    def test_firewall_tier_lookup(self):
        assert self.graph.get_firewall_tier("t2fw-east-01") == "t2"
        assert self.graph.get_firewall_tier("t1fw-east-01") == "t1"
        assert self.graph.get_firewall_tier("agg-east-01") is None
