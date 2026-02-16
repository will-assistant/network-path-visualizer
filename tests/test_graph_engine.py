"""Tests for the GraphEngine inventory loader and topology."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from graph_engine import GraphEngine
from models import DeviceRole

INVENTORY_PATH = str(Path(__file__).parent.parent / "data" / "inventory.yaml")


class TestGraphEngine:

    def setup_method(self):
        self.graph = GraphEngine()
        self.graph.load_inventory(INVENTORY_PATH)

    def test_loads_all_routers(self):
        assert len(self.graph.routers) == 13

    def test_loads_domains(self):
        assert len(self.graph.domains) == 4
        assert "backbone" in self.graph.domains
        assert "pe-east" in self.graph.domains

    def test_loads_boundaries(self):
        assert len(self.graph.boundaries) == 3

    def test_pe_routers(self):
        pes = self.graph.get_routers_by_role(DeviceRole.PE)
        assert len(pes) == 4
        names = {r.hostname for r in pes}
        assert "pe-nyc-01" in names

    def test_edge_routers(self):
        edges = self.graph.get_routers_by_role(DeviceRole.EDGE)
        assert len(edges) == 2

    def test_firewalls(self):
        fws = self.graph.get_routers_by_role(DeviceRole.FIREWALL)
        assert len(fws) == 3

    def test_graph_has_edges(self):
        assert self.graph.graph.number_of_edges() > 0

    def test_path_pe_to_edge(self):
        path = self.graph.shortest_path("pe-nyc-01", "edge-01")
        assert len(path) > 0
        assert path[0] == "pe-nyc-01"
        assert path[-1] == "edge-01"

    def test_vis_json_output(self):
        data = self.graph.to_vis_json()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 13
        assert len(data["edges"]) > 0

    def test_vis_nodes_have_required_fields(self):
        data = self.graph.to_vis_json()
        for node in data["nodes"]:
            assert "id" in node
            assert "label" in node
            assert "color" in node
            assert "shape" in node
