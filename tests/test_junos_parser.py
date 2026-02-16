"""Tests for the Junos BGP route detail parser."""

import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from collectors.bgp import JunosRouteParser, resolve_att_city, BGPPath


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "att-8.8.8.0-24-detail.txt"


def load_fixture() -> str:
    return FIXTURE_PATH.read_text()


class TestJunosRouteParser:

    def test_parse_all_16_paths(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        assert len(paths) == 16, f"Expected 16 paths, got {len(paths)}"

    def test_prefix_extracted(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        assert all(p.prefix == "8.8.8.0/24" for p in paths)

    def test_exactly_one_active(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        active = [p for p in paths if p.active]
        assert len(active) == 1, f"Expected 1 active path, got {len(active)}"

    def test_active_path_details(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        best = [p for p in paths if p.active][0]
        assert best.next_hop == "12.122.83.238"
        assert best.as_path == "7018 15169"
        assert best.origin == "IGP"
        assert best.local_pref == 100
        assert best.peer_as == 7018

    def test_all_paths_have_next_hop(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        for p in paths:
            assert p.next_hop, f"Path missing next_hop: {p}"
            assert p.next_hop.startswith("12.122."), f"Unexpected next-hop: {p.next_hop}"

    def test_all_paths_have_as_path(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        for p in paths:
            assert "15169" in p.as_path, f"Missing AS15169 in path: {p.as_path}"
            assert "7018" in p.as_path, f"Missing AS7018 in path: {p.as_path}"

    def test_all_paths_have_communities(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        for p in paths:
            assert len(p.communities) >= 1, f"No communities: {p.next_hop}"
            assert any(c.startswith("7018:") for c in p.communities)

    def test_local_pref_all_100(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        for p in paths:
            assert p.local_pref == 100, f"Unexpected local_pref: {p.local_pref}"

    def test_med_is_zero(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        for p in paths:
            assert p.med == 0, f"Unexpected MED: {p.med}"

    def test_inactive_paths_have_reason(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        inactive = [p for p in paths if not p.active]
        assert len(inactive) == 15
        for p in inactive:
            assert p.inactive_reason is not None, f"No inactive reason for {p.next_hop}"

    def test_unique_next_hops(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        next_hops = [p.next_hop for p in paths]
        assert len(set(next_hops)) == 16, "Expected 16 unique next-hops"


class TestATTCityResolution:

    def test_known_cities(self):
        assert resolve_att_city(["7018:2500", "7018:36244"]) == "Washington, DC"
        assert resolve_att_city(["7018:2500", "7018:37232"]) == "Atlanta, GA"
        assert resolve_att_city(["7018:2500", "7018:39220"]) == "Los Angeles, CA"
        assert resolve_att_city(["7018:2500", "7018:33051"]) == "Chicago, IL"

    def test_unknown_community(self):
        assert resolve_att_city(["7018:2500", "7018:99999"]) is None

    def test_all_fixture_paths_resolve(self):
        output = load_fixture()
        paths = JunosRouteParser.parse(output)
        resolved = 0
        for p in paths:
            city = resolve_att_city(p.communities)
            if city:
                resolved += 1
        # We should resolve most of them
        assert resolved >= 10, f"Only resolved {resolved}/16 cities"


class TestParserEdgeCases:

    def test_empty_input(self):
        paths = JunosRouteParser.parse("")
        assert paths == []

    def test_no_bgp_entries(self):
        paths = JunosRouteParser.parse("inet.0: 0 destinations\n")
        assert paths == []

    def test_single_entry(self):
        single = """
8.8.8.0/24 (1 entries, 1 announced)
        *BGP    Preference: 170/-101
                Source: 10.0.0.1
                State: <Active Ext>
                Local AS: 65000 Peer AS:  7018
                AS path: 7018 15169 I 
                Communities: 7018:2500 7018:36244
                Localpref: 100
                Router ID: 10.0.0.1
"""
        paths = JunosRouteParser.parse(single)
        assert len(paths) == 1
        assert paths[0].active is True
        assert paths[0].next_hop == "10.0.0.1"
        assert paths[0].as_path == "7018 15169"
