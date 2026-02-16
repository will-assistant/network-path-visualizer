"""Tests for V3 Junos Collector parser — reuses Phase 1 fixture data."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from collectors.junos_collector import JunosParser
from collectors import RouteEntry


FIXTURE_PATH = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> str:
    return (FIXTURE_PATH / name).read_text()


class TestJunosParserV3:
    """V3 parser tests using the same Phase 1 fixtures."""

    def test_parse_att_16_paths(self):
        output = load_fixture("att-8.8.8.0-24-detail.txt")
        entries = JunosParser.parse(output)
        assert len(entries) == 16

    def test_entries_are_route_entry(self):
        output = load_fixture("att-8.8.8.0-24-detail.txt")
        entries = JunosParser.parse(output)
        for e in entries:
            assert isinstance(e, RouteEntry)

    def test_prefix_extracted(self):
        output = load_fixture("att-8.8.8.0-24-detail.txt")
        entries = JunosParser.parse(output)
        assert all(e.prefix == "8.8.8.0/24" for e in entries)

    def test_one_active(self):
        output = load_fixture("att-8.8.8.0-24-detail.txt")
        entries = JunosParser.parse(output)
        active = [e for e in entries if e.active]
        assert len(active) == 1

    def test_active_entry_details(self):
        output = load_fixture("att-8.8.8.0-24-detail.txt")
        entries = JunosParser.parse(output)
        best = [e for e in entries if e.active][0]
        assert best.next_hop == "12.122.83.238"
        assert best.as_path == ["7018", "15169"]
        assert best.protocol == "bgp"
        assert best.local_pref == 100
        assert best.peer_as == 7018

    def test_all_have_next_hop(self):
        output = load_fixture("att-8.8.8.0-24-detail.txt")
        entries = JunosParser.parse(output)
        for e in entries:
            assert e.next_hop
            assert e.next_hop.startswith("12.122.")

    def test_as_path_is_list(self):
        output = load_fixture("att-8.8.8.0-24-detail.txt")
        entries = JunosParser.parse(output)
        for e in entries:
            assert isinstance(e.as_path, list)
            assert "15169" in e.as_path
            assert "7018" in e.as_path

    def test_communities(self):
        output = load_fixture("att-8.8.8.0-24-detail.txt")
        entries = JunosParser.parse(output)
        for e in entries:
            assert len(e.communities) >= 1
            assert any(c.startswith("7018:") for c in e.communities)

    def test_tdc_14_paths(self):
        output = load_fixture("tdc-8.8.8.0-24-detail.txt")
        entries = JunosParser.parse(output)
        assert len(entries) == 14

    def test_cloudflare_16_paths(self):
        output = load_fixture("att-1.1.1.0-24-detail.txt")
        entries = JunosParser.parse(output)
        assert len(entries) == 16
        assert all(e.prefix == "1.1.1.0/24" for e in entries)

    def test_empty_input(self):
        assert JunosParser.parse("") == []

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
        entries = JunosParser.parse(single)
        assert len(entries) == 1
        e = entries[0]
        assert e.active is True
        assert e.next_hop == "10.0.0.1"
        assert e.as_path == ["7018", "15169"]
        assert e.local_pref == 100
        assert e.communities == ["7018:2500", "7018:36244"]
