"""Tests for V3 JunosParser using real captured data from AT&T and GTT route servers."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from collectors.junos_collector import JunosParser

FIXTURES = Path(__file__).parent / "fixtures"


class TestATTParser:
    """Parse real AT&T route-server output for 8.8.8.0/24."""

    def setup_method(self):
        self.output = (FIXTURES / "att_8.8.8.0_24.txt").read_text()
        self.entries = JunosParser.parse(self.output, "8.8.8.0/24")

    def test_entry_count(self):
        assert len(self.entries) == 16

    def test_one_active(self):
        active = [e for e in self.entries if e.active]
        assert len(active) == 1

    def test_active_has_data(self):
        best = [e for e in self.entries if e.active][0]
        assert best.next_hop.startswith("12.122.")
        assert best.as_path == ["7018", "15169"]
        assert best.local_pref == 100
        assert best.peer_as == 7018
        assert any(c.startswith("7018:") for c in best.communities)

    def test_all_have_next_hop(self):
        for e in self.entries:
            assert e.next_hop, f"Missing next_hop"

    def test_all_have_as_path(self):
        for e in self.entries:
            assert "15169" in e.as_path
            assert "7018" in e.as_path

    def test_all_have_communities(self):
        for e in self.entries:
            assert len(e.communities) >= 1

    def test_all_lp_100(self):
        for e in self.entries:
            assert e.local_pref == 100

    def test_inactive_have_reason(self):
        inactive = [e for e in self.entries if not e.active]
        assert len(inactive) == 15
        for e in inactive:
            assert e.inactive_reason


class TestGTTParser:
    """Parse real GTT route-server output for 8.8.8.0/24."""

    def setup_method(self):
        self.output = (FIXTURES / "gtt_8.8.8.0_24.txt").read_text()
        self.entries = JunosParser.parse(self.output, "8.8.8.0/24")

    def test_entry_count(self):
        assert len(self.entries) == 8

    def test_one_active(self):
        active = [e for e in self.entries if e.active]
        assert len(active) == 1

    def test_active_has_data(self):
        best = [e for e in self.entries if e.active][0]
        assert best.next_hop.startswith("213.200.87.")
        assert best.as_path == ["3257", "15169"]
        assert best.local_pref == 100
        assert best.peer_as == 3257

    def test_as_path_not_recorded(self):
        """Regression: parser must not pick up 'AS path: Recorded' line."""
        for e in self.entries:
            assert "Recorded" not in e.as_path
            assert "3257" in e.as_path
            assert "15169" in e.as_path

    def test_all_have_communities(self):
        for e in self.entries:
            assert len(e.communities) >= 1
            assert any(c.startswith("3257:") for c in e.communities)

    def test_all_lp_100(self):
        for e in self.entries:
            assert e.local_pref == 100


class TestParserEdgeCases:

    def test_empty_input(self):
        assert JunosParser.parse("", "1.2.3.0/24") == []

    def test_no_bgp(self):
        assert JunosParser.parse("inet.0: 0 destinations\n", "1.2.3.0/24") == []

    def test_single_entry(self):
        single = """
8.8.8.0/24 (1 entries, 1 announced)
        *BGP    Preference: 170/-101
                Source: 10.0.0.1
                State: <Active Ext>
                Local AS: 65000 Peer AS:  7018
                AS path: 7018 15169 I
                Communities: 7018:2500
                Localpref: 100
                Router ID: 10.0.0.1
"""
        entries = JunosParser.parse(single, "8.8.8.0/24")
        assert len(entries) == 1
        assert entries[0].active
        assert entries[0].next_hop == "10.0.0.1"
        assert entries[0].as_path == ["7018", "15169"]

    def test_as_path_recorded_skipped(self):
        """Ensure 'AS path: Recorded' is ignored."""
        block = """
8.8.8.0/24 (1 entries, 1 announced)
        *BGP    Preference: 170/-101
                Source: 10.0.0.1
                State: <Active Ext>
                Local AS: 65000 Peer AS:  3257
                AS path: 3257 15169 I
                AS path: Recorded
                Communities: 3257:50001
                Localpref: 100
                Router ID: 10.0.0.1
"""
        entries = JunosParser.parse(block, "8.8.8.0/24")
        assert len(entries) == 1
        assert entries[0].as_path == ["3257", "15169"]
