"""Tests for the V2 AGG-first path walker."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from path_walker import PathWalkerV2, DerivedPath, TraceResult
from collectors.bgp import BGPPath
from inventory import load_ansible_inventory

INVENTORY_PATH = str(Path(__file__).parent.parent / "ansible" / "inventories" / "fis-production.yml")


def make_bgp_path(
    next_hop="10.0.0.1",
    as_path="7018 15169",
    communities=None,
    local_pref=100,
    active=False,
    med=0,
):
    return BGPPath(
        prefix="10.0.0.0/24",
        next_hop=next_hop,
        as_path=as_path,
        origin="IGP",
        local_pref=local_pref,
        med=med,
        communities=communities or [],
        active=active,
    )


class TestPathWalkerV2Basic:

    def setup_method(self):
        self.walker = PathWalkerV2()

    def test_empty_paths(self):
        result = self.walker.derive_paths([], "10.0.0.0/24")
        assert isinstance(result, TraceResult)
        assert len(result.paths) == 0
        assert result.primary_path is None

    def test_single_path(self):
        paths = [make_bgp_path(active=True)]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        assert len(result.paths) == 1
        assert result.primary_path is not None

    def test_multiple_paths(self):
        paths = [
            make_bgp_path(next_hop="10.0.0.1", active=True),
            make_bgp_path(next_hop="10.0.0.2"),
            make_bgp_path(next_hop="10.0.0.3"),
        ]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        assert len(result.paths) == 3
        assert result.raw_path_count == 3


class TestCommunityDrivenPaths:

    def setup_method(self):
        self.walker = PathWalkerV2()

    def test_oid_aid_decoded(self):
        paths = [make_bgp_path(
            communities=["1:1594", "2:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        assert dp.origin_site == "Site-1"
        assert dp.advertising_site == "Site-2"
        assert dp.preference == "primary"
        assert dp.local_pref == 200

    def test_secondary_path(self):
        paths = [make_bgp_path(
            communities=["3:1594", "1:194"],
            local_pref=150,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        assert dp.preference == "secondary"

    def test_tertiary_path(self):
        paths = [make_bgp_path(
            communities=["1:1594", "3:194"],
            local_pref=50,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        assert dp.preference == "tertiary"

    def test_firewall_derived_americas(self):
        paths = [make_bgp_path(
            next_hop="100.120.32.1",
            communities=["1:1594", "1:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        assert dp.firewall is not None
        assert dp.firewall.region == "americas"
        assert dp.firewall.vrf_id == 32

    def test_firewall_derived_emea(self):
        paths = [make_bgp_path(
            next_hop="100.123.44.2",
            communities=["7:1594", "7:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        assert dp.firewall.region == "emea"

    def test_firewall_derived_apac(self):
        paths = [make_bgp_path(
            next_hop="100.124.10.3",
            communities=["17:1594", "17:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        assert dp.firewall.region == "apac"


class TestPathSorting:

    def setup_method(self):
        self.walker = PathWalkerV2()

    def test_primary_first(self):
        paths = [
            make_bgp_path(next_hop="10.0.0.3", communities=["1:1594", "3:194"], local_pref=50),
            make_bgp_path(next_hop="10.0.0.1", communities=["1:1594", "1:194"], local_pref=200),
            make_bgp_path(next_hop="10.0.0.2", communities=["1:1594", "2:194"], local_pref=150),
        ]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        assert result.paths[0].preference == "primary"
        assert result.paths[1].preference == "secondary"
        assert result.paths[2].preference == "tertiary"

    def test_primary_path_set(self):
        paths = [
            make_bgp_path(communities=["1:1594", "1:194"], local_pref=200, active=True),
        ]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        assert result.primary_path is not None
        assert result.primary_path.preference == "primary"


class TestWithInventory:

    def setup_method(self):
        inv = load_ansible_inventory(INVENTORY_PATH)
        self.walker = PathWalkerV2(inventory=inv)

    def test_hop_list_with_inventory(self):
        paths = [make_bgp_path(
            communities=["1:1594", "1:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        # Should have hops: DCPE, SPE, T2_FW (from AID), AGG
        assert len(dp.hops) >= 3
        roles = [h.role for h in dp.hops]
        assert "dcpe" in roles
        assert "agg" in roles

    def test_hop_devices_from_inventory(self):
        paths = [make_bgp_path(
            communities=["1:1594", "1:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        # DCPE should resolve to actual hostname from inventory
        dcpe_hop = [h for h in dp.hops if h.role == "dcpe"][0]
        assert dcpe_hop.device == "s1-wed01"

    def test_spe_from_inventory(self):
        paths = [make_bgp_path(
            communities=["2:1594", "2:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        spe_hops = [h for h in dp.hops if h.role == "spe"]
        assert len(spe_hops) == 1
        assert spe_hops[0].device == "s2-wex03"

    def test_agg_rr_from_inventory(self):
        paths = [make_bgp_path(
            communities=["1:1594", "1:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        agg_hops = [h for h in dp.hops if h.role == "agg"]
        assert len(agg_hops) == 1
        assert agg_hops[0].device == "s1-wcr01"  # RR at site1


class TestDescription:

    def setup_method(self):
        self.walker = PathWalkerV2()

    def test_description_generated(self):
        paths = [make_bgp_path(
            communities=["1:1594", "2:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        assert dp.description
        assert "Primary" in dp.description
        assert "Site-1" in dp.description

    def test_description_with_firewall(self):
        paths = [make_bgp_path(
            next_hop="100.120.32.1",
            communities=["1:1594", "1:194"],
            local_pref=200,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        assert "AMERICAS" in dp.description


class TestRawOutputParsing:

    def setup_method(self):
        self.walker = PathWalkerV2()

    def test_derive_from_fixture(self):
        fixture = Path(__file__).parent / "fixtures" / "att-8.8.8.0-24-detail.txt"
        if fixture.exists():
            raw = fixture.read_text()
            result = self.walker.derive_paths_from_raw_output(raw, "8.8.8.0/24")
            assert result.raw_path_count == 16
            assert len(result.paths) == 16


class TestNoInventory:
    """Test that walker works gracefully without inventory."""

    def setup_method(self):
        self.walker = PathWalkerV2(inventory=None)

    def test_generates_placeholder_hops(self):
        paths = [make_bgp_path(
            communities=["3:1594", "1:194"],
            local_pref=150,
        )]
        result = self.walker.derive_paths(paths, "10.0.0.0/24")
        dp = result.paths[0]
        assert len(dp.hops) >= 2
        # Should have placeholder device names
        dcpe_hop = [h for h in dp.hops if h.role == "dcpe"][0]
        assert "site-3" in dcpe_hop.device or "Site-3" in dcpe_hop.label
