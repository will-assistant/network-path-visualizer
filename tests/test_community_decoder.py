"""Tests for the community decoder module."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from community_decoder import (
    decode_communities,
    derive_firewall_from_nexthop,
    preferred_firewall_site,
    get_failover_chain,
    lp_to_preference,
    LP_PRIMARY,
    LP_SECONDARY,
    LP_TERTIARY,
)


class TestOIDDecode:
    def test_oid_site_1(self):
        result = decode_communities(["1:1594"])
        assert result.oid == 1
        assert result.origin_site == "Site-1"
        assert result.region == "americas"

    def test_oid_site_17(self):
        result = decode_communities(["17:1594"])
        assert result.oid == 17
        assert result.origin_site == "Site-17"
        assert result.region == "apac"

    def test_oid_site_7(self):
        result = decode_communities(["7:1594"])
        assert result.oid == 7
        assert result.origin_site == "Site-7"
        assert result.region == "emea"


class TestAIDDecode:
    def test_aid_site_2(self):
        result = decode_communities(["2:194"])
        assert result.aid == 2
        assert result.advertising_site == "Site-2"

    def test_aid_site_18(self):
        result = decode_communities(["18:194"])
        assert result.aid == 18
        assert result.advertising_site == "Site-18"


class TestCompoundDecode:
    def test_oid_aid_together(self):
        result = decode_communities(["1:1594", "3:194"])
        assert result.oid == 1
        assert result.aid == 3
        assert result.origin_site == "Site-1"
        assert result.advertising_site == "Site-3"
        assert result.region == "americas"

    def test_local_route_oid_equals_aid(self):
        result = decode_communities(["2:1594", "2:194"])
        assert result.oid == 2
        assert result.aid == 2
        assert result.preference == "primary"
        assert result.local_pref == LP_PRIMARY

    def test_explicit_lp_overrides(self):
        result = decode_communities(["1:1594", "3:194"], local_pref=150)
        assert result.local_pref == 150
        assert result.preference == "secondary"


class TestLPPreference:
    def test_lp_200_primary(self):
        assert lp_to_preference(200) == "primary"

    def test_lp_150_secondary(self):
        assert lp_to_preference(150) == "secondary"

    def test_lp_50_tertiary(self):
        assert lp_to_preference(50) == "tertiary"

    def test_lp_100_unknown(self):
        assert lp_to_preference(100) == "unknown"

    def test_lp_250_primary(self):
        assert lp_to_preference(250) == "primary"


class TestSecurityCommunities:
    def test_dmz_route(self):
        result = decode_communities(["41326:41326", "1:1594"])
        assert result.is_child_originated is True

    def test_child_route(self):
        result = decode_communities(["3124:3124", "17:1594"])
        assert result.is_child_originated is True

    def test_default_route(self):
        result = decode_communities(["1:0"])
        assert result.is_default_route is True


class TestFirewallDerivation:
    def test_americas_fw(self):
        fw = derive_firewall_from_nexthop("100.120.32.1")
        assert fw is not None
        assert fw.region == "americas"
        assert fw.vrf_id == 32

    def test_emea_fw(self):
        fw = derive_firewall_from_nexthop("100.123.44.2")
        assert fw is not None
        assert fw.region == "emea"
        assert fw.vrf_id == 44

    def test_apac_fw(self):
        fw = derive_firewall_from_nexthop("100.124.100.3")
        assert fw is not None
        assert fw.region == "apac"
        assert fw.vrf_id == 100

    def test_gmn_fw(self):
        fw = derive_firewall_from_nexthop("100.127.5.4")
        assert fw is not None
        assert fw.region == "gmn"
        assert fw.vrf_id == 5

    def test_non_fw_nexthop(self):
        fw = derive_firewall_from_nexthop("10.0.0.1")
        assert fw is None

    def test_invalid_ip(self):
        fw = derive_firewall_from_nexthop("not-an-ip")
        assert fw is None


class TestPreferredFirewall:
    def test_lowest_wins(self):
        assert preferred_firewall_site(1, 3) == 1
        assert preferred_firewall_site(3, 1) == 1
        assert preferred_firewall_site(2, 4) == 2

    def test_same_site(self):
        assert preferred_firewall_site(2, 2) == 2

    def test_apac(self):
        assert preferred_firewall_site(17, 19) == 17
        assert preferred_firewall_site(18, 19) == 18


class TestFailoverChains:
    def test_americas_chains(self):
        assert get_failover_chain(1) == [1, 2, 3]
        assert get_failover_chain(2) == [2, 3, 1]
        assert get_failover_chain(3) == [3, 2, 1]
        assert get_failover_chain(4) == [4, 3, 2]

    def test_apac_chains(self):
        assert get_failover_chain(17) == [17, 18, 19]
        assert get_failover_chain(18) == [18, 17, 19]

    def test_unknown_site(self):
        assert get_failover_chain(99) == [99]


class TestEdgeCases:
    def test_empty_communities(self):
        result = decode_communities([])
        assert result.oid is None
        assert result.aid is None
        assert result.preference is None

    def test_no_oid_aid(self):
        result = decode_communities(["7018:2500", "7018:36244"])
        assert result.oid is None
        assert result.aid is None

    def test_raw_communities_preserved(self):
        comms = ["1:1594", "2:194", "7018:5000"]
        result = decode_communities(comms)
        assert result.raw_communities == comms

    def test_standard_communities_collected(self):
        result = decode_communities(["1:1594", "7018:5000", "2:194"])
        assert "7018:5000" in result.standard_communities
        assert len(result.standard_communities) == 1
