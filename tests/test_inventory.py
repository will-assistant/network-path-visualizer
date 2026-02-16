"""Tests for the inventory loader module."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from inventory import load_ansible_inventory, Inventory

INVENTORY_PATH = str(Path(__file__).parent.parent / "ansible" / "inventories" / "fis-production.yml")


class TestAnsibleInventoryLoader:

    def setup_method(self):
        self.inv = load_ansible_inventory(INVENTORY_PATH)

    def test_loads_devices(self):
        assert len(self.inv.devices) > 0

    def test_loads_sites(self):
        assert len(self.inv.sites) > 0
        assert "site1" in self.inv.sites
        assert "site2" in self.inv.sites

    def test_loads_regions(self):
        assert "americas" in self.inv.regions
        assert "emea" in self.inv.regions
        assert "apac" in self.inv.regions

    def test_americas_sites(self):
        americas = self.inv.regions["americas"]
        assert "site1" in americas
        assert "site2" in americas
        assert "site3" in americas
        assert "site4" in americas

    def test_emea_sites(self):
        emea = self.inv.regions["emea"]
        assert "site7" in emea
        assert "site8" in emea

    def test_apac_sites(self):
        apac = self.inv.regions["apac"]
        assert "site17" in apac


class TestDeviceLookup:

    def setup_method(self):
        self.inv = load_ansible_inventory(INVENTORY_PATH)

    def test_device_has_role(self):
        dev = self.inv.get_device("s1-wed01")
        assert dev is not None
        assert dev.role == "dcpe"

    def test_device_has_site(self):
        dev = self.inv.get_device("s1-wed01")
        assert dev.site == "site1"
        assert dev.site_number == 1

    def test_device_has_domain(self):
        dev = self.inv.get_device("s1-wed01")
        assert dev.domain == "pe_zone"

    def test_device_has_region(self):
        dev = self.inv.get_device("s1-wed01")
        assert dev.region == "americas"

    def test_agg_has_rr_role(self):
        dev = self.inv.get_device("s1-wcr01")
        assert dev is not None
        assert dev.role == "agg"
        assert dev.rr_role == "route_reflector"

    def test_agg_client(self):
        dev = self.inv.get_device("s1-wcr02")
        assert dev.rr_role == "client"

    def test_spe_device(self):
        dev = self.inv.get_device("s1-wex03")
        assert dev.role == "spe"
        assert dev.domain == "pe_zone"

    def test_ipe_device(self):
        dev = self.inv.get_device("s1-wei01")
        assert dev.role == "ipe"
        assert dev.domain == "inet_edge"

    def test_p_node_with_platform(self):
        dev = self.inv.get_device("s1-wcm01")
        assert dev is not None
        assert dev.role == "p_node"
        assert dev.platform == "mx480"
        assert dev.generation == "legacy"

    def test_wee_with_carrier(self):
        dev = self.inv.get_device("s1-wee03")
        assert dev is not None
        assert dev.role == "wan_pe_edge"
        assert dev.carrier == "sprint"


class TestSiteLookup:

    def setup_method(self):
        self.inv = load_ansible_inventory(INVENTORY_PATH)

    def test_site1_dcpe(self):
        site = self.inv.get_site("site1")
        assert site is not None
        assert len(site.dcpe) == 2
        assert "s1-wed01" in site.dcpe
        assert "s1-wed02" in site.dcpe

    def test_site1_spe(self):
        site = self.inv.get_site("site1")
        assert len(site.spe) == 2
        assert "s1-wex03" in site.spe

    def test_site1_agg(self):
        site = self.inv.get_site("site1")
        assert len(site.agg) == 2
        assert "s1-wcr01" in site.agg

    def test_site1_ipe(self):
        site = self.inv.get_site("site1")
        assert len(site.ipe) == 2

    def test_site1_p_nodes(self):
        site = self.inv.get_site("site1")
        assert len(site.p_nodes) == 6

    def test_site1_core_rr(self):
        site = self.inv.get_site("site1")
        assert len(site.core_rr) == 2
        assert "s1-wsr03" in site.core_rr

    def test_site1_wee(self):
        site = self.inv.get_site("site1")
        assert len(site.wee) == 4

    def test_site_number(self):
        site = self.inv.get_site("site1")
        assert site.site_number == 1
        site7 = self.inv.get_site("site7")
        assert site7.site_number == 7

    def test_site_region(self):
        assert self.inv.get_site("site1").region == "americas"
        assert self.inv.get_site("site7").region == "emea"
        assert self.inv.get_site("site17").region == "apac"


class TestConvenienceMethods:

    def setup_method(self):
        self.inv = load_ansible_inventory(INVENTORY_PATH)

    def test_get_agg_routers_all(self):
        aggs = self.inv.get_agg_routers()
        assert len(aggs) >= 8  # 2 per site, at least 4 sites

    def test_get_agg_routers_site(self):
        aggs = self.inv.get_agg_routers("site1")
        assert len(aggs) == 2

    def test_get_rr_routers(self):
        rrs = self.inv.get_rr_routers()
        assert len(rrs) >= 4  # At least 1 per site with RR

    def test_get_dcpe_for_site(self):
        dcpe = self.inv.get_dcpe_for_site("site2")
        assert len(dcpe) == 2

    def test_get_spe_for_site(self):
        spe = self.inv.get_spe_for_site("site1")
        assert len(spe) == 2

    def test_site_id_from_number(self):
        assert self.inv.site_id_from_number(1) == "site1"
        assert self.inv.site_id_from_number(17) == "site17"
        assert self.inv.site_id_from_number(99) is None

    def test_get_sites_in_region(self):
        americas = self.inv.get_sites_in_region("americas")
        assert len(americas) == 4
