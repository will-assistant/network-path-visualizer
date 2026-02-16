"""
Inventory Loader — Parse Ansible YAML inventory into device/site lookup maps.

Supports the FIS production inventory format (nested children groups)
and the simpler flat inventory format used by the mock topology.

Builds three lookup structures:
1. device_lookup: hostname → DeviceInfo
2. site_lookup: site_id → SiteInfo (lists of devices by role)
3. domain_boundaries: firewall addressing → region mapping
"""

from __future__ import annotations

import re
import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DeviceInfo:
    """Flat device record for quick lookups."""
    hostname: str
    ip: Optional[str] = None   # May be vault reference in prod
    role: str = ""             # dcpe, spe, agg, ipe, p_node, core_rr, wan_pe_edge
    domain: str = ""           # pe_zone, backbone, inet_edge, carrier_vrf
    site: str = ""             # "site1", "site2", etc.
    site_number: Optional[int] = None
    tier: Optional[int] = None
    platform: Optional[str] = None
    region: Optional[str] = None   # americas, emea, apac
    rr_role: Optional[str] = None  # route_reflector, client
    asn: Optional[int] = None
    carrier: Optional[str] = None
    generation: Optional[str] = None
    extra: dict = field(default_factory=dict)


@dataclass
class SiteInfo:
    """All devices at a site, organized by role."""
    site_id: str               # "site1", "site2", etc.
    site_number: int
    region: str                # "americas", "emea", "apac"
    dcpe: list[str] = field(default_factory=list)
    spe: list[str] = field(default_factory=list)
    agg: list[str] = field(default_factory=list)
    ipe: list[str] = field(default_factory=list)
    p_nodes: list[str] = field(default_factory=list)
    core_rr: list[str] = field(default_factory=list)
    wee: list[str] = field(default_factory=list)
    all_devices: list[str] = field(default_factory=list)


@dataclass
class Inventory:
    """Complete parsed inventory."""
    devices: dict[str, DeviceInfo] = field(default_factory=dict)
    sites: dict[str, SiteInfo] = field(default_factory=dict)
    regions: dict[str, list[str]] = field(default_factory=dict)  # region → [site_ids]

    def get_device(self, hostname: str) -> Optional[DeviceInfo]:
        return self.devices.get(hostname)

    def get_site(self, site_id: str) -> Optional[SiteInfo]:
        return self.sites.get(site_id)

    def get_agg_routers(self, site_id: Optional[str] = None) -> list[DeviceInfo]:
        """Get AGG routers, optionally filtered by site."""
        if site_id:
            site = self.sites.get(site_id)
            if site:
                return [self.devices[h] for h in site.agg if h in self.devices]
            return []
        return [d for d in self.devices.values() if d.role == "agg"]

    def get_rr_routers(self, site_id: Optional[str] = None) -> list[DeviceInfo]:
        """Get route reflector AGG routers (wcr01 pattern)."""
        aggs = self.get_agg_routers(site_id)
        return [a for a in aggs if a.rr_role == "route_reflector"]

    def get_dcpe_for_site(self, site_id: str) -> list[DeviceInfo]:
        site = self.sites.get(site_id)
        if not site:
            return []
        return [self.devices[h] for h in site.dcpe if h in self.devices]

    def get_spe_for_site(self, site_id: str) -> list[DeviceInfo]:
        site = self.sites.get(site_id)
        if not site:
            return []
        return [self.devices[h] for h in site.spe if h in self.devices]

    def site_id_from_number(self, num: int) -> Optional[str]:
        """Look up site_id from site number."""
        for sid, site in self.sites.items():
            if site.site_number == num:
                return sid
        return None

    def get_sites_in_region(self, region: str) -> list[SiteInfo]:
        site_ids = self.regions.get(region, [])
        return [self.sites[s] for s in site_ids if s in self.sites]


# Site number extraction from group names or hostnames
_SITE_NUM_RE = re.compile(r'site(\d+)')
_HOST_SITE_RE = re.compile(r'^s(\d+)-')


def _extract_site_number(name: str) -> Optional[int]:
    """Extract site number from group name like 'site1' or hostname like 's1-wed01'."""
    m = _SITE_NUM_RE.search(name)
    if m:
        return int(m.group(1))
    m = _HOST_SITE_RE.match(name)
    if m:
        return int(m.group(1))
    return None


# Region names from inventory structure
_REGION_MAP = {
    "americas": "americas",
    "emea": "emea",
    "apac": "apac",
}

# Role suffix patterns in group names
_ROLE_PATTERNS = {
    "_dcpe": ("dcpe", "pe_zone", 1),
    "_spe": ("spe", "pe_zone", 2),
    "_agg": ("agg", "backbone", 4),
    "_ipe": ("ipe", "inet_edge", 7),
    "_p_nodes": ("p_node", "backbone", None),
    "_core_rr": ("core_rr", "backbone", None),
    "_wee": ("wan_pe_edge", "carrier_vrf", None),
}


def load_ansible_inventory(path: str | Path) -> Inventory:
    """
    Parse Ansible YAML inventory in the FIS production format.

    Handles the nested children structure:
      all → children → {region} → children → {siteN} → children → {siteN_role} → hosts
    """
    path = Path(path)
    with open(path) as f:
        raw = yaml.safe_load(f)

    inv = Inventory()

    if not raw or "all" not in raw:
        return inv

    all_section = raw["all"]
    global_vars = all_section.get("vars", {})
    children = all_section.get("children", {})

    # Walk the tree: region → site → role_group → hosts
    for region_name, region_data in children.items():
        normalized_region = _REGION_MAP.get(region_name)

        if not isinstance(region_data, dict) or "children" not in region_data:
            # Non-region groups (firewalls, panorama, public_route_servers, carrier_edge)
            _process_flat_group(inv, region_name, region_data, global_vars)
            continue

        if normalized_region:
            inv.regions.setdefault(normalized_region, [])

        for site_name, site_data in region_data.get("children", {}).items():
            site_num = _extract_site_number(site_name)
            if site_num is None:
                continue

            site_id = f"site{site_num}"
            if normalized_region:
                if site_id not in inv.regions[normalized_region]:
                    inv.regions[normalized_region].append(site_id)

            # Ensure SiteInfo exists
            if site_id not in inv.sites:
                inv.sites[site_id] = SiteInfo(
                    site_id=site_id,
                    site_number=site_num,
                    region=normalized_region or "unknown",
                )

            site_info = inv.sites[site_id]

            if not isinstance(site_data, dict) or "children" not in site_data:
                continue

            for role_group, role_data in site_data.get("children", {}).items():
                if not isinstance(role_data, dict):
                    continue

                group_vars = role_data.get("vars", {})
                role_name = group_vars.get("device_role", "")
                domain = group_vars.get("domain", "")
                tier = group_vars.get("tier")
                asn = group_vars.get("asn")

                # Fallback: infer role from group name suffix
                if not role_name:
                    for suffix, (r, d, t) in _ROLE_PATTERNS.items():
                        if role_group.endswith(suffix):
                            role_name = r
                            domain = domain or d
                            tier = tier or t
                            break

                hosts = role_data.get("hosts", {})
                if not hosts:
                    continue

                for hostname, host_data in hosts.items():
                    host_data = host_data or {}
                    device = DeviceInfo(
                        hostname=hostname,
                        ip=host_data.get("ansible_host"),
                        role=role_name,
                        domain=domain,
                        site=site_id,
                        site_number=site_num,
                        tier=tier,
                        platform=host_data.get("platform"),
                        region=normalized_region,
                        rr_role=host_data.get("rr_role"),
                        asn=asn,
                        carrier=host_data.get("carrier"),
                        generation=host_data.get("generation"),
                    )
                    inv.devices[hostname] = device
                    site_info.all_devices.append(hostname)

                    # Add to role-specific list
                    role_list_map = {
                        "dcpe": site_info.dcpe,
                        "spe": site_info.spe,
                        "agg": site_info.agg,
                        "ipe": site_info.ipe,
                        "p_node": site_info.p_nodes,
                        "core_rr": site_info.core_rr,
                        "wan_pe_edge": site_info.wee,
                    }
                    target_list = role_list_map.get(role_name)
                    if target_list is not None:
                        target_list.append(hostname)

    return inv


def _process_flat_group(inv: Inventory, group_name: str, group_data: dict, global_vars: dict):
    """Process non-regional groups like firewalls, panorama, public_route_servers."""
    if not isinstance(group_data, dict):
        return

    # Handle nested children (e.g. firewalls → t2_firewalls, t1_firewalls)
    for child_name, child_data in group_data.get("children", {}).items():
        if isinstance(child_data, dict):
            _process_flat_group(inv, child_name, child_data, global_vars)

    group_vars = group_data.get("vars", {})
    hosts = group_data.get("hosts", {})
    if not hosts:
        return

    for hostname, host_data in hosts.items():
        host_data = host_data or {}
        device = DeviceInfo(
            hostname=hostname,
            ip=host_data.get("ansible_host"),
            role=group_vars.get("device_role", group_name),
            domain=group_vars.get("domain", ""),
            extra={k: v for k, v in host_data.items() if k != "ansible_host"},
        )
        inv.devices[hostname] = device
