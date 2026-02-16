"""
Path Walker V2 — AGG-First Algorithm

Core insight: Query the AGG (wcr01) first. It's the index.
Communities on the AGG route tell you the entire path before
you touch any other device.

Algorithm:
1. Query AGG → get all routes for prefix (with communities, LP, next-hop)
2. Decode communities → OID/AID → origin site, advertising site, preference
3. Map OID → site → DCPE/SPE devices from inventory
4. Derive T2 firewall from next-hop addressing (100.120.x = americas, etc.)
5. Build full path without querying every hop
6. Optional: validate endpoints (DCPE has prefix, IPE has internet route)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

from community_decoder import (
    decode_communities,
    derive_firewall_from_nexthop,
    DecodedCommunity,
    FirewallIdentity,
)
from inventory import Inventory, DeviceInfo
from collectors.bgp import BGPPath

logger = logging.getLogger(__name__)


@dataclass
class PathHopV2:
    """A single hop in the derived path."""
    device: str              # Hostname or identifier
    role: str                # dcpe, spe, t2_fw, agg, t1_fw, ipe
    domain: str              # pe_zone, backbone, inet_edge
    site: Optional[str] = None
    vrf: Optional[str] = None
    next_hop: Optional[str] = None
    interface: Optional[str] = None
    label: Optional[str] = None   # Human-readable label for this hop


@dataclass
class DerivedPath:
    """A complete path derived from AGG community decode."""
    path_id: str
    preference: str          # "primary", "secondary", "tertiary"
    local_pref: int
    origin_site: Optional[str] = None
    advertising_site: Optional[str] = None
    region: Optional[str] = None
    hops: list[PathHopV2] = field(default_factory=list)
    communities: list[str] = field(default_factory=list)
    as_path: Optional[str] = None
    next_hop: Optional[str] = None
    firewall: Optional[FirewallIdentity] = None
    decoded: Optional[DecodedCommunity] = None
    active: bool = False
    description: str = ""    # Human-readable summary


@dataclass
class TraceResult:
    """Complete trace result with all alternative paths."""
    prefix: str
    query_device: str        # The AGG we queried
    paths: list[DerivedPath] = field(default_factory=list)
    primary_path: Optional[DerivedPath] = None
    warnings: list[str] = field(default_factory=list)
    raw_path_count: int = 0


class PathWalkerV2:
    """
    AGG-first path walker. Derives full forwarding paths from a single
    AGG query + community decode + inventory mapping.
    """

    def __init__(self, inventory: Optional[Inventory] = None):
        self.inventory = inventory

    def derive_paths(self, bgp_paths: list[BGPPath], prefix: str) -> TraceResult:
        """
        Take raw BGP paths from an AGG query and derive full forwarding paths.

        This is the core V2 algorithm:
        1. For each BGP path, decode communities
        2. Map decoded info to inventory devices
        3. Build the hop-by-hop path from community semantics
        4. Return all paths sorted by preference
        """
        result = TraceResult(
            prefix=prefix,
            query_device="agg",
            raw_path_count=len(bgp_paths),
        )

        for i, bgp_path in enumerate(bgp_paths):
            derived = self._derive_single_path(bgp_path, prefix, i)
            if derived:
                result.paths.append(derived)

        # Sort by preference: primary first, then secondary, then tertiary
        pref_order = {"primary": 0, "secondary": 1, "tertiary": 2, "unknown": 3}
        result.paths.sort(key=lambda p: (pref_order.get(p.preference, 99), -p.local_pref))

        # Mark primary
        if result.paths:
            result.primary_path = result.paths[0]

        return result

    def _derive_single_path(
        self, bgp_path: BGPPath, prefix: str, index: int
    ) -> Optional[DerivedPath]:
        """Derive a full path from a single BGP path entry."""

        # Step 1: Decode communities
        decoded = decode_communities(
            bgp_path.communities,
            local_pref=bgp_path.local_pref,
        )

        # Step 2: Derive firewall from next-hop
        fw_identity = None
        if bgp_path.next_hop:
            fw_identity = derive_firewall_from_nexthop(bgp_path.next_hop)

        # Step 3: Build the path
        path = DerivedPath(
            path_id=f"path-{index}",
            preference=decoded.preference or "unknown",
            local_pref=decoded.local_pref or bgp_path.local_pref or 100,
            origin_site=decoded.origin_site,
            advertising_site=decoded.advertising_site,
            region=decoded.region,
            communities=bgp_path.communities,
            as_path=bgp_path.as_path,
            next_hop=bgp_path.next_hop,
            firewall=fw_identity,
            decoded=decoded,
            active=bgp_path.active,
        )

        # Step 4: Build hop list from inventory + decoded info
        path.hops = self._build_hop_list(decoded, fw_identity, prefix)

        # Step 5: Generate description
        path.description = self._describe_path(path)

        return path

    def _build_hop_list(
        self,
        decoded: DecodedCommunity,
        fw: Optional[FirewallIdentity],
        prefix: str,
    ) -> list[PathHopV2]:
        """
        Build ordered hop list from decoded community info + inventory.

        Path structure (south to north):
          DCPE → SPE → T2 FW → AGG → [T1 FW → IPE if internet-bound]
        """
        hops: list[PathHopV2] = []
        origin_site_id = None

        # Resolve origin site from OID
        if decoded.oid is not None and self.inventory:
            origin_site_id = self.inventory.site_id_from_number(decoded.oid)

        # 1. DCPE (origin)
        if origin_site_id and self.inventory:
            dcpe_devices = self.inventory.get_dcpe_for_site(origin_site_id)
            if dcpe_devices:
                for dcpe in dcpe_devices:
                    hops.append(PathHopV2(
                        device=dcpe.hostname,
                        role="dcpe",
                        domain="pe_zone",
                        site=origin_site_id,
                        label=f"Origin DCPE at {decoded.origin_site or origin_site_id}",
                    ))
                    break  # Primary DCPE only
            else:
                hops.append(PathHopV2(
                    device=f"dcpe-{decoded.origin_site or 'unknown'}",
                    role="dcpe",
                    domain="pe_zone",
                    site=origin_site_id,
                    label=f"Origin DCPE at {decoded.origin_site or 'unknown'}",
                ))
        elif decoded.oid is not None:
            hops.append(PathHopV2(
                device=f"dcpe-site-{decoded.oid}",
                role="dcpe",
                domain="pe_zone",
                label=f"Origin DCPE at Site-{decoded.oid}",
            ))

        # 2. SPE
        if origin_site_id and self.inventory:
            spe_devices = self.inventory.get_spe_for_site(origin_site_id)
            if spe_devices:
                hops.append(PathHopV2(
                    device=spe_devices[0].hostname,
                    role="spe",
                    domain="pe_zone",
                    site=origin_site_id,
                    label=f"SPE at {decoded.origin_site or origin_site_id}",
                ))
        elif decoded.oid is not None:
            hops.append(PathHopV2(
                device=f"spe-site-{decoded.oid}",
                role="spe",
                domain="pe_zone",
                label=f"SPE at Site-{decoded.oid}",
            ))

        # 3. T2 Firewall (derived from next-hop or AID)
        if fw:
            hops.append(PathHopV2(
                device=f"t2fw-{fw.region}-vrf{fw.vrf_id}",
                role="t2_fw",
                domain="boundary",
                label=f"T2 FW ({fw.region.upper()}, VRF {fw.vrf_id})",
                next_hop=fw.next_hop,
            ))
        elif decoded.aid is not None:
            ad_site = decoded.advertising_site or f"Site-{decoded.aid}"
            hops.append(PathHopV2(
                device=f"t2fw-{ad_site}",
                role="t2_fw",
                domain="boundary",
                label=f"T2 FW at {ad_site}",
            ))

        # 4. AGG (the router we queried)
        agg_site = None
        if decoded.aid is not None and self.inventory:
            agg_site = self.inventory.site_id_from_number(decoded.aid)

        if agg_site and self.inventory:
            agg_devices = self.inventory.get_agg_routers(agg_site)
            rr_devices = [a for a in agg_devices if a.rr_role == "route_reflector"]
            agg_name = rr_devices[0].hostname if rr_devices else (agg_devices[0].hostname if agg_devices else f"agg-{agg_site}")
            hops.append(PathHopV2(
                device=agg_name,
                role="agg",
                domain="backbone",
                site=agg_site,
                label=f"AGG RR at {decoded.advertising_site or agg_site}",
            ))
        else:
            hops.append(PathHopV2(
                device="agg",
                role="agg",
                domain="backbone",
                label="AGG (queried)",
            ))

        return hops

    def _describe_path(self, path: DerivedPath) -> str:
        """Generate a human-readable description of this path."""
        parts = []

        pref_emoji = {
            "primary": "🟢",
            "secondary": "🟡",
            "tertiary": "🔴",
            "unknown": "⚪",
        }
        emoji = pref_emoji.get(path.preference, "⚪")

        parts.append(f"{emoji} {path.preference.title()}")

        if path.origin_site:
            parts.append(f"from {path.origin_site}")
        if path.advertising_site:
            parts.append(f"via {path.advertising_site}")
        if path.local_pref:
            parts.append(f"LP {path.local_pref}")
        if path.firewall:
            parts.append(f"FW: {path.firewall.region.upper()}")

        return " | ".join(parts)

    def derive_paths_from_raw_output(
        self, raw_output: str, prefix: str
    ) -> TraceResult:
        """
        Convenience: parse raw Junos output and derive paths in one call.
        Uses the existing JunosRouteParser.
        """
        from collectors.bgp import JunosRouteParser
        bgp_paths = JunosRouteParser.parse(raw_output, prefix)
        return self.derive_paths(bgp_paths, prefix)
