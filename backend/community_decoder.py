"""
Community Decoder — Parse OID/AID communities and derive path semantics.

Community design (from GIN templates):
- OID (Origin ID): X:1594 — tagged at DCPE, identifies originating site
- AID (Advertising ID): X:194 — tagged at SPE parent VRF export, identifies advertising site
- LP mapping: 200=primary, 150=secondary, 50=tertiary
- Failover rule: bidirectional traffic prefers lowest-numbered site's firewall

Regional types:
- Type 0 (Americas): 100.120.x.x, Sites 1-4
- Type 3 (EMEA): 100.123.x.x, Sites 7-8
- Type 4 (APAC): 100.124.x.x, Sites 17-19
- Type 7 (GMN): 100.127.x.x, cross-regional management
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


# Community format constants
OID_MARKER = 1594   # X:1594 = OID for site X
AID_MARKER = 194    # X:194  = AID for site X
DEFAULT_MARKER = 0  # X:0    = default route from site X AGG

# Security communities
COMMUNITY_DMZ_ROUTE = "41326:41326"   # CONUS (Sites 1-4) child-originated
COMMUNITY_CHILD_ROUTE = "3124:3124"   # APAC/EMEA child-originated

# LP values
LP_PRIMARY = 200
LP_SECONDARY = 150
LP_TERTIARY = 50

# Regional failover chains
FAILOVER_CHAINS: dict[str, list[list[int]]] = {
    "americas": [
        [1, 2, 3],   # Site 1 failover order
        [2, 3, 1],   # Site 2
        [3, 2, 1],   # Site 3
        [4, 3, 2],   # Site 4 (never transit for 1-3)
    ],
    "emea": [
        [7, 8],
        [8, 7],
    ],
    "apac": [
        [17, 18, 19],
        [18, 17, 19],
        [19, 17, 18],
    ],
}

# Site → region mapping
SITE_REGIONS: dict[int, str] = {
    1: "americas", 2: "americas", 3: "americas", 4: "americas",
    7: "emea", 8: "emea",
    17: "apac", 18: "apac", 19: "apac",
}

# Region → firewall next-hop prefix (second octet identifies region)
REGION_FW_OCTETS: dict[str, int] = {
    "americas": 120,  # 100.120.{vrf}.x
    "emea": 123,      # 100.123.{vrf}.x
    "apac": 124,      # 100.124.{vrf}.x
    "gmn": 127,       # 100.127.{vrf}.x
}


@dataclass
class DecodedCommunity:
    """Result of decoding BGP communities on a route."""
    oid: Optional[int] = None           # Origin site number
    aid: Optional[int] = None           # Advertising site number
    origin_site: Optional[str] = None   # "Site-1", "Site-7", etc.
    advertising_site: Optional[str] = None
    region: Optional[str] = None        # "americas", "emea", "apac"
    local_pref: Optional[int] = None    # 200/150/50
    preference: Optional[str] = None    # "primary"/"secondary"/"tertiary"
    is_default_route: bool = False
    is_child_originated: bool = False
    raw_communities: list[str] = field(default_factory=list)
    # All standard communities (non-OID/AID)
    standard_communities: list[str] = field(default_factory=list)


@dataclass
class FirewallIdentity:
    """T2 firewall identity derived from next-hop addressing."""
    region: str              # "americas", "emea", "apac", "gmn"
    vrf_id: int              # The VRF ID from the third octet
    next_hop: str            # Original next-hop IP
    site: Optional[int] = None  # Inferred site (if determinable from context)


def decode_communities(communities: list[str], local_pref: Optional[int] = None) -> DecodedCommunity:
    """
    Decode a list of BGP communities into structured path information.

    Looks for:
    - X:1594 → OID (origin site X)
    - X:194  → AID (advertising site X)
    - X:0    → default route from site X
    - 41326:41326 → CONUS child-originated
    - 3124:3124   → APAC/EMEA child-originated
    """
    result = DecodedCommunity(raw_communities=list(communities))

    for comm in communities:
        # Parse standard community format "ASN:VALUE"
        m = re.match(r'^(\d+):(\d+)$', comm)
        if not m:
            result.standard_communities.append(comm)
            continue

        left, right = int(m.group(1)), int(m.group(2))

        # OID: X:1594
        if right == OID_MARKER:
            result.oid = left
            result.origin_site = f"Site-{left}"
            result.region = SITE_REGIONS.get(left)
            continue

        # AID: X:194
        if right == AID_MARKER:
            result.aid = left
            result.advertising_site = f"Site-{left}"
            continue

        # Default route: X:0
        if right == DEFAULT_MARKER and 1 <= left <= 50:
            result.is_default_route = True
            continue

        # Security communities
        if comm == COMMUNITY_DMZ_ROUTE or comm == COMMUNITY_CHILD_ROUTE:
            result.is_child_originated = True
            continue

        result.standard_communities.append(comm)

    # Derive preference from LP
    if local_pref is not None:
        result.local_pref = local_pref
        result.preference = lp_to_preference(local_pref)
    elif result.oid is not None and result.aid is not None:
        # Infer LP from OID/AID relationship using failover matrix
        result.local_pref, result.preference = infer_preference(result.oid, result.aid)

    return result


def lp_to_preference(lp: int) -> str:
    """Map local-pref value to preference label."""
    if lp >= LP_PRIMARY:
        return "primary"
    elif lp >= LP_SECONDARY:
        return "secondary"
    elif lp <= LP_TERTIARY:
        return "tertiary"
    else:
        return "unknown"


def infer_preference(oid: int, aid: int) -> tuple[int, str]:
    """
    Infer LP and preference from OID/AID pair using the failover matrix.

    The primary firewall for traffic between two sites is the lowest-numbered site.
    """
    region = SITE_REGIONS.get(oid)
    if not region:
        return 100, "unknown"

    # Find the failover chain for the AID site (the site making the decision)
    for chain in FAILOVER_CHAINS.get(region, []):
        if chain[0] == aid:
            # Position of the preferred firewall site in the chain
            # Primary = lowest numbered site between OID and AID
            preferred_fw = min(oid, aid)
            if preferred_fw == aid:
                return LP_PRIMARY, "primary"
            else:
                # Check position in failover chain
                try:
                    idx = chain.index(oid)
                    if idx == 0:
                        return LP_PRIMARY, "primary"
                    elif idx == 1:
                        return LP_SECONDARY, "secondary"
                    else:
                        return LP_TERTIARY, "tertiary"
                except ValueError:
                    pass

    # If OID == AID, it's local — primary
    if oid == aid:
        return LP_PRIMARY, "primary"

    return 100, "unknown"


def derive_firewall_from_nexthop(next_hop: str) -> Optional[FirewallIdentity]:
    """
    Derive T2 firewall identity from next-hop addressing pattern.

    Patterns:
    - 100.120.{vrf_id}.x → Americas T2
    - 100.123.{vrf_id}.x → EMEA T2
    - 100.124.{vrf_id}.x → APAC T2
    - 100.127.{vrf_id}.x → EMEA GMN
    """
    m = re.match(r'^100\.(\d+)\.(\d+)\.\d+$', next_hop)
    if not m:
        return None

    second_octet = int(m.group(1))
    vrf_id = int(m.group(2))

    # Reverse lookup: octet → region
    for region, octet in REGION_FW_OCTETS.items():
        if second_octet == octet:
            return FirewallIdentity(
                region=region,
                vrf_id=vrf_id,
                next_hop=next_hop,
            )

    return None


def preferred_firewall_site(site_a: int, site_b: int) -> int:
    """
    Determine which site's firewall is preferred for traffic between two sites.
    Rule: lowest-numbered site wins.
    """
    return min(site_a, site_b)


def get_failover_chain(site: int) -> list[int]:
    """Get the ordered failover chain for a site."""
    region = SITE_REGIONS.get(site)
    if not region:
        return [site]

    for chain in FAILOVER_CHAINS.get(region, []):
        if chain[0] == site:
            return chain

    return [site]
