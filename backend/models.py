"""
Data models for the Network Path Visualizer.

The network is modeled as a multi-tier MPLS architecture with:
- 7 device tiers (south to north): DCCE → DCPE → SPE → T2-FW → AGG → T1-FW → IPE
- Parent/child VRF relationships with eBGP gateway at SPE
- Community-based path selection (OID/AID + local-pref)
- Multiple RR tiers (core, agg, inet)
- Firewalls as static-route domain boundaries (no BGP on FWs)
- Carrier-supporting-carrier (CSC) VRF for AGG peering
"""

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# --- Query Models ---

class PathQuery(BaseModel):
    source: str              # IP or prefix
    destination: Optional[str] = None
    vrf: Optional[str] = None
    exclude_nodes: Optional[list[str]] = None  # Failure simulation


# --- Network Topology Models ---

class DeviceVendor(str, Enum):
    JUNIPER = "juniper"
    # Future: CISCO_XR, PALO_ALTO, FORTINET

class DeviceRole(str, Enum):
    """7-tier MPLS device roles, south to north."""
    DCCE = "dcce"            # Data center customer edge (ToR/leaf)
    DCPE = "dcpe"            # Data center provider edge (DC border)
    SPE = "spe"              # Service PE — parent/child VRF gateway, eBGP between VRFs
    T2_FIREWALL = "t2_fw"   # Tier-2 firewall — static routes, between SPE and AGG
    AGG = "agg"              # Aggregation / MPLS backbone
    T1_FIREWALL = "t1_fw"   # Tier-1 firewall — static routes, between AGG and IPE
    IPE = "ipe"              # Internet PE / peering edge
    RR = "rr"                # Route reflector (multiple tiers)
    P = "p"                  # MPLS P router (transit/core)

class RRTier(str, Enum):
    """Route reflector tiers — each handles different address families."""
    CORE = "core"            # MP-BGP VPNv4 — carries VRF routes across MPLS core
    AGG = "agg"              # Default routes + failover between AGG sites
    INET = "inet"            # Internet/full-table routes for IPE peering

class DomainType(str, Enum):
    DC = "dc"                  # Data center (DCCE + DCPE)
    SERVICE_EDGE = "service_edge"  # SPE tier — VRF gateway
    AGG_BACKBONE = "agg_backbone"  # AGG + P routers, MPLS core
    INET_EDGE = "inet_edge"        # IPE peering zone
    CSC = "csc"                    # Carrier-supporting-carrier VRF domain

class VRFType(str, Enum):
    """VRF classification for parent/child model."""
    PARENT = "parent"        # Gateway VRF — can reach AGG tier
    CHILD = "child"          # Routes through parent VRF via eBGP at SPE
    CSC = "csc"              # AGG-CSC VRF for cross-site AGG peering
    GLOBAL = "global"        # Global routing table

class VRF(BaseModel):
    """VRF instance with parent/child relationships."""
    name: str
    vrf_type: VRFType
    parent_vrf: Optional[str] = None   # Child VRFs reference their parent
    rd: Optional[str] = None           # Route distinguisher
    rt_import: list[str] = []          # Import route targets
    rt_export: list[str] = []          # Export route targets
    description: Optional[str] = None

class PathSelectionCommunity(BaseModel):
    """Community-based path selection attributes (OID/AID model)."""
    oid: Optional[str] = None    # Origin ID community — identifies originating site/router
    aid: Optional[str] = None    # Advertising ID community — identifies advertising path
    local_pref: int = 100        # Associated local-pref (200=primary, 150=secondary, 50=backup)
    description: Optional[str] = None

class Router(BaseModel):
    hostname: str
    mgmt_ip: str
    vendor: DeviceVendor
    role: DeviceRole
    domain: str
    site: Optional[str] = None          # Physical site/location
    tier: Optional[int] = None          # Numeric tier (1-7, south to north)
    rr_tier: Optional[RRTier] = None    # For RR role: which tier
    vrfs: list[VRF] = []                # VRF instances on this router
    interfaces: Optional[list["Interface"]] = None

class Interface(BaseModel):
    name: str
    ip: Optional[str] = None
    description: Optional[str] = None
    speed: Optional[str] = None
    utilization: Optional[float] = None
    neighbor: Optional[str] = None
    vrf: Optional[str] = None           # VRF assignment for this interface

class RoutingDomain(BaseModel):
    """A zone where one routing protocol suite operates."""
    name: str
    domain_type: DomainType
    protocol: str            # 'isis+mpls', 'ebgp', 'static'
    routers: list[str] = []

class DomainBoundary(BaseModel):
    """A firewall sitting between two routing domains. FWs use static routes only."""
    firewall: str
    upstream_domain: str     # South side (toward customer)
    downstream_domain: str   # North side (toward internet)
    tier: Optional[str] = None  # 't1' or 't2'
    static_routes: Optional[list["StaticRoute"]] = None
    nat_rules: Optional[list["NATRule"]] = None

class StaticRoute(BaseModel):
    prefix: str
    next_hop: str
    interface: Optional[str] = None
    metric: int = 0
    tag: Optional[int] = None
    vrf: Optional[str] = None

class NATRule(BaseModel):
    original_src: Optional[str] = None
    original_dst: Optional[str] = None
    translated_src: Optional[str] = None
    translated_dst: Optional[str] = None
    zone_from: Optional[str] = None
    zone_to: Optional[str] = None


# --- Path Result Models ---

class PathHop(BaseModel):
    """A single hop in the forwarding path."""
    seq: int
    hostname: str
    vendor: DeviceVendor
    role: DeviceRole
    ingress_interface: Optional[str] = None
    egress_interface: Optional[str] = None
    action: str              # 'route', 'mpls-push', 'mpls-swap', 'mpls-pop', 'static',
                             # 'vrf-leak', 'ebgp-parent-child', 'nat', 'policy'
    label_in: Optional[int] = None
    label_out: Optional[int] = None
    next_hop: Optional[str] = None
    domain: str
    vrf: Optional[str] = None
    tier: Optional[int] = None
    utilization: Optional[float] = None
    communities: list[str] = []  # OID/AID communities at this hop

class LSPInfo(BaseModel):
    name: str
    lsp_type: str            # 'rsvp-te', 'sr-te', 'ldp'
    role: str                # 'primary', 'secondary', 'ecmp', 'frr-bypass'

class SinglePath(BaseModel):
    """One complete forwarding path from A to B."""
    path_id: str
    hops: list[PathHop]
    lsp: Optional[LSPInfo] = None
    total_latency_ms: Optional[float] = None
    bottleneck_util: Optional[float] = None
    is_primary: bool = True
    selection_reason: Optional[str] = None  # 'community-based', 'igp-cost', 'local-pref'

class PrefixOrigin(BaseModel):
    """Where a prefix is originated."""
    prefix: str
    vrf: Optional[str] = None
    originating_router: str
    origin_type: str         # 'connected', 'static', 'bgp', 'redistribute', 'vrf-import'
    bgp_as_path: Optional[str] = None
    bgp_local_pref: Optional[int] = None
    bgp_med: Optional[int] = None
    bgp_communities: Optional[list[str]] = None
    oid: Optional[str] = None  # Origin ID community
    aid: Optional[str] = None  # Advertising ID community

class MultiPath(BaseModel):
    """All paths for a given flow — primary, ECMP, backup."""
    paths: list[SinglePath]
    ecmp_hash: Optional[str] = None

class PathResult(BaseModel):
    """Complete result of a path trace."""
    query: PathQuery
    origins: list[PrefixOrigin]
    forward_paths: Optional[MultiPath] = None
    reverse_paths: Optional[MultiPath] = None
    domains_traversed: list[str]
    tiers_traversed: list[str] = []   # e.g. ['dcce', 'dcpe', 'spe', 't2_fw', 'agg', 't1_fw', 'ipe']
    vrf_transitions: list[str] = []   # e.g. ['child:CUST-A → parent:GATEWAY via eBGP@SPE']
    warnings: list[str] = []


# --- Collection/Cached Data Models ---

class BGPRoute(BaseModel):
    prefix: str
    next_hop: str
    as_path: list[str] = Field(default_factory=list)
    communities: list[str] = Field(default_factory=list)
    local_pref: Optional[int] = None
    origin: str = "unknown"
    source_router: str
    timestamp: datetime


class MPLSLsp(BaseModel):
    name: str
    from_router: str
    to_router: str
    path: list[str] = Field(default_factory=list)
    labels: list[str] = Field(default_factory=list)
    state: str


class ISISEntry(BaseModel):
    system_id: str
    hostname: str
    neighbors: list[dict] = Field(default_factory=list)
    ip_reachability: list[str] = Field(default_factory=list)


class CollectionJob(BaseModel):
    id: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    hosts: list[str] = Field(default_factory=list)
    types: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
