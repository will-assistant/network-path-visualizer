"""
Data models for the Network Path Visualizer.

The network is modeled as routing domains connected by boundaries (firewalls).
Paths are traced by walking the forwarding plane across these domains.
"""

from pydantic import BaseModel
from typing import Optional
from enum import Enum


# --- Query Models ---

class PathQuery(BaseModel):
    source: str              # IP or prefix (e.g., "10.45.12.0/24" or "10.45.12.5")
    destination: Optional[str] = None  # IP or prefix for flow tracing
    vrf: Optional[str] = None          # Limit to specific VRF
    exclude_nodes: Optional[list[str]] = None  # Failure simulation


# --- Network Topology Models ---

class DeviceVendor(str, Enum):
    JUNIPER = "juniper"
    CISCO_XR = "cisco_xr"
    CISCO_IOS = "cisco_ios"
    PALO_ALTO = "palo_alto"
    FORTINET = "fortinet"

class DeviceRole(str, Enum):
    PE = "pe"                # Customer-facing provider edge
    P = "p"                  # Core/backbone (MPLS P router)
    AGG = "agg"              # Aggregation backbone
    FIREWALL = "firewall"    # Domain boundary
    EDGE = "edge"            # Internet edge / peering
    RR = "rr"                # Route reflector

class DomainType(str, Enum):
    PE_ZONE = "pe_zone"        # PE-facing zone behind firewall
    BACKBONE = "backbone"      # MPLS backbone / aggregation
    INET_EDGE = "inet_edge"    # Internet edge / peering zone
    DMZ = "dmz"                # DMZ zone

class Router(BaseModel):
    hostname: str
    mgmt_ip: str
    vendor: DeviceVendor
    role: DeviceRole
    domain: str              # Which routing domain this belongs to
    interfaces: Optional[list["Interface"]] = None

class Interface(BaseModel):
    name: str
    ip: Optional[str] = None
    description: Optional[str] = None
    speed: Optional[str] = None
    utilization: Optional[float] = None  # 0-100%
    neighbor: Optional[str] = None       # Connected router hostname

class RoutingDomain(BaseModel):
    """A zone where one routing protocol suite operates."""
    name: str
    domain_type: DomainType
    protocol: str            # 'isis+mpls', 'ospf', 'ebgp', 'static'
    routers: list[str]       # Hostnames

class DomainBoundary(BaseModel):
    """A firewall sitting between two routing domains."""
    firewall: str            # Hostname
    upstream_domain: str
    downstream_domain: str
    static_routes: Optional[list["StaticRoute"]] = None
    nat_rules: Optional[list["NATRule"]] = None

class StaticRoute(BaseModel):
    prefix: str
    next_hop: str
    interface: Optional[str] = None
    metric: int = 0
    tag: Optional[int] = None

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
    action: str              # 'route', 'mpls-push', 'mpls-swap', 'mpls-pop', 'static', 'nat', 'policy'
    label_in: Optional[int] = None
    label_out: Optional[int] = None
    next_hop: Optional[str] = None
    domain: str
    utilization: Optional[float] = None

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
    bottleneck_util: Optional[float] = None  # Highest utilization on any segment
    is_primary: bool = True

class PrefixOrigin(BaseModel):
    """Where a prefix is originated."""
    prefix: str
    vrf: Optional[str] = None
    originating_router: str
    origin_type: str         # 'connected', 'static', 'bgp', 'redistribute'
    bgp_as_path: Optional[str] = None
    bgp_local_pref: Optional[int] = None
    bgp_med: Optional[int] = None
    bgp_communities: Optional[list[str]] = None

class MultiPath(BaseModel):
    """All paths for a given flow — primary, ECMP, backup."""
    paths: list[SinglePath]
    ecmp_hash: Optional[str] = None  # '5-tuple', '3-tuple', 'entropy-label'

class PathResult(BaseModel):
    """Complete result of a path trace."""
    query: PathQuery
    origins: list[PrefixOrigin]
    forward_paths: Optional[MultiPath] = None
    reverse_paths: Optional[MultiPath] = None  # For asymmetry detection
    domains_traversed: list[str]
    warnings: list[str] = []  # 'asymmetric path', 'zombie route', 'no backup', etc.
