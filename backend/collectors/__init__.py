"""Vendor collectors — normalize route data to common RouteEntry format."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RouteEntry:
    """Common route entry format across all vendors."""
    prefix: str = ""
    protocol: str = ""           # bgp, static, connected, ospf, isis
    next_hop: str = ""
    interface: str = ""
    communities: list[str] = field(default_factory=list)
    local_pref: Optional[int] = None
    as_path: list[str] = field(default_factory=list)
    metric: Optional[int] = None
    vrf: str = ""
    active: bool = False
    paths: list["RouteEntry"] = field(default_factory=list)  # ECMP paths
    # Extra metadata
    inactive_reason: str = ""
    peer_as: Optional[int] = None
    router_id: str = ""
    age: str = ""
    source: str = ""             # peer IP that sent the route
