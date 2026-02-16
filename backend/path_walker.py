"""
Path Walker — The core engine that traces forwarding paths across routing domains.

Strategy:
1. Don't trust the RR — it shows every route in every VRF (noise)
2. Start at the data plane — query actual FIBs, not RIBs
3. Walk hop-by-hop, crossing domain boundaries (firewalls) explicitly
4. Collect ALL paths (ECMP, backup, standby) not just "best"
"""

from typing import Optional
from models import (
    PathQuery, PathResult, PathHop, PrefixOrigin,
    MultiPath, SinglePath, DeviceRole
)
from graph_engine import GraphEngine


class PathWalker:
    """Walks the forwarding plane across multi-domain networks."""
    
    def __init__(self, graph: GraphEngine):
        self.graph = graph
    
    async def find_origin(self, prefix: str, vrf: str = None) -> PathResult:
        """
        Given a prefix, find where it's actually originated.
        
        Algorithm:
        1. Start at backbone AGG routers (the crossroads)
        2. Query FIB for the prefix — next-hop points toward a firewall
        3. Query the firewall's static route table — next-hop enters a PE zone
        4. Query the PE zone — find the actual originator
        5. If originator is an edge router with eBGP, that's an external origin
        6. If originator is a PE with connected/static, that's an internal origin
        
        Do NOT start at the RR. The RR shows 30 copies. We want the real one.
        """
        origins = []
        warnings = []
        domains = []
        
        # Phase 1: Ask the backbone where this prefix points
        backbone_routers = self.graph.get_routers_by_role(DeviceRole.AGG)
        
        for agg in backbone_routers:
            fib_entry = await self._query_fib(agg, prefix, vrf)
            if not fib_entry:
                continue
            
            # Phase 2: Follow next-hop — likely hits a firewall
            next_device = self.graph.resolve_next_hop(agg, fib_entry.next_hop)
            
            if next_device and next_device.role == DeviceRole.FIREWALL:
                # Phase 3: Cross the firewall boundary
                fw_route = await self._query_fw_static(next_device, prefix)
                if fw_route:
                    # Phase 4: Enter the downstream domain
                    downstream = self.graph.resolve_next_hop(
                        next_device, fw_route.next_hop
                    )
                    origin = await self._find_originator_in_domain(
                        downstream, prefix, vrf
                    )
                    if origin:
                        origins.append(origin)
                        
            elif next_device and next_device.role in (DeviceRole.PE, DeviceRole.EDGE):
                # Direct route — no firewall in path
                origin = await self._identify_origin(next_device, prefix, vrf)
                if origin:
                    origins.append(origin)
        
        # Deduplicate origins (same prefix might be found via multiple AGGs)
        origins = self._deduplicate_origins(origins)
        
        if not origins:
            warnings.append(f"No forwarding-plane origin found for {prefix}")
        
        return PathResult(
            query=PathQuery(source=prefix, vrf=vrf),
            origins=origins,
            domains_traversed=domains,
            warnings=warnings
        )
    
    async def trace_flow(
        self, 
        source: str, 
        destination: str,
        vrf: str = None,
        exclude_nodes: list[str] = None
    ) -> PathResult:
        """
        Trace all forwarding paths from source to destination.
        
        Algorithm:
        1. Find which PE/router the source is attached to
        2. Find the origin(s) of the destination prefix  
        3. Walk the forwarding path from source PE to dest origin
        4. At each hop: query FIB, collect ALL next-hops (ECMP)
        5. At firewalls: query static/policy routes
        6. At MPLS hops: collect label operations
        7. Build the complete path tree
        8. Optionally trace reverse path for asymmetry detection
        """
        # Find source attachment point
        src_origin = await self.find_origin(source, vrf)
        dst_origin = await self.find_origin(destination, vrf)
        
        forward_paths = []
        warnings = []
        
        # For each source PE, trace toward each destination origin
        for src in src_origin.origins:
            for dst in dst_origin.origins:
                paths = await self._walk_path(
                    src.originating_router,
                    dst.originating_router,
                    destination,
                    vrf,
                    exclude_nodes
                )
                forward_paths.extend(paths)
        
        # Trace reverse for asymmetry detection
        reverse_paths = []
        for dst in dst_origin.origins:
            for src in src_origin.origins:
                rpaths = await self._walk_path(
                    dst.originating_router,
                    src.originating_router,
                    source,
                    vrf,
                    exclude_nodes
                )
                reverse_paths.extend(rpaths)
        
        # Check for asymmetry
        if forward_paths and reverse_paths:
            if self._paths_asymmetric(forward_paths, reverse_paths):
                warnings.append("⚠️ Asymmetric forwarding detected — forward and reverse take different paths")
        
        return PathResult(
            query=PathQuery(source=source, destination=destination, vrf=vrf),
            origins=dst_origin.origins,
            forward_paths=MultiPath(paths=forward_paths) if forward_paths else None,
            reverse_paths=MultiPath(paths=reverse_paths) if reverse_paths else None,
            domains_traversed=self._collect_domains(forward_paths),
            warnings=warnings
        )
    
    async def _walk_path(
        self,
        from_router: str,
        to_router: str,
        prefix: str,
        vrf: str = None,
        exclude_nodes: list[str] = None,
        max_hops: int = 30
    ) -> list[SinglePath]:
        """
        Walk the forwarding path hop-by-hop from one router to another.
        Branches on ECMP. Crosses firewall boundaries.
        Returns all discovered paths.
        """
        paths = []
        
        # BFS/DFS through the forwarding plane
        # Each "frontier" is a partial path being extended
        frontier = [
            SinglePath(
                path_id=f"{from_router}->{to_router}-0",
                hops=[],
                is_primary=True
            )
        ]
        
        # TODO: Implement actual hop-by-hop walk
        # For each hop:
        #   1. Query FIB on current router for prefix
        #   2. Get all next-hops (ECMP creates branches)
        #   3. For each next-hop:
        #      a. Resolve to a connected device
        #      b. If device is firewall → query static routes → continue
        #      c. If device is MPLS router → record label op → continue
        #      d. If device is destination → path complete
        #      e. If hop count > max → abort (loop detection)
        
        return paths
    
    async def _query_fib(self, router, prefix, vrf=None):
        """Query a router's FIB (forwarding table) for a prefix."""
        # TODO: Ansible/NETCONF collection populates a local cache
        # This queries the cached data
        pass
    
    async def _query_fw_static(self, firewall, prefix):
        """Query a firewall's static route table."""
        pass
    
    async def _find_originator_in_domain(self, entry_router, prefix, vrf):
        """Walk within a routing domain to find the actual originator."""
        pass
    
    async def _identify_origin(self, router, prefix, vrf):
        """Determine how a router originates a prefix (connected/static/bgp)."""
        pass
    
    def _deduplicate_origins(self, origins):
        """Remove duplicate origins found via different AGG routers."""
        seen = set()
        unique = []
        for o in origins:
            key = (o.prefix, o.originating_router, o.vrf)
            if key not in seen:
                seen.add(key)
                unique.append(o)
        return unique
    
    def _paths_asymmetric(self, forward, reverse):
        """Check if forward and reverse paths traverse different nodes."""
        fwd_nodes = set()
        for p in forward:
            for h in p.hops:
                fwd_nodes.add(h.hostname)
        rev_nodes = set()
        for p in reverse:
            for h in p.hops:
                rev_nodes.add(h.hostname)
        return fwd_nodes != rev_nodes
    
    def _collect_domains(self, paths):
        """Collect all routing domains traversed."""
        domains = []
        if paths:
            for p in paths:
                for h in p.hops:
                    if h.domain not in domains:
                        domains.append(h.domain)
        return domains
