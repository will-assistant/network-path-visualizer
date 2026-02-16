"""
Graph Engine — Builds and queries the network topology graph.

Uses NetworkX for graph operations. Topology is built from:
1. Ansible-collected data (router configs, interface tables)
2. Inventory file (manual domain/boundary definitions)
3. IGP LSDB (auto-discovered topology within domains)
"""

import networkx as nx
from typing import Optional
from models import Router, DeviceRole, RoutingDomain, DomainBoundary


class GraphEngine:
    """Network topology as a directed graph with domain awareness."""
    
    def __init__(self):
        self.graph = nx.DiGraph()
        self.domains: dict[str, RoutingDomain] = {}
        self.boundaries: list[DomainBoundary] = []
        self.routers: dict[str, Router] = {}
    
    def load_inventory(self, inventory_path: str):
        """Load router inventory and domain definitions from YAML."""
        # TODO: Parse inventory YAML
        pass
    
    def load_collected_data(self, data_dir: str):
        """Load Ansible-collected data (FIBs, LSPs, static routes)."""
        # TODO: Parse collected JSON/YAML from Ansible
        pass
    
    def build_graph(self):
        """Build the topology graph from inventory + collected data."""
        for hostname, router in self.routers.items():
            self.graph.add_node(
                hostname,
                vendor=router.vendor,
                role=router.role,
                domain=router.domain,
                mgmt_ip=router.mgmt_ip
            )
        
        # Add edges from interface neighbor data
        for hostname, router in self.routers.items():
            if router.interfaces:
                for iface in router.interfaces:
                    if iface.neighbor:
                        self.graph.add_edge(
                            hostname,
                            iface.neighbor,
                            interface=iface.name,
                            speed=iface.speed,
                            utilization=iface.utilization,
                            description=iface.description
                        )
    
    def get_routers_by_role(self, role: DeviceRole) -> list[Router]:
        """Get all routers with a specific role."""
        return [r for r in self.routers.values() if r.role == role]
    
    def get_routers_in_domain(self, domain_name: str) -> list[Router]:
        """Get all routers in a routing domain."""
        return [r for r in self.routers.values() if r.domain == domain_name]
    
    def resolve_next_hop(self, current_router: Router, next_hop_ip: str) -> Optional[Router]:
        """Given a next-hop IP, find which connected router it belongs to."""
        # Check all neighbors of current router
        for neighbor in self.graph.neighbors(current_router.hostname):
            neighbor_router = self.routers.get(neighbor)
            if neighbor_router and neighbor_router.interfaces:
                for iface in neighbor_router.interfaces:
                    if iface.ip and iface.ip.split('/')[0] == next_hop_ip:
                        return neighbor_router
        return None
    
    def get_domain_boundary(self, from_domain: str, to_domain: str) -> Optional[DomainBoundary]:
        """Find the firewall boundary between two domains."""
        for boundary in self.boundaries:
            if (boundary.upstream_domain == from_domain and 
                boundary.downstream_domain == to_domain):
                return boundary
            if (boundary.upstream_domain == to_domain and
                boundary.downstream_domain == from_domain):
                return boundary
        return None
    
    def shortest_path(self, from_node: str, to_node: str, exclude: list[str] = None) -> list[str]:
        """Find shortest path, optionally excluding nodes (failure sim)."""
        g = self.graph.copy()
        if exclude:
            for node in exclude:
                if node in g:
                    g.remove_node(node)
        try:
            return nx.shortest_path(g, from_node, to_node)
        except nx.NetworkXNoPath:
            return []
    
    def all_paths(self, from_node: str, to_node: str, max_length: int = 15) -> list[list[str]]:
        """Find all simple paths between two nodes."""
        try:
            return list(nx.all_simple_paths(
                self.graph, from_node, to_node, cutoff=max_length
            ))
        except nx.NetworkXError:
            return []
    
    def get_domains(self) -> dict:
        """Return domain structure for API."""
        return {
            "domains": [d.model_dump() for d in self.domains.values()],
            "boundaries": [b.model_dump() for b in self.boundaries]
        }
    
    def to_vis_json(self) -> dict:
        """Export topology as vis.js compatible JSON."""
        nodes = []
        edges = []
        
        # Role-based styling
        role_colors = {
            DeviceRole.PE: "#4CAF50",       # Green
            DeviceRole.P: "#2196F3",        # Blue
            DeviceRole.AGG: "#2196F3",      # Blue
            DeviceRole.FIREWALL: "#F44336", # Red
            DeviceRole.EDGE: "#FF9800",     # Orange
            DeviceRole.RR: "#9C27B0",       # Purple
        }
        
        role_shapes = {
            DeviceRole.PE: "dot",
            DeviceRole.P: "diamond",
            DeviceRole.AGG: "diamond",
            DeviceRole.FIREWALL: "triangle",
            DeviceRole.EDGE: "square",
            DeviceRole.RR: "star",
        }
        
        for hostname, data in self.graph.nodes(data=True):
            role = data.get('role', DeviceRole.P)
            nodes.append({
                "id": hostname,
                "label": hostname,
                "color": role_colors.get(role, "#757575"),
                "shape": role_shapes.get(role, "dot"),
                "title": f"{hostname}\n{data.get('vendor', '')}\n{data.get('domain', '')}",
                "group": data.get('domain', 'unknown')
            })
        
        for u, v, data in self.graph.edges(data=True):
            util = data.get('utilization', 0)
            color = "#4CAF50" if util < 60 else "#FF9800" if util < 80 else "#F44336"
            edges.append({
                "from": u,
                "to": v,
                "label": data.get('interface', ''),
                "color": color,
                "title": f"{data.get('speed', '')} | {util}% util",
                "width": max(1, util / 20) if util else 1
            })
        
        return {"nodes": nodes, "edges": edges}
