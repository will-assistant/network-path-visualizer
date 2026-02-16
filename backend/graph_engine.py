"""
Graph Engine — Builds and queries the network topology graph.

Uses NetworkX for graph operations. Topology is built from:
1. Inventory YAML (router definitions, domain boundaries)
2. Ansible-collected data (future)
"""

import yaml
import networkx as nx
from pathlib import Path
from typing import Optional
from models import (
    Router, Interface, DeviceRole, DeviceVendor,
    RoutingDomain, DomainBoundary, DomainType
)


class GraphEngine:
    """Network topology as a directed graph with domain awareness."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.domains: dict[str, RoutingDomain] = {}
        self.boundaries: list[DomainBoundary] = []
        self.routers: dict[str, Router] = {}

    def load_inventory(self, inventory_path: str):
        """Load router inventory and domain definitions from YAML."""
        path = Path(inventory_path)
        if not path.exists():
            raise FileNotFoundError(f"Inventory not found: {inventory_path}")

        with open(path) as f:
            inv = yaml.safe_load(f)

        # Load domains
        for name, dconf in inv.get("domains", {}).items():
            self.domains[name] = RoutingDomain(
                name=name,
                domain_type=DomainType(dconf["type"]),
                protocol=dconf["protocol"],
                routers=[],
            )

        # Load routers
        for hostname, rconf in inv.get("routers", {}).items():
            interfaces = []
            for iconf in rconf.get("interfaces", []):
                interfaces.append(Interface(
                    name=iconf["name"],
                    ip=iconf.get("ip"),
                    description=iconf.get("description"),
                    speed=iconf.get("speed"),
                    neighbor=iconf.get("neighbor"),
                ))

            router = Router(
                hostname=hostname,
                mgmt_ip=rconf["mgmt_ip"],
                vendor=DeviceVendor(rconf["vendor"]),
                role=DeviceRole(rconf["role"]),
                domain=rconf["domain"],
                interfaces=interfaces,
            )
            self.routers[hostname] = router

            # Register router in its domain
            if rconf["domain"] in self.domains:
                self.domains[rconf["domain"]].routers.append(hostname)

        # Load boundaries
        for bconf in inv.get("boundaries", []):
            self.boundaries.append(DomainBoundary(
                firewall=bconf["firewall"],
                upstream_domain=bconf["upstream_domain"],
                downstream_domain=bconf["downstream_domain"],
            ))

        self.build_graph()

    def build_graph(self):
        """Build the topology graph from loaded inventory."""
        for hostname, router in self.routers.items():
            self.graph.add_node(
                hostname,
                vendor=router.vendor.value,
                role=router.role,
                domain=router.domain,
                mgmt_ip=router.mgmt_ip,
            )

        for hostname, router in self.routers.items():
            if router.interfaces:
                for iface in router.interfaces:
                    if iface.neighbor and iface.neighbor in self.routers:
                        self.graph.add_edge(
                            hostname,
                            iface.neighbor,
                            interface=iface.name,
                            speed=iface.speed or "",
                            utilization=iface.utilization or 0,
                            description=iface.description or "",
                        )

    def get_routers_by_role(self, role: DeviceRole) -> list[Router]:
        return [r for r in self.routers.values() if r.role == role]

    def get_routers_in_domain(self, domain_name: str) -> list[Router]:
        return [r for r in self.routers.values() if r.domain == domain_name]

    def resolve_next_hop(self, current_router: Router, next_hop_ip: str) -> Optional[Router]:
        for neighbor in self.graph.neighbors(current_router.hostname):
            neighbor_router = self.routers.get(neighbor)
            if neighbor_router and neighbor_router.interfaces:
                for iface in neighbor_router.interfaces:
                    if iface.ip and iface.ip.split("/")[0] == next_hop_ip:
                        return neighbor_router
        return None

    def get_domain_boundary(self, from_domain: str, to_domain: str) -> Optional[DomainBoundary]:
        for boundary in self.boundaries:
            if (boundary.upstream_domain == from_domain and
                    boundary.downstream_domain == to_domain):
                return boundary
            if (boundary.upstream_domain == to_domain and
                    boundary.downstream_domain == from_domain):
                return boundary
        return None

    def shortest_path(self, from_node: str, to_node: str, exclude: list[str] = None) -> list[str]:
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
        try:
            return list(nx.all_simple_paths(
                self.graph, from_node, to_node, cutoff=max_length
            ))
        except nx.NetworkXError:
            return []

    def get_domains(self) -> dict:
        return {
            "domains": [d.model_dump() for d in self.domains.values()],
            "boundaries": [b.model_dump() for b in self.boundaries],
        }

    def to_vis_json(self) -> dict:
        """Export topology as vis.js compatible JSON."""
        role_colors = {
            DeviceRole.PE: "#4CAF50",
            DeviceRole.P: "#2196F3",
            DeviceRole.AGG: "#2196F3",
            DeviceRole.FIREWALL: "#F44336",
            DeviceRole.EDGE: "#FF9800",
            DeviceRole.RR: "#9C27B0",
        }
        role_shapes = {
            DeviceRole.PE: "dot",
            DeviceRole.P: "diamond",
            DeviceRole.AGG: "diamond",
            DeviceRole.FIREWALL: "triangle",
            DeviceRole.EDGE: "square",
            DeviceRole.RR: "star",
        }
        domain_groups = {
            "pe-east": "pe_zone",
            "pe-west": "pe_zone",
            "backbone": "backbone",
            "inet-edge": "inet_edge",
        }

        nodes = []
        edges = []
        seen_edges = set()

        for hostname, data in self.graph.nodes(data=True):
            role = data.get("role", DeviceRole.P)
            domain = data.get("domain", "unknown")
            nodes.append({
                "id": hostname,
                "label": hostname.upper(),
                "color": role_colors.get(role, "#757575"),
                "shape": role_shapes.get(role, "dot"),
                "title": f"{hostname}\n{data.get('vendor', '')}\nDomain: {domain}",
                "group": domain_groups.get(domain, domain),
                "font": {"color": "#ccc"},
            })

        for u, v, data in self.graph.edges(data=True):
            edge_key = tuple(sorted([u, v]))
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)

            speed = data.get("speed", "")
            width = 1
            if "100G" in speed:
                width = 4
            elif "40G" in speed:
                width = 3
            elif "10G" in speed:
                width = 2

            edges.append({
                "from": u,
                "to": v,
                "color": {"color": "#333", "highlight": "#4CAF50"},
                "width": width,
                "title": f"{data.get('interface', '')} {speed}",
                "smooth": {"type": "continuous"},
            })

        return {"nodes": nodes, "edges": edges}
