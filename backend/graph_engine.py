"""
Graph Engine — Builds and queries the 7-tier MPLS network topology.

Tier model (south to north):
  DCCE → DCPE → SPE → T2-FW → AGG → T1-FW → IPE

Uses NetworkX for graph operations. Topology built from inventory YAML.
"""

import yaml
import networkx as nx
from pathlib import Path
from typing import Optional
from models import (
    Router, Interface, DeviceRole, DeviceVendor,
    RoutingDomain, DomainBoundary, DomainType,
    VRF, VRFType, RRTier,
)


class GraphEngine:
    """Network topology as a directed graph with 7-tier awareness."""

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
                    vrf=iconf.get("vrf"),
                ))

            vrfs = []
            for vconf in rconf.get("vrfs", []):
                vrfs.append(VRF(
                    name=vconf["name"],
                    vrf_type=VRFType(vconf["vrf_type"]),
                    parent_vrf=vconf.get("parent_vrf"),
                    rd=vconf.get("rd"),
                    rt_import=vconf.get("rt_import", []),
                    rt_export=vconf.get("rt_export", []),
                ))

            rr_tier = None
            if rconf.get("rr_tier"):
                rr_tier = RRTier(rconf["rr_tier"])

            router = Router(
                hostname=hostname,
                mgmt_ip=rconf["mgmt_ip"],
                vendor=DeviceVendor(rconf["vendor"]),
                role=DeviceRole(rconf["role"]),
                domain=rconf["domain"],
                site=rconf.get("site"),
                tier=rconf.get("tier"),
                rr_tier=rr_tier,
                vrfs=vrfs,
                interfaces=interfaces,
            )
            self.routers[hostname] = router

            if rconf["domain"] in self.domains:
                self.domains[rconf["domain"]].routers.append(hostname)

        # Load boundaries
        for bconf in inv.get("boundaries", []):
            self.boundaries.append(DomainBoundary(
                firewall=bconf["firewall"],
                upstream_domain=bconf["upstream_domain"],
                downstream_domain=bconf["downstream_domain"],
                tier=bconf.get("tier"),
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
                site=router.site,
                tier=router.tier,
                rr_tier=router.rr_tier.value if router.rr_tier else None,
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
                            vrf=iface.vrf,
                        )

    def get_routers_by_role(self, role: DeviceRole) -> list[Router]:
        return [r for r in self.routers.values() if r.role == role]

    def get_routers_by_tier(self, tier: int) -> list[Router]:
        return [r for r in self.routers.values() if r.tier == tier]

    def get_routers_by_site(self, site: str) -> list[Router]:
        return [r for r in self.routers.values() if r.site == site]

    def get_rr_by_tier(self, rr_tier: RRTier) -> list[Router]:
        return [r for r in self.routers.values()
                if r.role == DeviceRole.RR and r.rr_tier == rr_tier]

    def get_routers_in_domain(self, domain_name: str) -> list[Router]:
        return [r for r in self.routers.values() if r.domain == domain_name]

    def get_routers_with_vrf(self, vrf_name: str) -> list[Router]:
        """Find all routers that have a specific VRF configured."""
        return [r for r in self.routers.values()
                if any(v.name == vrf_name for v in r.vrfs)]

    def get_child_vrfs(self, parent_vrf: str) -> list[tuple[Router, VRF]]:
        """Find all child VRFs that route through a given parent VRF."""
        results = []
        for r in self.routers.values():
            for v in r.vrfs:
                if v.vrf_type == VRFType.CHILD and v.parent_vrf == parent_vrf:
                    results.append((r, v))
        return results

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

    def get_firewall_tier(self, hostname: str) -> Optional[str]:
        """Get the firewall tier (t1 or t2) for a given firewall."""
        for b in self.boundaries:
            if b.firewall == hostname:
                return b.tier
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
        """Export topology as vis.js compatible JSON with 7-tier layout."""
        role_colors = {
            DeviceRole.DCCE: "#81C784",      # Light green
            DeviceRole.DCPE: "#4CAF50",      # Green
            DeviceRole.SPE: "#66BB6A",       # Medium green
            DeviceRole.T2_FIREWALL: "#EF5350",  # Red
            DeviceRole.AGG: "#2196F3",       # Blue
            DeviceRole.T1_FIREWALL: "#F44336",  # Dark red
            DeviceRole.IPE: "#FF9800",       # Orange
            DeviceRole.RR: "#9C27B0",        # Purple
            DeviceRole.P: "#42A5F5",         # Light blue
        }
        role_shapes = {
            DeviceRole.DCCE: "dot",
            DeviceRole.DCPE: "dot",
            DeviceRole.SPE: "hexagon",
            DeviceRole.T2_FIREWALL: "triangle",
            DeviceRole.AGG: "diamond",
            DeviceRole.T1_FIREWALL: "triangle",
            DeviceRole.IPE: "square",
            DeviceRole.RR: "star",
            DeviceRole.P: "diamond",
        }
        # Vertical layout: tier determines Y position (south=bottom, north=top)
        tier_y = {1: 400, 2: 300, 3: 200, 4: 100, 5: 0, 6: -100, 7: -200}
        # Horizontal: site determines X
        site_x = {"east": -200, "west": 200}

        nodes = []
        edges = []
        seen_edges = set()

        for hostname, data in self.graph.nodes(data=True):
            role = data.get("role", DeviceRole.P)
            domain = data.get("domain", "unknown")
            tier = data.get("tier", 5)
            site = data.get("site", "east")
            rr_tier = data.get("rr_tier")

            # Compute position
            y = tier_y.get(tier, 0)
            x = site_x.get(site, 0)
            # Offset RRs to the side
            if role == DeviceRole.RR:
                x = 400
                if rr_tier == "core":
                    y = 20
                elif rr_tier == "agg":
                    y = 0
                elif rr_tier == "inet":
                    y = -20

            label = hostname.upper()
            title_parts = [hostname, f"Role: {role.value}", f"Domain: {domain}"]
            if rr_tier:
                label += f"\n({rr_tier})"
                title_parts.append(f"RR Tier: {rr_tier}")

            nodes.append({
                "id": hostname,
                "label": label,
                "color": role_colors.get(role, "#757575"),
                "shape": role_shapes.get(role, "dot"),
                "title": "\n".join(title_parts),
                "group": domain,
                "font": {"color": "#ccc", "size": 11},
                "x": x,
                "y": y,
                "fixed": {"x": True, "y": True},  # Hierarchical layout
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
