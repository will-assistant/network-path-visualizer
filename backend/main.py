"""
Network Path Visualizer — Backend API (V2)

AGG-first path walker with community decode.
Queries AT&T route server as mock AGG for testing.
"""

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from models import PathQuery
from collectors.bgp import BGPCollector, JunosRouteParser, resolve_att_city
from graph_engine import GraphEngine
from path_walker import PathWalkerV2
from inventory import load_ansible_inventory, Inventory

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Network Path Visualizer",
    description="AGG-first multi-domain network path analyzer with community decode",
    version="0.3.0",
)

# Paths
backend_dir = Path(__file__).parent
project_dir = backend_dir.parent
frontend_path = project_dir / "frontend"
inventory_path = project_dir / "data" / "inventory.yaml"
ansible_inventory_path = project_dir / "ansible" / "inventories" / "fis-production.yml"

# Initialize topology graph (mock inventory for vis.js)
graph = GraphEngine()
try:
    graph.load_inventory(str(inventory_path))
    logger.info(f"Loaded graph inventory: {len(graph.routers)} routers, {len(graph.domains)} domains")
except Exception as e:
    logger.warning(f"Could not load graph inventory: {e}")

# Initialize Ansible inventory (production format for V2 walker)
ansible_inv: Optional[Inventory] = None
try:
    ansible_inv = load_ansible_inventory(str(ansible_inventory_path))
    logger.info(f"Loaded Ansible inventory: {len(ansible_inv.devices)} devices, {len(ansible_inv.sites)} sites")
except Exception as e:
    logger.warning(f"Could not load Ansible inventory: {e}")

# V2 walker with inventory
walker_v2 = PathWalkerV2(inventory=ansible_inv)
collector = BGPCollector()

# Serve frontend
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")


@app.get("/")
async def root():
    return FileResponse(str(frontend_path / "index.html"))


@app.get("/api/topology")
async def get_topology():
    """Return the full network topology for vis.js rendering."""
    return graph.to_vis_json()


@app.post("/api/trace")
async def trace_path(query: PathQuery):
    """
    V2 Trace: Query AGG (AT&T RS for testing), decode communities,
    derive full paths with preference indicators.
    """
    prefix = query.source.strip()
    if not prefix:
        raise HTTPException(400, "No prefix provided")

    try:
        bgp_paths = await collector.lookup_prefix(prefix)
    except Exception as e:
        logger.error(f"BGP lookup failed: {e}")
        raise HTTPException(502, f"Route server query failed: {str(e)}")

    # V2: Derive paths using community decode
    trace_result = walker_v2.derive_paths(bgp_paths, prefix)

    # Build response with both V1 BGP details and V2 derived paths
    bgp_details = []
    for p in bgp_paths:
        city = resolve_att_city(p.communities)
        bgp_details.append({
            "next_hop": p.next_hop,
            "as_path": p.as_path,
            "origin": p.origin,
            "local_pref": p.local_pref,
            "med": p.med,
            "communities": p.communities,
            "active": p.active,
            "city": city,
            "inactive_reason": p.inactive_reason,
            "peer_as": p.peer_as,
            "router_id": p.router_id,
            "age": p.age,
        })

    # V2 derived paths
    derived_paths = []
    for dp in trace_result.paths:
        derived_paths.append({
            "path_id": dp.path_id,
            "preference": dp.preference,
            "local_pref": dp.local_pref,
            "origin_site": dp.origin_site,
            "advertising_site": dp.advertising_site,
            "region": dp.region,
            "description": dp.description,
            "active": dp.active,
            "as_path": dp.as_path,
            "next_hop": dp.next_hop,
            "communities": dp.communities,
            "firewall": {
                "region": dp.firewall.region,
                "vrf_id": dp.firewall.vrf_id,
                "next_hop": dp.firewall.next_hop,
            } if dp.firewall else None,
            "hops": [
                {
                    "device": h.device,
                    "role": h.role,
                    "domain": h.domain,
                    "site": h.site,
                    "label": h.label,
                }
                for h in dp.hops
            ],
        })

    return {
        "query": {"source": prefix},
        "bgp_paths": bgp_details,
        "derived_paths": derived_paths,
        "path_count": len(bgp_paths),
        "active_count": sum(1 for p in bgp_paths if p.active),
        "primary_path": derived_paths[0] if derived_paths else None,
        "preference_summary": {
            "primary": sum(1 for p in trace_result.paths if p.preference == "primary"),
            "secondary": sum(1 for p in trace_result.paths if p.preference == "secondary"),
            "tertiary": sum(1 for p in trace_result.paths if p.preference == "tertiary"),
            "unknown": sum(1 for p in trace_result.paths if p.preference == "unknown"),
        },
        "domains_traversed": ["inet-edge"],
        "warnings": trace_result.warnings,
    }


@app.get("/api/inventory")
async def get_inventory():
    """Return parsed inventory summary."""
    if not ansible_inv:
        return {"error": "No Ansible inventory loaded"}

    return {
        "device_count": len(ansible_inv.devices),
        "site_count": len(ansible_inv.sites),
        "regions": {r: len(sites) for r, sites in ansible_inv.regions.items()},
        "sites": {
            sid: {
                "site_number": s.site_number,
                "region": s.region,
                "dcpe_count": len(s.dcpe),
                "spe_count": len(s.spe),
                "agg_count": len(s.agg),
                "ipe_count": len(s.ipe),
                "total_devices": len(s.all_devices),
            }
            for sid, s in ansible_inv.sites.items()
        },
    }


@app.get("/api/domains")
async def list_domains():
    return graph.get_domains()


class FailureQuery(BaseModel):
    node: str
    query: PathQuery


@app.post("/api/simulate-failure")
async def simulate_failure(req: FailureQuery):
    """Re-trace with a node removed (uses graph engine for topology sim)."""
    return {"error": "Failure simulation not yet implemented for V2 walker"}
