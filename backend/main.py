"""
Network Path Visualizer — Backend API

Serves the topology, handles prefix traces via AT&T route server,
returns structured BGP path data for visualization.
"""

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional

from models import PathQuery, PathResult, PrefixOrigin
from collectors.bgp import BGPCollector, JunosRouteParser, resolve_att_city
from graph_engine import GraphEngine
from path_walker import PathWalker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Network Path Visualizer",
    description="Multi-domain network path analyzer",
    version="0.2.0",
)

# Paths
backend_dir = Path(__file__).parent
project_dir = backend_dir.parent
frontend_path = project_dir / "frontend"
inventory_path = project_dir / "data" / "inventory.yaml"

# Initialize topology
graph = GraphEngine()
try:
    graph.load_inventory(str(inventory_path))
    logger.info(f"Loaded inventory: {len(graph.routers)} routers, {len(graph.domains)} domains")
except Exception as e:
    logger.warning(f"Could not load inventory: {e}")

walker = PathWalker(graph)
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
    Trace a prefix. Queries AT&T route server for real BGP paths.
    Returns structured path data with city resolution.
    """
    prefix = query.source.strip()
    if not prefix:
        raise HTTPException(400, "No prefix provided")

    try:
        paths = await collector.lookup_prefix(prefix)
    except Exception as e:
        logger.error(f"BGP lookup failed: {e}")
        raise HTTPException(502, f"Route server query failed: {str(e)}")

    # Convert BGPPath objects to PrefixOrigin models
    origins = []
    for p in paths:
        city = resolve_att_city(p.communities)
        origins.append(PrefixOrigin(
            prefix=p.prefix,
            originating_router=p.next_hop,
            origin_type=f"eBGP ({'active' if p.active else 'inactive'})",
            bgp_as_path=p.as_path,
            bgp_local_pref=p.local_pref,
            bgp_med=p.med,
            bgp_communities=p.communities,
        ))

    # Build response with BGP path details
    bgp_details = []
    for p in paths:
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

    return {
        "query": {"source": prefix},
        "origins": [o.model_dump() for o in origins],
        "bgp_paths": bgp_details,
        "path_count": len(paths),
        "active_count": sum(1 for p in paths if p.active),
        "domains_traversed": ["inet-edge"],
        "warnings": [],
    }


@app.get("/api/domains")
async def list_domains():
    return graph.get_domains()


class FailureQuery(BaseModel):
    node: str
    query: PathQuery


@app.post("/api/simulate-failure")
async def simulate_failure(req: FailureQuery):
    """Re-trace a path with a node/link removed."""
    try:
        result = await walker.trace_flow(
            req.query.source,
            req.query.destination,
            exclude_nodes=[req.node],
        )
        return result
    except Exception as e:
        raise HTTPException(500, str(e))
