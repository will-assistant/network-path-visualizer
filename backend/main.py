"""
Network Path Visualizer — Backend API

Core engine that:
1. Accepts a prefix or src/dst pair
2. Walks the forwarding path across routing domains
3. Returns structured path data for visualization
"""

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import networkx as nx
from pathlib import Path

from models import (
    PathQuery, PathResult, PathHop, RoutingDomain,
    DomainBoundary, PrefixOrigin, MultiPath
)
from collectors.bgp import BGPCollector
from graph_engine import GraphEngine
from path_walker import PathWalker

app = FastAPI(
    title="Network Path Visualizer",
    description="Multi-domain network path analyzer",
    version="0.1.0"
)

# Serve frontend
frontend_path = Path(__file__).parent.parent / "frontend"
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")

# Initialize engines
graph = GraphEngine()
walker = PathWalker(graph)


@app.get("/")
async def root():
    return FileResponse(str(frontend_path / "index.html"))


@app.post("/api/trace", response_model=PathResult)
async def trace_path(query: PathQuery):
    """
    Trace the forwarding path for a prefix or src/dst pair.
    
    - prefix only: Find origination point(s)
    - src + dst: Find all forwarding paths between them
    """
    try:
        if query.destination:
            result = await walker.trace_flow(query.source, query.destination)
        else:
            result = await walker.find_origin(query.source)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/topology")
async def get_topology():
    """Return the full network topology graph for visualization."""
    return graph.to_vis_json()


@app.post("/api/collect")
async def trigger_collection():
    """Trigger an Ansible collection run to refresh router data."""
    # TODO: Trigger ansible-playbook via subprocess
    return {"status": "collection triggered"}


@app.get("/api/domains")
async def list_domains():
    """List all known routing domains and boundaries."""
    return graph.get_domains()


@app.post("/api/simulate-failure")
async def simulate_failure(node: str, query: PathQuery):
    """Re-trace a path with a node/link removed."""
    try:
        result = await walker.trace_flow(
            query.source, 
            query.destination,
            exclude_nodes=[node]
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
