"""
Network Path Visualizer V3 — Generic Next-Hop Follower API.

No hardcoded architecture. Just follows the routing table.
"""

import logging
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from inventory import Inventory
from path_walker import PathWalker, TraceResult
from collectors import RouteEntry
from collectors.junos_collector import JunosCollector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Network Path Visualizer",
    description="Generic next-hop follower — trace routes across any network",
    version="3.0.0",
)

# Paths
backend_dir = Path(__file__).parent
project_dir = backend_dir.parent
frontend_path = project_dir / "frontend"
inventory_path = project_dir / "inventories" / "example-generic.yml"

# Load inventory
inv: Optional[Inventory] = None
try:
    inv = Inventory.from_yaml(str(inventory_path))
    logger.info(f"Loaded inventory: {len(inv.devices)} devices")
except Exception as e:
    logger.warning(f"Could not load inventory: {e}")
    inv = Inventory()

# Collector cache (lazy-init per device)
_collectors: dict[str, JunosCollector] = {}


def _get_collector(device_name: str) -> JunosCollector:
    """Get or create a collector for a device."""
    if device_name not in _collectors:
        dev = inv.get_device(device_name)
        if not dev:
            raise ValueError(f"Device {device_name} not in inventory")
        _collectors[device_name] = JunosCollector(
            host=dev.management_ip,
            username=dev.credentials.get("username", ""),
            password=dev.credentials.get("password", ""),
            connection=dev.connection,
        )
    return _collectors[device_name]


async def collector_fn(device_name: str, prefix: str, vrf: str) -> list[RouteEntry]:
    """Universal collector function — dispatches to vendor-specific collector."""
    collector = _get_collector(device_name)
    return await collector.get_route(prefix, vrf)


# Load plugins
plugins = []
try:
    from plugins.fis_community_decoder import FISCommunityDecoder
    plugins.append(FISCommunityDecoder())
    logger.info("Loaded FIS community decoder plugin")
except ImportError:
    pass

# Walker
walker = PathWalker(
    inventory=inv,
    collector_fn=collector_fn,
    plugins=plugins,
)

# Serve frontend
if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")


class TraceQuery(BaseModel):
    prefix: str
    start_device: str
    vrf: Optional[str] = None


@app.get("/")
async def root():
    return FileResponse(str(frontend_path / "index.html"))


@app.post("/api/trace")
async def trace_path(query: TraceQuery):
    """Trace a prefix from a starting device, following next-hops."""
    prefix = query.prefix.strip()
    start = query.start_device.strip()

    if not prefix:
        raise HTTPException(400, "No prefix provided")
    if not start:
        raise HTTPException(400, "No start_device provided")
    if start not in inv.devices:
        raise HTTPException(404, f"Device '{start}' not in inventory")

    try:
        result = await walker.trace(prefix, start, query.vrf or "")
    except Exception as e:
        logger.error(f"Trace failed: {e}")
        raise HTTPException(502, f"Trace failed: {str(e)}")

    return _serialize_result(result)


@app.get("/api/devices")
async def list_devices():
    """Return all devices in inventory for the frontend dropdown."""
    devices = []
    for name, dev in inv.devices.items():
        devices.append({
            "hostname": name,
            "role": dev.role,
            "site": dev.site,
            "vendor": dev.vendor,
        })
    return {"devices": devices}


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "version": "3.0.0",
        "devices": len(inv.devices),
    }


def _serialize_result(result: TraceResult) -> dict:
    """Serialize TraceResult to JSON response."""
    return {
        "prefix": result.prefix,
        "start": result.start,
        "total_time_ms": result.total_time_ms,
        "paths": [
            {
                "hops": [
                    {
                        "device": h.device,
                        "role": h.role,
                        "next_hop": h.next_hop,
                        "protocol": h.protocol,
                        "communities": h.communities,
                        "lp": h.lp,
                        "as_path": h.as_path,
                        "metric": h.metric,
                        "interface": h.interface,
                        "vrf": h.vrf,
                        "plugin_labels": h.plugin_labels,
                        "note": h.note,
                        "query_time_ms": h.query_time_ms,
                        "all_entries": h.all_entries,
                    }
                    for h in p.hops
                ],
                "complete": p.complete,
                "end_reason": p.end_reason,
            }
            for p in result.paths
        ],
    }
