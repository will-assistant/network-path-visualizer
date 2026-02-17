"""Network Path Visualizer V3 API."""

from __future__ import annotations

import logging
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from collectors import RouteEntry
from collectors.junos_collector import JunosCollector
from data_loader import CollectedDataLoader
from inventory import Inventory
from models import CollectionJob
from path_walker import PathWalker, TraceResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Network Path Visualizer", description="Generic next-hop follower", version="3.1.0")

backend_dir = Path(__file__).parent
project_dir = backend_dir.parent
frontend_path = project_dir / "frontend"
inventory_path = project_dir / "inventories" / "example-generic.yml"
collected_dir = project_dir / "data" / "collected"
ansible_playbook = project_dir / "ansible" / "playbooks" / "collect-all.yml"
ansible_inventory = project_dir / "inventories" / "example-generic.yml"

inv: Optional[Inventory] = None
try:
    inv = Inventory.from_yaml(str(inventory_path))
except Exception as e:
    logger.warning("Could not load inventory: %s", e)
    inv = Inventory()

_collectors: dict[str, JunosCollector] = {}
_jobs: dict[str, CollectionJob] = {}
_loader = CollectedDataLoader(collected_dir)


def _get_collector(device_name: str) -> JunosCollector:
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
    cached = _loader.lookup_routes(device_name, prefix)
    if cached:
        return cached
    collector = _get_collector(device_name)
    return await collector.get_route(prefix, vrf)


plugins = []
try:
    from plugins.fis_community_decoder import FISCommunityDecoder
    plugins.append(FISCommunityDecoder())
except ImportError:
    pass

walker = PathWalker(inventory=inv, collector_fn=collector_fn, plugins=plugins)

if frontend_path.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_path)), name="static")


class TraceQuery(BaseModel):
    prefix: str
    start_device: str
    vrf: Optional[str] = None


class CollectRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    types: list[str] = Field(default_factory=lambda: ["bgp", "mpls", "isis"])


@app.get("/")
async def root():
    return FileResponse(str(frontend_path / "index.html"))


@app.post("/api/trace")
async def trace_path(query: TraceQuery):
    if query.start_device not in inv.devices:
        raise HTTPException(404, f"Device '{query.start_device}' not in inventory")
    try:
        result = await walker.trace(query.prefix.strip(), query.start_device.strip(), query.vrf or "")
    except Exception as e:
        logger.error("Trace failed: %s", e)
        raise HTTPException(502, f"Trace failed: {e}")
    return _serialize_result(result)


@app.post("/api/collect")
async def collect(request: CollectRequest):
    if not ansible_playbook.exists():
        raise HTTPException(500, "collect-all.yml not found")

    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    job = CollectionJob(id=job_id, status="running", started_at=now, hosts=request.hosts, types=request.types)
    _jobs[job_id] = job

    cmd = ["ansible-playbook", str(ansible_playbook), "-i", str(ansible_inventory)]
    if request.hosts:
        cmd.extend(["--limit", ",".join(request.hosts)])
    if request.types:
        cmd.extend(["--tags", ",".join(request.types)])

    def _run_collection():
        try:
            proc = subprocess.Popen(cmd, cwd=str(project_dir), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out, err = proc.communicate()
            if proc.returncode == 0:
                _jobs[job_id].status = "completed"
                _loader.reload()
            else:
                _jobs[job_id].status = "failed"
                if out:
                    _jobs[job_id].errors.append(out[-2000:])
                if err:
                    _jobs[job_id].errors.append(err[-2000:])
        except Exception as exc:
            _jobs[job_id].status = "failed"
            _jobs[job_id].errors.append(str(exc))
        finally:
            _jobs[job_id].completed_at = datetime.now(timezone.utc)

    threading.Thread(target=_run_collection, daemon=True).start()
    return {"job_id": job_id, "status": "running"}


@app.get("/api/collect/{job_id}")
async def get_collection_job(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(404, "job not found")
    return job


@app.get("/api/collected")
async def list_collected_files():
    files = []
    if collected_dir.exists():
        for path in sorted(collected_dir.rglob("*.json")):
            st = path.stat()
            files.append({
                "file": str(path.relative_to(project_dir)),
                "hostname": path.parent.name,
                "size": st.st_size,
                "modified_at": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            })
    return {"files": files, "warnings": _loader.stale_warnings()}


@app.get("/api/devices")
async def list_devices():
    return {"devices": [{"hostname": name, "role": dev.role, "site": dev.site, "vendor": dev.vendor} for name, dev in inv.devices.items()]}


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "3.1.0", "devices": len(inv.devices)}


def _serialize_result(result: TraceResult) -> dict:
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
