"""Network Path Visualizer V3 API."""

from __future__ import annotations

import asyncio
import logging
import subprocess
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import networkx as nx

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from collectors import RouteEntry
from collectors.junos_collector import JunosCollector
from data_loader import CollectedDataLoader
from inventory import Inventory
from models import CollectionJob
from path_walker import PathWalker, TraceResult, AsymmetryResult, FailureSimResult
from graph_engine import GraphEngine
from blast_radius import BlastRadiusCalculator, BlastRadiusResult

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Network Path Visualizer", description="Generic next-hop follower", version="3.2.0")

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
_graph_engine: Optional[GraphEngine] = None


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


def _build_graph_engine_from_inventory() -> GraphEngine:
    ge = GraphEngine()
    ge.graph = nx.DiGraph()

    for hostname in inv.devices.keys():
        ge.graph.add_node(hostname)

    ip_to_host: dict[str, str] = {}
    for hostname, dev in inv.devices.items():
        for ip in dev.interfaces.values():
            if ip:
                ip_to_host[ip] = hostname

    for hostname, dev in inv.devices.items():
        for ip in dev.interfaces.values():
            peer = ip_to_host.get(ip)
            if peer and peer != hostname:
                ge.graph.add_edge(hostname, peer)

    return ge


def _get_graph_engine() -> GraphEngine:
    global _graph_engine
    if _graph_engine is None:
        _graph_engine = _build_graph_engine_from_inventory()
    return _graph_engine


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


class CompareQuery(BaseModel):
    source: str
    destination: str
    vrf: Optional[str] = None


class FailureQuery(BaseModel):
    source: str
    destination: str
    failed_node: str
    vrf: Optional[str] = None


class CollectRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    types: list[str] = Field(default_factory=lambda: ["bgp", "mpls", "isis"])


class BlastRadiusQuery(BaseModel):
    failed_node: str


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


@app.post("/api/trace/reverse")
async def trace_reverse(query: CompareQuery):
    try:
        result = await walker.trace(query.source.strip(), query.destination.strip(), query.vrf or "")
    except Exception as e:
        raise HTTPException(502, f"Reverse trace failed: {e}")
    return _serialize_result(result)


@app.post("/api/trace/compare")
async def compare_paths(query: CompareQuery):
    try:
        result = await walker.trace_reverse(query.destination.strip(), query.source.strip(), query.vrf or "")
    except Exception as e:
        raise HTTPException(502, f"Compare failed: {e}")
    return _serialize_asymmetry(result)


@app.post("/api/simulate/failure")
async def simulate_failure(query: FailureQuery):
    try:
        result = await walker.simulate_failure(query.source.strip(), query.destination.strip(), query.failed_node.strip(), query.vrf or "")
    except Exception as e:
        raise HTTPException(502, f"Failure simulation failed: {e}")
    return _serialize_failure(result)


@app.get("/api/origin/{prefix:path}")
async def get_origin(prefix: str, start_device: str):
    if start_device not in inv.devices:
        raise HTTPException(404, f"Device '{start_device}' not in inventory")
    try:
        return await walker.find_origin(prefix.strip(), start_device.strip())
    except Exception as e:
        raise HTTPException(502, f"Origin lookup failed: {e}")


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


@app.get("/api/blast-radius/nodes")
async def blast_radius_nodes():
    return {"nodes": sorted(inv.devices.keys())}


@app.post("/api/blast-radius")
async def blast_radius(query: BlastRadiusQuery):
    failed_node = query.failed_node.strip()
    if failed_node not in inv.devices:
        raise HTTPException(404, f"Node '{failed_node}' not in inventory")
    try:
        calc = BlastRadiusCalculator(_get_graph_engine())
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, calc.calculate, failed_node)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(502, f"Blast radius failed: {e}")
    return _serialize_blast_radius(result)


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "3.2.0", "devices": len(inv.devices)}


def _serialize_result(result: TraceResult) -> dict:
    return {
        "prefix": result.prefix,
        "start": result.start,
        "total_time_ms": result.total_time_ms,
        "origin_type": result.origin_type,
        "origin_router": result.origin_router,
        "ecmp_branches": [
            {
                "parent_hop": b.parent_hop,
                "branch_index": b.branch_index,
                "next_hops": b.next_hops,
                "selected_paths": b.selected_paths,
            }
            for b in result.ecmp_branches
        ],
        "domain_crossings": [
            {
                "firewall": d.firewall,
                "from_domain": d.from_domain,
                "to_domain": d.to_domain,
                "route_type": d.route_type,
            }
            for d in result.domain_crossings
        ],
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
                        "labels": [
                            {"action": l.action, "label": l.label, "lsp_name": l.lsp_name}
                            for l in h.labels
                        ],
                        "domain_crossing": (
                            {
                                "firewall": h.domain_crossing.firewall,
                                "from_domain": h.domain_crossing.from_domain,
                                "to_domain": h.domain_crossing.to_domain,
                                "route_type": h.domain_crossing.route_type,
                            }
                            if h.domain_crossing else None
                        ),
                    }
                    for h in p.hops
                ],
                "complete": p.complete,
                "end_reason": p.end_reason,
            }
            for p in result.paths
        ],
    }


def _serialize_asymmetry(result: AsymmetryResult) -> dict:
    return {
        "forward_path": _serialize_result(result.forward_path),
        "reverse_path": _serialize_result(result.reverse_path),
        "symmetric": result.symmetric,
        "divergence_points": result.divergence_points,
    }


def _serialize_failure(result: FailureSimResult) -> dict:
    return {
        "original": _serialize_result(result.original),
        "failover": _serialize_result(result.failover),
        "failed_node": result.failed_node,
        "impact_summary": result.impact_summary,
        "affected_hops": result.affected_hops,
        "convergence_notes": result.convergence_notes,
    }


def _serialize_blast_radius(result: BlastRadiusResult) -> dict:
    return {
        "failed_node": result.failed_node,
        "isolated_pairs": [
            {
                "source": p.source,
                "destination": p.destination,
                "original_path": p.original_path,
                "alternate_path": p.alternate_path,
                "status": p.status,
            }
            for p in result.isolated_pairs
        ],
        "rerouted_pairs": [
            {
                "source": p.source,
                "destination": p.destination,
                "original_path": p.original_path,
                "alternate_path": p.alternate_path,
                "status": p.status,
            }
            for p in result.rerouted_pairs
        ],
        "unaffected_node_count": result.unaffected_node_count,
        "summary": result.summary,
    }
