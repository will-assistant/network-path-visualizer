"""
Path Walker V3 — Generic Next-Hop Follower.

Enhanced in Phase 3 with:
- ECMP branch tree + branch caps
- MPLS label operation tracking
- Domain boundary crossing annotations
- Reverse trace + asymmetry detection
- Failure simulation
- Prefix origin detection
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional, Callable, Awaitable

from inventory import Inventory
from collectors import RouteEntry
from plugins import CommunityDecoderPlugin

logger = logging.getLogger(__name__)


@dataclass
class LabelOp:
    action: str  # push|swap|pop
    label: int
    lsp_name: Optional[str] = None


@dataclass
class DomainCrossing:
    firewall: str
    from_domain: str
    to_domain: str
    route_type: str  # static|policy


@dataclass
class HopResult:
    """A single hop in the trace."""
    device: str
    role: str = ""
    next_hop: str = ""
    protocol: str = ""
    communities: list[str] = field(default_factory=list)
    lp: Optional[int] = None
    as_path: list[str] = field(default_factory=list)
    metric: Optional[int] = None
    interface: str = ""
    vrf: str = ""
    plugin_labels: dict = field(default_factory=dict)
    note: str = ""
    query_time_ms: Optional[float] = None
    raw_output: str = ""  # populated in verbose mode
    all_entries: list[dict] = field(default_factory=list)  # all route entries at this hop
    labels: list[LabelOp] = field(default_factory=list)
    domain_crossing: Optional[DomainCrossing] = None


@dataclass
class ECMPBranch:
    parent_hop: str
    branch_index: int
    next_hops: list[str] = field(default_factory=list)
    selected_paths: list[str] = field(default_factory=list)


@dataclass
class TracePath:
    """One path through the network (may branch for ECMP)."""
    hops: list[HopResult] = field(default_factory=list)
    complete: bool = False
    end_reason: str = ""  # origin, blackhole, not_in_inventory, loop, unreachable
    branches: list["TracePath"] = field(default_factory=list)


@dataclass
class TraceResult:
    """Complete trace result."""
    prefix: str
    start: str
    paths: list[TracePath] = field(default_factory=list)
    total_time_ms: Optional[float] = None
    ecmp_branches: list[ECMPBranch] = field(default_factory=list)
    domain_crossings: list[DomainCrossing] = field(default_factory=list)
    origin_type: Optional[str] = None
    origin_router: Optional[str] = None


@dataclass
class AsymmetryResult:
    forward_path: TraceResult
    reverse_path: TraceResult
    symmetric: bool
    divergence_points: list[int] = field(default_factory=list)


@dataclass
class FailureSimResult:
    original: TraceResult
    failover: TraceResult
    failed_node: str
    impact_summary: str
    affected_hops: list[str] = field(default_factory=list)
    convergence_notes: str = ""


CollectorFn = Callable[[str, str, str], Awaitable[list[RouteEntry]]]


class PathWalker:
    """Generic next-hop follower."""

    def __init__(
        self,
        inventory: Inventory,
        collector_fn: CollectorFn,
        plugins: list[CommunityDecoderPlugin] | None = None,
        max_hops: int = 20,
        verbose: bool = False,
        max_ecmp_branches: int = 8,
    ):
        self.inventory = inventory
        self.collector_fn = collector_fn
        self.plugins = plugins or []
        self.max_hops = max_hops
        self.verbose = verbose
        self.max_ecmp_branches = max_ecmp_branches

    async def trace(
        self,
        prefix: str,
        start_device: str,
        vrf: str = "",
        exclude_nodes: Optional[set[str]] = None,
    ) -> TraceResult:
        result = TraceResult(prefix=prefix, start=start_device)
        t0 = time.monotonic()
        initial_path = TracePath()
        await self._walk(prefix, start_device, vrf, set(), initial_path, result, 0, exclude_nodes or set())
        result.total_time_ms = (time.monotonic() - t0) * 1000
        result.origin_type, result.origin_router = self._detect_origin_from_paths(result.paths)
        return result

    async def trace_reverse(self, destination: str, source: str, vrf: str = "") -> AsymmetryResult:
        forward = await self.trace(destination, source, vrf)
        reverse = await self.trace(source, destination, vrf)
        symmetric, divergence = self._compare_paths(forward, reverse)
        return AsymmetryResult(
            forward_path=forward,
            reverse_path=reverse,
            symmetric=symmetric,
            divergence_points=divergence,
        )

    async def simulate_failure(self, source: str, destination: str, failed_node: str, vrf: str = "") -> FailureSimResult:
        original = await self.trace(destination, source, vrf)
        failover = await self.trace(destination, source, vrf, exclude_nodes={failed_node})

        original_nodes = {h.device for p in original.paths for h in p.hops}
        fail_nodes = {h.device for p in failover.paths for h in p.hops}
        affected = sorted(original_nodes - fail_nodes)

        if not failover.paths:
            impact = f"No failover path after removing {failed_node}"
        elif any(p.complete for p in failover.paths):
            impact = f"Failover succeeded around {failed_node}"
        else:
            impact = f"Failover degraded after removing {failed_node}"

        return FailureSimResult(
            original=original,
            failover=failover,
            failed_node=failed_node,
            impact_summary=impact,
            affected_hops=affected,
            convergence_notes="Control-plane reconvergence not simulated; data-driven path recomputation only.",
        )

    async def find_origin(self, prefix: str, start_device: str, vrf: str = "") -> dict:
        result = await self.trace(prefix, start_device, vrf)
        return {
            "prefix": prefix,
            "origin_type": result.origin_type or "unknown",
            "origin_router": result.origin_router or "",
        }

    async def _walk(
        self,
        prefix: str,
        device_name: str,
        vrf: str,
        visited: set[str],
        current_path: TracePath,
        result: TraceResult,
        branch_depth: int,
        exclude_nodes: set[str],
    ):
        if device_name in exclude_nodes:
            current_path.end_reason = "failed_node"
            current_path.complete = False
            current_path.hops.append(HopResult(device=device_name, note="Excluded due to failure simulation"))
            result.paths.append(current_path)
            return

        if device_name in visited:
            current_path.end_reason = "loop"
            current_path.complete = False
            current_path.hops.append(HopResult(device=device_name, note="Loop detected — already visited"))
            result.paths.append(current_path)
            return

        if len(current_path.hops) >= self.max_hops:
            current_path.end_reason = "max_hops"
            current_path.complete = False
            result.paths.append(current_path)
            return

        visited = visited | {device_name}
        dev = self.inventory.get_device(device_name)
        role = dev.role if dev else ""

        t0 = time.monotonic()
        try:
            entries = await self.collector_fn(device_name, prefix, vrf)
            query_time_ms = (time.monotonic() - t0) * 1000
        except Exception as e:
            logger.error("Failed to query %s: %s", device_name, e)
            current_path.hops.append(HopResult(device=device_name, role=role, note=f"Unreachable: {e}"))
            current_path.end_reason = "unreachable"
            result.paths.append(current_path)
            return

        if not entries:
            current_path.hops.append(HopResult(device=device_name, role=role, note="No route found"))
            current_path.end_reason = "blackhole"
            result.paths.append(current_path)
            return

        # Firewall/domain boundary preference: static/policy first.
        if self.inventory.is_firewall(device_name):
            fw_entries = [e for e in entries if e.protocol in ("static", "policy")]
            if fw_entries:
                entries = fw_entries

        active_entries = [e for e in entries if e.active]
        if not active_entries:
            active_entries = entries[:1]

        best = active_entries[0]

        if best.protocol in ("direct", "connected", "local"):
            current_path.hops.append(HopResult(
                device=device_name,
                role=role,
                protocol=best.protocol,
                interface=best.interface,
                note="Origin — connected route",
            ))
            current_path.end_reason = "origin"
            current_path.complete = True
            result.paths.append(current_path)
            return

        hop = self._build_hop(device_name, role, best)
        hop.query_time_ms = query_time_ms
        hop.all_entries = [{
            "next_hop": e.next_hop,
            "as_path": e.as_path,
            "communities": e.communities,
            "lp": e.local_pref,
            "metric": e.metric,
            "active": e.active,
            "peer_as": e.peer_as,
            "protocol": e.protocol,
        } for e in entries]
        hop.labels = self.inventory.get_mpls_label_ops(device_name, best.next_hop)

        crossing = self.inventory.get_domain_crossing(device_name, best.next_hop)
        if crossing:
            crossing.route_type = "policy" if best.protocol == "policy" else "static"
            hop.domain_crossing = crossing
            result.domain_crossings.append(crossing)

        current_path.hops.append(hop)

        next_hops = self._collect_next_hops(best, active_entries)
        if not next_hops:
            current_path.end_reason = "blackhole"
            result.paths.append(current_path)
            return

        if len(next_hops) == 1:
            nh = next_hops[0]
            next_device = self.inventory.resolve_ip(nh)
            if not next_device:
                current_path.end_reason = "not_in_inventory"
                current_path.hops.append(HopResult(device=f"unknown ({nh})", note=f"Next-hop {nh} not in inventory"))
                result.paths.append(current_path)
                return
            await self._walk(prefix, next_device, vrf, visited, current_path, result, branch_depth, exclude_nodes)
            return

        # ECMP branch capping
        if branch_depth >= self.max_ecmp_branches:
            current_path.end_reason = "ecmp_depth_exceeded"
            result.paths.append(current_path)
            return

        selected = next_hops[: self.max_ecmp_branches]
        branch_meta = ECMPBranch(
            parent_hop=device_name,
            branch_index=branch_depth,
            next_hops=next_hops,
            selected_paths=selected,
        )
        result.ecmp_branches.append(branch_meta)

        for nh in selected:
            next_device = self.inventory.resolve_ip(nh)
            branch = TracePath(hops=list(current_path.hops))
            current_path.branches.append(branch)
            if not next_device:
                branch.end_reason = "not_in_inventory"
                branch.hops.append(HopResult(device=f"unknown ({nh})", note=f"Next-hop {nh} not in inventory"))
                result.paths.append(branch)
            else:
                await self._walk(prefix, next_device, vrf, visited, branch, result, branch_depth + 1, exclude_nodes)

    @staticmethod
    def _collect_next_hops(best: RouteEntry, active_entries: list[RouteEntry]) -> list[str]:
        all_next_hops = set()
        if best.next_hop:
            all_next_hops.add(best.next_hop)
        for ecmp_path in best.paths:
            if ecmp_path.next_hop:
                all_next_hops.add(ecmp_path.next_hop)
        for ae in active_entries[1:]:
            if ae.next_hop:
                all_next_hops.add(ae.next_hop)
        return sorted(all_next_hops)

    @staticmethod
    def _detect_origin_from_paths(paths: list[TracePath]) -> tuple[Optional[str], Optional[str]]:
        for path in paths:
            if not path.hops:
                continue
            last = path.hops[-1]
            if path.end_reason == "origin":
                return "connected", last.device
            if last.protocol == "static":
                return "static", last.device
            if last.protocol == "bgp":
                return "ebgp", last.device
        return None, None

    @staticmethod
    def _compare_paths(forward: TraceResult, reverse: TraceResult) -> tuple[bool, list[int]]:
        if not forward.paths or not reverse.paths:
            return False, [0]
        f = [h.device for h in forward.paths[0].hops]
        r = list(reversed([h.device for h in reverse.paths[0].hops]))
        divergence = []
        for i, (fd, rd) in enumerate(zip(f, r)):
            if fd != rd:
                divergence.append(i)
        if len(f) != len(r):
            divergence.append(min(len(f), len(r)))
        return len(divergence) == 0, divergence

    def _build_hop(self, device: str, role: str, entry: RouteEntry) -> HopResult:
        hop = HopResult(
            device=device,
            role=role,
            next_hop=entry.next_hop,
            protocol=entry.protocol,
            communities=entry.communities,
            lp=entry.local_pref,
            as_path=entry.as_path,
            metric=entry.metric,
            interface=entry.interface,
            vrf=entry.vrf,
        )
        for plugin in self.plugins:
            try:
                labels = plugin.decode(entry.communities, entry.local_pref)
                if labels:
                    hop.plugin_labels[plugin.name()] = labels
            except Exception as e:
                logger.warning("Plugin %s failed: %s", plugin.name(), e)
        return hop
