"""
Path Walker V3 — Generic Next-Hop Follower.

Input: prefix + starting device.
Output: follow next-hops device by device until origin or dead end.

No hardcoded architecture. No tier model. No hardcoded community meanings.
It just follows the routing table like a packet would.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from inventory import Inventory, DeviceInfo
from collectors import RouteEntry
from plugins import CommunityDecoderPlugin

logger = logging.getLogger(__name__)


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


@dataclass
class TracePath:
    """One path through the network (may branch for ECMP)."""
    hops: list[HopResult] = field(default_factory=list)
    complete: bool = False
    end_reason: str = ""  # origin, blackhole, not_in_inventory, loop, unreachable


@dataclass
class TraceResult:
    """Complete trace result."""
    prefix: str
    start: str
    paths: list[TracePath] = field(default_factory=list)
    total_time_ms: Optional[float] = None


# Type for the async function that queries a device
from typing import Callable, Awaitable
CollectorFn = Callable[[str, str, str], Awaitable[list[RouteEntry]]]


class PathWalker:
    """
    Generic next-hop follower. Queries devices one by one,
    following the routing table like a packet would.
    """

    def __init__(
        self,
        inventory: Inventory,
        collector_fn: CollectorFn,
        plugins: list[CommunityDecoderPlugin] | None = None,
        max_hops: int = 20,
        verbose: bool = False,
    ):
        self.inventory = inventory
        self.collector_fn = collector_fn
        self.plugins = plugins or []
        self.max_hops = max_hops
        self.verbose = verbose

    async def trace(self, prefix: str, start_device: str, vrf: str = "") -> TraceResult:
        """
        Trace a prefix starting from a device. Returns all paths (ECMP branches as separate paths).
        """
        result = TraceResult(prefix=prefix, start=start_device)
        t0 = time.monotonic()

        # Start the recursive trace
        initial_path = TracePath()
        await self._walk(prefix, start_device, vrf, set(), initial_path, result)

        result.total_time_ms = (time.monotonic() - t0) * 1000
        return result

    async def _walk(
        self,
        prefix: str,
        device_name: str,
        vrf: str,
        visited: set[str],
        current_path: TracePath,
        result: TraceResult,
    ):
        """Recursive walk. Branches on ECMP."""

        # Loop detection
        if device_name in visited:
            current_path.end_reason = "loop"
            current_path.complete = False
            hop = HopResult(device=device_name, note="Loop detected — already visited")
            current_path.hops.append(hop)
            result.paths.append(current_path)
            return

        # Max hop safety
        if len(current_path.hops) >= self.max_hops:
            current_path.end_reason = "max_hops"
            current_path.complete = False
            result.paths.append(current_path)
            return

        visited = visited | {device_name}  # Copy for branching

        # Get device info
        dev = self.inventory.get_device(device_name)
        role = dev.role if dev else ""

        # Query the device with timing
        t0 = time.monotonic()
        try:
            entries = await self.collector_fn(device_name, prefix, vrf)
            query_time_ms = (time.monotonic() - t0) * 1000
        except Exception as e:
            logger.error(f"Failed to query {device_name}: {e}")
            hop = HopResult(device=device_name, role=role, note=f"Unreachable: {e}")
            current_path.hops.append(hop)
            current_path.end_reason = "unreachable"
            current_path.complete = False
            result.paths.append(current_path)
            return

        if not entries:
            # No route — blackhole
            hop = HopResult(device=device_name, role=role, note="No route found")
            current_path.hops.append(hop)
            current_path.end_reason = "blackhole"
            current_path.complete = False
            result.paths.append(current_path)
            return

        # Use the active/best entry
        active_entries = [e for e in entries if e.active]
        if not active_entries:
            active_entries = entries[:1]  # Fallback to first

        best = active_entries[0]

        # Check for connected/direct — origin found
        if best.protocol in ("direct", "connected", "local"):
            hop = HopResult(
                device=device_name, role=role, protocol=best.protocol,
                interface=best.interface, note="Origin — connected route",
            )
            current_path.hops.append(hop)
            current_path.end_reason = "origin"
            current_path.complete = True
            result.paths.append(current_path)
            return

        # Build hop for this device
        hop = self._build_hop(device_name, role, best)
        hop.query_time_ms = query_time_ms
        # Include all entries summary for last-hop enrichment
        hop.all_entries = [
            {
                "next_hop": e.next_hop,
                "as_path": e.as_path,
                "communities": e.communities,
                "lp": e.local_pref,
                "active": e.active,
                "peer_as": e.peer_as,
            }
            for e in entries
        ]
        current_path.hops.append(hop)

        # Gather all next-hops for ECMP
        all_next_hops = set()
        all_next_hops.add(best.next_hop)
        for ecmp_path in best.paths:
            if ecmp_path.next_hop:
                all_next_hops.add(ecmp_path.next_hop)
        # Also check other active entries
        for ae in active_entries[1:]:
            if ae.next_hop:
                all_next_hops.add(ae.next_hop)

        all_next_hops.discard("")

        if not all_next_hops:
            current_path.end_reason = "blackhole"
            current_path.complete = False
            result.paths.append(current_path)
            return

        next_hops = sorted(all_next_hops)

        # Single next-hop: continue on same path
        if len(next_hops) == 1:
            nh = next_hops[0]
            next_device = self.inventory.resolve_ip(nh)
            if not next_device:
                current_path.end_reason = "not_in_inventory"
                current_path.complete = False
                last_hop = HopResult(
                    device=f"unknown ({nh})",
                    note=f"Next-hop {nh} not in inventory",
                )
                current_path.hops.append(last_hop)
                result.paths.append(current_path)
                return
            await self._walk(prefix, next_device, vrf, visited, current_path, result)

        else:
            # ECMP: branch for each next-hop
            for nh in next_hops:
                next_device = self.inventory.resolve_ip(nh)
                # Clone the path for this branch
                branch = TracePath(hops=list(current_path.hops))

                if not next_device:
                    branch.end_reason = "not_in_inventory"
                    branch.complete = False
                    branch.hops.append(HopResult(
                        device=f"unknown ({nh})",
                        note=f"Next-hop {nh} not in inventory",
                    ))
                    result.paths.append(branch)
                else:
                    await self._walk(prefix, next_device, vrf, visited, branch, result)

    def _build_hop(self, device: str, role: str, entry: RouteEntry) -> HopResult:
        """Build a HopResult from a RouteEntry."""
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

        # Run plugins
        for plugin in self.plugins:
            try:
                labels = plugin.decode(entry.communities, entry.local_pref)
                if labels:
                    hop.plugin_labels[plugin.name()] = labels
            except Exception as e:
                logger.warning(f"Plugin {plugin.name()} failed: {e}")

        return hop
