#!/usr/bin/env python3
"""
End-to-end trace test — load inventory, trace through real route servers.

Usage: python3 scripts/trace_test.py [prefix]
"""

import sys
import asyncio
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from inventory import Inventory
from path_walker import PathWalker, TraceResult
from collectors import RouteEntry
from collectors.junos_collector import JunosCollector

INVENTORY_PATH = Path(__file__).parent.parent / "inventories" / "example-generic.yml"
DEFAULT_PREFIX = "8.8.8.0/24"

# Cache collectors
_collectors: dict[str, JunosCollector] = {}


def get_collector(inv: Inventory, device_name: str) -> JunosCollector:
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


async def timed_collector(inv: Inventory, device_name: str, prefix: str, vrf: str) -> list[RouteEntry]:
    """Collector wrapper that prints timing."""
    t0 = time.monotonic()
    collector = get_collector(inv, device_name)
    entries = await collector.get_route(prefix, vrf)
    elapsed = time.monotonic() - t0
    print(f"    ⏱ {device_name}: {elapsed:.1f}s ({len(entries)} entries)")
    return entries


def print_trace(result: TraceResult):
    """Pretty-print a trace result."""
    for pi, path in enumerate(result.paths):
        print(f"\n  Path {pi+1} ({path.end_reason}):")
        for hi, hop in enumerate(path.hops):
            print(f"    Hop {hi+1}: {hop.device}")
            if hop.next_hop:
                print(f"           → next-hop: {hop.next_hop}")
            if hop.as_path:
                print(f"           AS path: {' '.join(hop.as_path)}")
            if hop.communities:
                print(f"           Communities: {' '.join(hop.communities[:5])}")
            if hop.lp is not None:
                print(f"           LP: {hop.lp}")
            if hop.note:
                print(f"           Note: {hop.note}")


async def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PREFIX

    print(f"Loading inventory from {INVENTORY_PATH}")
    inv = Inventory.from_yaml(str(INVENTORY_PATH))
    print(f"Loaded {len(inv.devices)} devices: {', '.join(inv.devices.keys())}")

    async def collector_fn(device_name, prefix, vrf):
        return await timed_collector(inv, device_name, prefix, vrf)

    walker = PathWalker(inventory=inv, collector_fn=collector_fn)

    errors = []
    for start in ["att-rs", "gtt-rs"]:
        print(f"\n{'='*60}")
        print(f"  Trace: {prefix} from {start}")
        print(f"{'='*60}")

        t0 = time.monotonic()
        result = await walker.trace(prefix, start)
        elapsed = time.monotonic() - t0
        print(f"  Total time: {elapsed:.1f}s")

        print_trace(result)

        # Validate first hop has real data
        if result.paths:
            first_hop = result.paths[0].hops[0] if result.paths[0].hops else None
            if first_hop:
                if not first_hop.as_path:
                    errors.append(f"{start}: first hop missing AS path")
                if not first_hop.communities:
                    errors.append(f"{start}: first hop missing communities")
                if first_hop.lp is None:
                    errors.append(f"{start}: first hop missing LP")
                if not first_hop.next_hop:
                    errors.append(f"{start}: first hop missing next-hop")
            else:
                errors.append(f"{start}: no hops in trace")
        else:
            errors.append(f"{start}: no paths in trace")

    print(f"\n{'='*60}")
    if errors:
        print("⚠ VALIDATION ISSUES:")
        for e in errors:
            print(f"  - {e}")
        return 1
    else:
        print("✓ All trace validations passed!")
        return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
