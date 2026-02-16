#!/usr/bin/env python3
"""
Live test — connect to BOTH route servers (AT&T + GTT) and validate parsing.

Usage: python3 scripts/live_test.py [prefix]
Default prefix: 8.8.8.0/24
"""

import sys
import asyncio
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
from collectors.junos_collector import JunosCollector

SERVERS = [
    ("ATT", "route-server.ip.att.net", "rviews", "rviews"),
    ("GTT", "route-server.ip.tiscali.net", "public", "public"),
]
DEFAULT_PREFIX = "8.8.8.0/24"


async def test_server(name: str, host: str, user: str, pw: str, prefix: str) -> bool:
    """Test one route server. Returns True if all validations pass."""
    print(f"\n{'='*60}")
    print(f"  {name} — {host}")
    print(f"{'='*60}")

    collector = JunosCollector(host=host, username=user, password=pw, connection="telnet")
    entries = await collector.get_route(prefix)

    active = [e for e in entries if e.active]
    print(f"\nParsed {len(entries)} entries, {len(active)} active\n")

    for i, e in enumerate(entries):
        tag = "★ ACTIVE" if e.active else "  inactive"
        print(f"  [{i+1}] {tag}")
        print(f"      Next-hop:     {e.next_hop}")
        print(f"      AS Path:      {' '.join(e.as_path)}")
        print(f"      LP:           {e.local_pref}")
        print(f"      Communities:  {' '.join(e.communities)}")
        print(f"      Peer AS:      {e.peer_as}")
        print(f"      Router ID:    {e.router_id}")
        if e.inactive_reason:
            print(f"      Reason:       {e.inactive_reason}")
        print()

    # Validate
    errors = []
    if not entries:
        errors.append("No entries parsed!")
    if len(active) != 1:
        errors.append(f"Expected 1 active entry, got {len(active)}")
    for e in entries:
        if not e.next_hop:
            errors.append("Entry missing next_hop")
        if not e.as_path:
            errors.append(f"Entry {e.next_hop} missing AS path")
        if e.local_pref is None:
            errors.append(f"Entry {e.next_hop} missing local_pref")
        if not e.communities:
            errors.append(f"Entry {e.next_hop} missing communities")

    if errors:
        print(f"⚠ {name} VALIDATION ISSUES:")
        for err in errors:
            print(f"  - {err}")
        return False
    else:
        print(f"✓ {name} — all validations passed!")
        return True


async def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PREFIX
    print(f"Testing prefix: {prefix}")

    results = []
    for name, host, user, pw in SERVERS:
        ok = await test_server(name, host, user, pw, prefix)
        results.append((name, ok))

    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    all_ok = True
    for name, ok in results:
        status = "✓ PASS" if ok else "✗ FAIL"
        print(f"  {name}: {status}")
        if not ok:
            all_ok = False

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
