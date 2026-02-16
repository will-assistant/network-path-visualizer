#!/usr/bin/env python3
"""
Live test — connect to AT&T route server and parse real BGP output.

Usage: python3 scripts/live_test.py [prefix]
Default prefix: 8.8.8.0/24
"""

import sys
import pexpect
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))
from collectors.junos_collector import JunosParser

HOST = "route-server.ip.att.net"
USERNAME = "rviews"
PASSWORD = "rviews"
DEFAULT_PREFIX = "8.8.8.0/24"


def collect_output(prefix: str) -> str:
    """Connect to AT&T RS via telnet and collect route detail."""
    prompt = r"\r\n\S+> "
    print(f"Connecting to {HOST}...")
    child = pexpect.spawn(f"telnet {HOST}", timeout=60, maxread=2000000, encoding="utf-8")

    child.expect("login:", timeout=30)
    child.sendline(USERNAME)
    child.expect("Password:", timeout=10)
    child.sendline(PASSWORD)
    child.expect(prompt, timeout=30)
    print("Logged in. Disabling paging...")

    child.sendline("set cli screen-length 0")
    child.expect(prompt, timeout=10)

    cmd = f"show route {prefix} detail | no-more"
    print(f"Running: {cmd}")
    child.sendline(cmd)
    child.expect(prompt, timeout=180)

    output = child.before
    child.sendline("exit")
    child.close()
    return output


def main():
    prefix = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PREFIX

    output = collect_output(prefix)
    print(f"\n{'='*60}")
    print(f"Raw output: {len(output)} chars")
    print(f"{'='*60}\n")

    entries = JunosParser.parse(output, prefix)
    print(f"Parsed {len(entries)} RouteEntry objects:\n")

    active_count = 0
    for i, e in enumerate(entries):
        status = "★ ACTIVE" if e.active else "  inactive"
        if e.active:
            active_count += 1
        print(f"  [{i+1}] {status}")
        print(f"      Prefix:    {e.prefix}")
        print(f"      Next-hop:  {e.next_hop} (source: {e.source})")
        print(f"      AS Path:   {' '.join(e.as_path)}")
        print(f"      LP:        {e.local_pref}")
        print(f"      Communities: {' '.join(e.communities)}")
        print(f"      Peer AS:   {e.peer_as}")
        print(f"      Router ID: {e.router_id}")
        print(f"      Age:       {e.age}")
        if e.inactive_reason:
            print(f"      Reason:    {e.inactive_reason}")
        print()

    print(f"Summary: {len(entries)} entries, {active_count} active")

    # Validation
    errors = []
    if not entries:
        errors.append("No entries parsed!")
    else:
        if active_count != 1:
            errors.append(f"Expected 1 active entry, got {active_count}")
        for e in entries:
            if not e.next_hop:
                errors.append(f"Entry missing next_hop")
            if not e.as_path:
                errors.append(f"Entry for {e.next_hop} missing AS path")
            if e.local_pref is None:
                errors.append(f"Entry for {e.next_hop} missing local_pref")

    if errors:
        print("\n⚠ VALIDATION ISSUES:")
        for err in errors:
            print(f"  - {err}")
        return 1
    else:
        print("\n✓ All validations passed!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
