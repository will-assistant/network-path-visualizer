"""
Junos Collector — Query Junos devices via telnet/pexpect.

Reuses the proven AT&T route server parser from Phase 1.
Normalizes output to RouteEntry format.
"""

import re
import logging
from typing import Optional

from collectors import RouteEntry

logger = logging.getLogger(__name__)


class JunosParser:
    """Parse Junos 'show route <prefix> detail' output into RouteEntry objects."""

    @staticmethod
    def parse(output: str, prefix: str = "") -> list[RouteEntry]:
        """Parse full Junos detail output into RouteEntry list."""
        entries = []

        # Extract prefix from output
        prefix_match = re.search(r'^(\S+/\d+)\s+\(\d+ entries', output, re.MULTILINE)
        if prefix_match:
            prefix = prefix_match.group(1)

        # Find all BGP entry blocks
        entry_pattern = re.compile(r'^(\s+)(\*?)BGP\s+Preference:', re.MULTILINE)
        starts = [m.start() for m in entry_pattern.finditer(output)]
        if not starts:
            # Check for direct/static/local routes
            return JunosParser._parse_non_bgp(output, prefix)

        blocks = []
        for i, start in enumerate(starts):
            end = starts[i + 1] if i + 1 < len(starts) else len(output)
            blocks.append(output[start:end])

        for block in blocks:
            entry = JunosParser._parse_bgp_block(block, prefix)
            if entry:
                entries.append(entry)

        # Build ECMP: if multiple active entries, group them
        active = [e for e in entries if e.active]
        if len(active) > 1:
            # Create a single entry with ECMP paths
            primary = active[0]
            primary.paths = active[1:]

        return entries

    @staticmethod
    def _parse_non_bgp(output: str, prefix: str) -> list[RouteEntry]:
        """Parse non-BGP routes (direct, static, local)."""
        entries = []

        # Look for Direct/Local/Static entries
        for proto in ['Direct', 'Static', 'Local', 'OSPF', 'IS-IS']:
            pattern = re.compile(rf'^\s+\*?{proto}\s+Preference:', re.MULTILINE)
            if pattern.search(output):
                entry = RouteEntry(
                    prefix=prefix,
                    protocol=proto.lower().replace('is-is', 'isis'),
                    active='*' in output.split(proto)[0][-5:] if proto in output else False,
                )
                # Extract next-hop
                nh_match = re.search(r'Next hop:\s+(\S+)', output)
                if nh_match:
                    entry.next_hop = nh_match.group(1)
                # Extract interface
                iface_match = re.search(r'via\s+(\S+)', output)
                if iface_match:
                    entry.interface = iface_match.group(1)
                entries.append(entry)

        return entries

    @staticmethod
    def _parse_bgp_block(block: str, prefix: str) -> Optional[RouteEntry]:
        """Parse a single BGP entry block."""
        lines = block.split('\n')
        active = '*BGP' in lines[0]

        entry = RouteEntry(
            prefix=prefix,
            protocol="bgp",
            active=active,
        )

        for line in lines:
            s = line.strip()

            m = re.match(r'Source:\s+(\S+)', s)
            if m:
                entry.next_hop = m.group(1)
                entry.source = m.group(1)
                continue

            m = re.match(r'State:\s+<(.+?)>', s)
            if m:
                state = m.group(1)
                entry.active = 'Active' in state and 'NotBest' not in state
                continue

            m = re.match(r'Inactive reason:\s+(.+)', s)
            if m:
                entry.inactive_reason = m.group(1).strip()
                continue

            m = re.search(r'Local AS:\s+(\d+)\s+Peer AS:\s+(\d+)', s)
            if m:
                entry.peer_as = int(m.group(2))
                continue

            m = re.search(r'Age:\s+(\S+)', s)
            if m:
                entry.age = m.group(1)

            m = re.search(r'Metric2:\s+(\d+)', s)
            if m:
                entry.metric = int(m.group(1))
                continue

            m = re.match(r'AS path:\s+(.+)', s)
            if m:
                parts = m.group(1).strip().split()
                # Last token is origin indicator (I/E/?)
                if parts and parts[-1] in ('I', 'E', '?'):
                    parts.pop()
                entry.as_path = parts
                continue

            m = re.match(r'Communities:\s+(.+)', s)
            if m:
                entry.communities = m.group(1).strip().split()
                continue

            m = re.match(r'Localpref:\s+(\d+)', s)
            if m:
                entry.local_pref = int(m.group(1))
                continue

            m = re.match(r'Router ID:\s+(\S+)', s)
            if m:
                entry.router_id = m.group(1)
                continue

            m = re.match(r'Task:\s+BGP_(\d+)\.', s)
            if m:
                entry.peer_as = int(m.group(1))
                continue

        return entry if entry.next_hop else None


class JunosCollector:
    """Collect routes from Junos devices via telnet/pexpect."""

    def __init__(self, host: str, username: str = "", password: str = "",
                 connection: str = "telnet"):
        self.host = host
        self.username = username
        self.password = password
        self.connection = connection

    async def get_route(self, prefix: str, vrf: str = "") -> list[RouteEntry]:
        """Query device for a route and return normalized RouteEntry list."""
        import pexpect

        prompt = r'[^\s]+>'

        try:
            child = pexpect.spawn(
                f'telnet {self.host}',
                timeout=60,
                maxread=2000000,
                encoding='utf-8',
            )

            child.expect('login:', timeout=30)
            child.sendline(self.username)
            child.expect('Password:', timeout=10)
            child.sendline(self.password)
            child.expect(prompt, timeout=30)

            # Disable paging
            child.sendline('set cli screen-length 0')
            child.expect(prompt, timeout=10)

            # Build command
            cmd = f'show route {prefix} detail'
            if vrf:
                cmd = f'show route table {vrf}.inet.0 {prefix} detail'
            child.sendline(f'{cmd} | no-more')
            child.expect(prompt, timeout=180)

            output = child.before

            child.sendline('exit')
            child.close()

            entries = JunosParser.parse(output, prefix)
            logger.info(f"[{self.host}] {prefix}: {len(entries)} entries")
            return entries

        except Exception as e:
            logger.error(f"[{self.host}] query failed: {e}")
            raise
