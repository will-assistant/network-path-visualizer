"""
BGP Collector — Query BGP tables via public route servers or NETCONF.

For development/testing: Uses AT&T's public route server (Junos-based)
via pexpect telnet to validate BGP path logic against real Internet routing data.
"""

import re
import logging
from typing import Optional
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BGPPath:
    prefix: str
    next_hop: str            # Source IP (the peer that sent the route)
    as_path: str
    origin: str              # 'IGP', 'EGP', '?'
    local_pref: Optional[int] = None
    med: Optional[int] = None
    communities: list[str] = field(default_factory=list)
    active: bool = False
    source_router: Optional[str] = None  # Task field peer IP
    inactive_reason: Optional[str] = None
    peer_as: Optional[int] = None
    local_as: Optional[int] = None
    router_id: Optional[str] = None
    age: Optional[str] = None
    validation_state: Optional[str] = None


class JunosRouteParser:
    """Parse Junos 'show route <prefix> detail' output into BGPPath objects."""

    @staticmethod
    def parse(output: str, prefix: str = "") -> list[BGPPath]:
        """
        Parse full Junos detail output. Handles multiple entries per prefix.
        
        Each entry starts with '*BGP' (active) or ' BGP' (inactive) at
        column ~8, followed by 'Preference: ...' on the same line.
        """
        paths = []
        # Split into individual BGP entry blocks
        # Each block starts with optional '*' then 'BGP    Preference:'
        entry_pattern = re.compile(r'^(\s+)(\*?)BGP\s+Preference:', re.MULTILINE)
        
        # Find prefix line to extract the actual prefix
        prefix_match = re.search(r'^(\S+/\d+)\s+\((\d+) entries', output, re.MULTILINE)
        if prefix_match:
            prefix = prefix_match.group(1)
        
        # Split into blocks by finding each BGP entry start
        starts = [m.start() for m in entry_pattern.finditer(output)]
        if not starts:
            return paths
        
        blocks = []
        for i, start in enumerate(starts):
            end = starts[i + 1] if i + 1 < len(starts) else len(output)
            blocks.append(output[start:end])
        
        for block in blocks:
            path = JunosRouteParser._parse_block(block, prefix)
            if path:
                paths.append(path)
        
        return paths

    @staticmethod
    def _parse_block(block: str, prefix: str) -> Optional[BGPPath]:
        """Parse a single BGP entry block."""
        lines = block.split('\n')
        
        # Active if line starts with '*BGP'
        active = '*BGP' in lines[0]
        
        path = BGPPath(
            prefix=prefix,
            next_hop="",
            as_path="",
            origin="?",
            active=active,
        )
        
        for line in lines:
            line_stripped = line.strip()
            
            # Source (the peer IP that sent this route)
            m = re.match(r'Source:\s+(\S+)', line_stripped)
            if m:
                path.next_hop = m.group(1)
                path.source_router = m.group(1)
                continue
            
            # State
            m = re.match(r'State:\s+<(.+?)>', line_stripped)
            if m:
                state = m.group(1)
                path.active = 'Active' in state
                if 'NotBest' in state:
                    path.active = False
                continue
            
            # Inactive reason
            m = re.match(r'Inactive reason:\s+(.+)', line_stripped)
            if m:
                path.inactive_reason = m.group(1).strip()
                continue
            
            # Local AS / Peer AS
            m = re.search(r'Local AS:\s+(\d+)\s+Peer AS:\s+(\d+)', line_stripped)
            if m:
                path.local_as = int(m.group(1))
                path.peer_as = int(m.group(2))
                continue
            
            # Age and Metric2 (MED)
            m = re.search(r'Age:\s+(\S+)', line_stripped)
            if m:
                path.age = m.group(1)
            m = re.search(r'Metric2:\s+(\d+)', line_stripped)
            if m:
                path.med = int(m.group(1))
                continue
            
            # Validation State
            m = re.match(r'Validation State:\s+(\S+)', line_stripped)
            if m:
                path.validation_state = m.group(1)
                continue
            
            # AS path — format: "7018 15169 I" where last token is origin
            m = re.match(r'AS path:\s+(.+)', line_stripped)
            if m:
                as_path_raw = m.group(1).strip()
                # Origin is the last token: I (IGP), E (EGP), ? (incomplete)
                parts = as_path_raw.split()
                if parts and parts[-1] in ('I', 'E', '?'):
                    origin_char = parts.pop()
                    path.origin = {'I': 'IGP', 'E': 'EGP', '?': 'Incomplete'}.get(origin_char, origin_char)
                path.as_path = ' '.join(parts)
                continue
            
            # Communities
            m = re.match(r'Communities:\s+(.+)', line_stripped)
            if m:
                path.communities = m.group(1).strip().split()
                continue
            
            # Localpref
            m = re.match(r'Localpref:\s+(\d+)', line_stripped)
            if m:
                path.local_pref = int(m.group(1))
                continue
            
            # Router ID
            m = re.match(r'Router ID:\s+(\S+)', line_stripped)
            if m:
                path.router_id = m.group(1)
                continue
            
            # Task field — extract peer info
            m = re.match(r'Task:\s+BGP_(\d+)\.(.+)', line_stripped)
            if m:
                path.peer_as = int(m.group(1))
                continue
        
        return path if path.next_hop else None


# AT&T community → city mapping (from AT&T NOC documentation)
ATT_CITY_COMMUNITIES = {
    "7018:32101": "New York, NY",
    "7018:33051": "Chicago, IL",
    "7018:34011": "Dallas, TX",
    "7018:36244": "Washington, DC",
    "7018:37232": "Atlanta, GA",
    "7018:38000": "San Francisco, CA",
    "7018:39220": "Los Angeles, CA",
    "7018:39343": "Seattle, WA",
}


def resolve_att_city(communities: list[str]) -> Optional[str]:
    """Resolve AT&T community to city name."""
    for comm in communities:
        if comm in ATT_CITY_COMMUNITIES:
            return ATT_CITY_COMMUNITIES[comm]
    return None


# Known public Junos route servers
JUNOS_ROUTE_SERVERS = {
    "att": {
        "host": "route-server.ip.att.net",
        "username": "rviews",
        "password": "rviews",
        "asn": 7018,
        "description": "AT&T (AS7018) — 16 BGP peers, US cities",
    },
    "tdc": {
        "host": "route-server.ip.tdc.net",
        "username": "rviews",
        "password": "Rviews",
        "asn": 3292,
        "description": "TDC A/S (AS3292) — European Junos RS",
    },
}


class BGPCollector:
    """Collect BGP routing data from public Junos route servers via pexpect."""

    def __init__(self, server: str = "att"):
        config = JUNOS_ROUTE_SERVERS.get(server, JUNOS_ROUTE_SERVERS["att"])
        self.host = config["host"]
        self.username = config["username"]
        self.password = config["password"]
        self.server_name = server

    async def lookup_prefix(self, prefix: str) -> list[BGPPath]:
        """Query a Junos route server for all paths to a prefix."""
        import pexpect

        prompt = r'rviews@[^\s]+>'

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

            # Query the prefix
            child.sendline(f'show route {prefix} detail | no-more')
            child.expect(prompt, timeout=180)

            output = child.before

            child.sendline('exit')
            child.close()

            paths = JunosRouteParser.parse(output, prefix)
            logger.info(f"[{self.server_name}] {prefix}: {len(paths)} paths")
            return paths

        except Exception as e:
            logger.error(f"[{self.server_name}] query failed: {e}")
            raise
