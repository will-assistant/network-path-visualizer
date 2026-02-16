"""
BGP Collector — Query BGP tables via NETCONF, SSH, or public route servers.

For development/testing: Uses AT&T's public route server (route-server.ip.att.net)
via telnet to validate BGP path logic against real Internet routing data.

For production: Uses Ansible + NETCONF to pull BGP RIB from internal routers.
"""

import subprocess
import json
import re
from typing import Optional
from dataclasses import dataclass


@dataclass
class BGPPath:
    prefix: str
    next_hop: str
    as_path: str
    origin: str          # 'i' (IGP), 'e' (EGP), '?' (incomplete)
    local_pref: Optional[int] = None
    med: Optional[int] = None
    communities: Optional[list[str]] = None
    best: bool = False
    source_router: Optional[str] = None


class BGPCollector:
    """Collect BGP routing data from various sources."""
    
    # Public route servers for testing
    PUBLIC_ROUTE_SERVERS = {
        "att": {
            "host": "route-server.ip.att.net",
            "type": "telnet",
            "vendor": "cisco_ios",
            "description": "AT&T public looking glass"
        },
        "he": {
            "host": "route-server.he.net",
            "type": "telnet",
            "vendor": "cisco_ios",
            "description": "Hurricane Electric looking glass"
        },
        "ripe": {
            "host": "rrc00.ripe.net",
            "type": "telnet",
            "vendor": "quagga",
            "description": "RIPE RIS route collector"
        }
    }
    
    def __init__(self, source: str = "att"):
        self.source = source
        self.rs_config = self.PUBLIC_ROUTE_SERVERS.get(source)
    
    async def lookup_prefix(self, prefix: str) -> list[BGPPath]:
        """
        Look up all BGP paths for a prefix.
        
        Against public route servers: telnet + CLI parsing
        Against internal routers: NETCONF structured data
        """
        if self.rs_config and self.rs_config["type"] == "telnet":
            return await self._telnet_lookup(prefix)
        else:
            return await self._netconf_lookup(prefix)
    
    async def _telnet_lookup(self, prefix: str) -> list[BGPPath]:
        """
        Query a public route server via telnet.
        
        Example session with AT&T:
        $ telnet route-server.ip.att.net
        > show ip bgp 8.8.8.0/24
        
        Returns all paths with AS-path, next-hop, origin, etc.
        """
        host = self.rs_config["host"]
        
        # Use expect-style interaction via subprocess
        # For now, use a simple netcat approach
        cmd = f"""
        (echo "show ip bgp {prefix}"; sleep 3; echo "exit") | \
        timeout 10 telnet {host} 2>/dev/null
        """
        
        try:
            result = subprocess.run(
                ["bash", "-c", cmd],
                capture_output=True,
                text=True,
                timeout=15
            )
            return self._parse_cisco_bgp_output(result.stdout, prefix)
        except subprocess.TimeoutExpired:
            return []
    
    async def _netconf_lookup(self, prefix: str) -> list[BGPPath]:
        """
        Query internal router via NETCONF.
        Uses ncclient for Juniper/Cisco.
        
        Juniper RPC: <get-route-information>
        Cisco XR YANG: openconfig-bgp-rib
        """
        # TODO: Implement NETCONF collection
        # This will be populated by Ansible playbook results
        pass
    
    def _parse_cisco_bgp_output(self, output: str, prefix: str) -> list[BGPPath]:
        """
        Parse Cisco 'show ip bgp <prefix>' output.
        
        Example output:
        BGP routing table entry for 8.8.8.0/24
           Paths: (23 available, best #1)
           15169
             12.122.28.45 from 12.122.28.45 (12.122.28.45)
               Origin IGP, metric 0, localpref 100, valid, external, best
               Community: 7018:5000 7018:37232
        """
        paths = []
        lines = output.split('\n')
        
        current_path = None
        in_paths = False
        
        for line in lines:
            line = line.strip()
            
            # Detect path blocks
            if 'Paths:' in line:
                in_paths = True
                continue
            
            if not in_paths:
                continue
            
            # AS path line (just numbers)
            as_match = re.match(r'^[\d\s]+$', line)
            if as_match and line.strip():
                if current_path:
                    paths.append(current_path)
                current_path = BGPPath(
                    prefix=prefix,
                    next_hop="",
                    as_path=line.strip(),
                    origin="?"
                )
                continue
            
            # Next-hop line
            nh_match = re.match(r'^\s*([\d.]+)\s+from', line)
            if nh_match and current_path:
                current_path.next_hop = nh_match.group(1)
                continue
            
            # Origin/attributes line
            if current_path and 'Origin' in line:
                if 'IGP' in line:
                    current_path.origin = 'i'
                elif 'EGP' in line:
                    current_path.origin = 'e'
                else:
                    current_path.origin = '?'
                
                if 'best' in line:
                    current_path.best = True
                
                lp_match = re.search(r'localpref\s+(\d+)', line)
                if lp_match:
                    current_path.local_pref = int(lp_match.group(1))
                
                med_match = re.search(r'metric\s+(\d+)', line)
                if med_match:
                    current_path.med = int(med_match.group(1))
            
            # Community line
            if current_path and 'Community:' in line:
                comms = line.replace('Community:', '').strip().split()
                current_path.communities = comms
        
        if current_path:
            paths.append(current_path)
        
        return paths


class AnsibleBGPCollector:
    """
    Collect BGP data via Ansible playbooks.
    
    Runs playbooks that NETCONF/SSH into routers,
    pulls structured BGP data, saves as JSON.
    """
    
    def __init__(self, inventory_path: str, playbook_dir: str):
        self.inventory_path = inventory_path
        self.playbook_dir = playbook_dir
    
    async def collect_all(self) -> dict:
        """Run the full collection playbook."""
        cmd = [
            "ansible-playbook",
            f"{self.playbook_dir}/collect-bgp.yml",
            "-i", self.inventory_path,
            "--extra-vars", "output_format=json"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        # TODO: Parse Ansible output, load collected JSON
        return {}
    
    async def collect_prefix(self, router: str, prefix: str) -> list[BGPPath]:
        """On-demand collection for a specific prefix from a specific router."""
        cmd = [
            "ansible-playbook",
            f"{self.playbook_dir}/collect-prefix.yml",
            "-i", self.inventory_path,
            "--limit", router,
            "--extra-vars", json.dumps({"target_prefix": prefix})
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        # TODO: Parse collected data
        return []
