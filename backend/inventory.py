"""
Inventory V3 — Simple IP-to-device resolution.

Loads a YAML inventory file. The only real job: resolve an IP address
to a device hostname by scanning management IPs, loopbacks, and interfaces.
"""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class DeviceInfo:
    """A device in the inventory."""
    hostname: str
    management_ip: str = ""
    vendor: str = "unknown"
    connection: str = "ssh"
    credentials: dict = field(default_factory=dict)
    role: str = ""
    site: str = ""
    loopbacks: list[str] = field(default_factory=list)
    interfaces: dict[str, str] = field(default_factory=dict)  # name → ip


class Inventory:
    """Device inventory with IP resolution."""

    def __init__(self):
        self.devices: dict[str, DeviceInfo] = {}
        # Pre-built IP → hostname index
        self._ip_index: dict[str, str] = {}

    def _rebuild_index(self):
        """Rebuild the IP → hostname lookup index."""
        self._ip_index.clear()
        for hostname, dev in self.devices.items():
            if dev.management_ip:
                self._ip_index[dev.management_ip] = hostname
            for lb in dev.loopbacks:
                self._ip_index[lb] = hostname
            for iface_ip in dev.interfaces.values():
                if iface_ip:
                    self._ip_index[iface_ip] = hostname

    def resolve_ip(self, ip: str) -> Optional[str]:
        """Resolve an IP address to a device hostname. Returns None if unknown."""
        return self._ip_index.get(ip)

    def get_device(self, hostname: str) -> Optional[DeviceInfo]:
        """Get device info by hostname."""
        return self.devices.get(hostname)

    def list_devices(self) -> list[str]:
        """Return all device hostnames."""
        return list(self.devices.keys())

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Inventory":
        """Load inventory from a YAML file."""
        path = Path(path)
        with open(path) as f:
            raw = yaml.safe_load(f)

        inv = cls()

        if not raw or "devices" not in raw:
            return inv

        for hostname, data in raw["devices"].items():
            if not isinstance(data, dict):
                continue
            dev = DeviceInfo(
                hostname=hostname,
                management_ip=str(data.get("management_ip", "")),
                vendor=data.get("vendor", "unknown"),
                connection=data.get("connection", "ssh"),
                credentials=data.get("credentials", {}),
                role=data.get("role", ""),
                site=data.get("site", ""),
                loopbacks=data.get("loopbacks", []) or [],
                interfaces=data.get("interfaces", {}) or {},
            )
            inv.devices[hostname] = dev

        inv._rebuild_index()
        return inv
