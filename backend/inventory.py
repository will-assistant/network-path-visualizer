"""Inventory V3 — IP resolution plus optional domain/MPLS metadata."""

from __future__ import annotations

import yaml
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional



@dataclass
class LabelOp:
    action: str
    label: int
    lsp_name: Optional[str] = None


@dataclass
class DomainCrossing:
    firewall: str
    from_domain: str
    to_domain: str
    route_type: str



@dataclass
class DeviceInfo:
    hostname: str
    management_ip: str = ""
    vendor: str = "unknown"
    connection: str = "ssh"
    credentials: dict = field(default_factory=dict)
    role: str = ""
    site: str = ""
    domain: str = ""
    loopbacks: list[str] = field(default_factory=list)
    interfaces: dict[str, str] = field(default_factory=dict)
    mpls: dict[str, list[dict]] = field(default_factory=dict)  # next-hop ip -> label ops


@dataclass
class BoundaryInfo:
    firewall: str
    upstream_domain: str
    downstream_domain: str


class Inventory:
    def __init__(self):
        self.devices: dict[str, DeviceInfo] = {}
        self.boundaries: list[BoundaryInfo] = []
        self._ip_index: dict[str, str] = {}

    def _rebuild_index(self):
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
        return self._ip_index.get(ip)

    def get_device(self, hostname: str) -> Optional[DeviceInfo]:
        return self.devices.get(hostname)

    def list_devices(self) -> list[str]:
        return list(self.devices.keys())

    def is_firewall(self, hostname: str) -> bool:
        d = self.get_device(hostname)
        if not d:
            return False
        role = (d.role or "").lower()
        return "fw" in role or "firewall" in role

    def get_mpls_label_ops(self, hostname: str, next_hop: str) -> list[LabelOp]:
        d = self.get_device(hostname)
        if not d:
            return []
        ops = d.mpls.get(next_hop, [])
        out: list[LabelOp] = []
        for op in ops:
            try:
                out.append(LabelOp(action=op["action"], label=int(op["label"]), lsp_name=op.get("lsp_name")))
            except Exception:
                continue
        return out

    def get_domain_crossing(self, firewall: str, next_hop: str) -> Optional[DomainCrossing]:
        if not self.is_firewall(firewall):
            return None
        current = self.get_device(firewall)
        next_dev = self.get_device(self.resolve_ip(next_hop) or "")
        if not current or not next_dev:
            return None
        for b in self.boundaries:
            if b.firewall != firewall:
                continue
            if current.domain == b.upstream_domain and next_dev.domain == b.downstream_domain:
                return DomainCrossing(firewall=firewall, from_domain=b.upstream_domain, to_domain=b.downstream_domain, route_type="static")
            if current.domain == b.downstream_domain and next_dev.domain == b.upstream_domain:
                return DomainCrossing(firewall=firewall, from_domain=b.downstream_domain, to_domain=b.upstream_domain, route_type="static")
        if current.domain and next_dev.domain and current.domain != next_dev.domain:
            return DomainCrossing(firewall=firewall, from_domain=current.domain, to_domain=next_dev.domain, route_type="static")
        return None

    @classmethod
    def from_yaml(cls, path: str | Path) -> "Inventory":
        path = Path(path)
        with open(path) as f:
            raw = yaml.safe_load(f)

        inv = cls()
        if not raw:
            return inv

        device_block = raw.get("devices", {})
        for hostname, data in device_block.items():
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
                domain=data.get("domain", ""),
                loopbacks=data.get("loopbacks", []) or [],
                interfaces=data.get("interfaces", {}) or {},
                mpls=data.get("mpls", {}) or {},
            )
            inv.devices[hostname] = dev

        for b in raw.get("boundaries", []) or []:
            if not isinstance(b, dict):
                continue
            fw = b.get("firewall")
            up = b.get("upstream_domain")
            down = b.get("downstream_domain")
            if fw and up and down:
                inv.boundaries.append(BoundaryInfo(firewall=fw, upstream_domain=up, downstream_domain=down))

        inv._rebuild_index()
        return inv
