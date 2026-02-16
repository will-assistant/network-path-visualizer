"""Tests for V3 Inventory — IP resolution."""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from inventory import Inventory, DeviceInfo


SAMPLE_YAML = """
devices:
  router-a:
    management_ip: 10.0.0.1
    vendor: juniper
    connection: ssh
    role: core
    loopbacks:
      - 192.168.255.1
      - 192.168.255.2
    interfaces:
      et-0/0/0: 10.1.1.1
      et-0/0/1: 10.1.2.1

  router-b:
    management_ip: 10.0.0.2
    vendor: juniper
    connection: netconf
    role: edge
    loopbacks:
      - 192.168.255.3
    interfaces:
      ge-0/0/0: 10.1.1.2
      ge-0/0/1: 10.2.1.1

  firewall-1:
    management_ip: 10.0.0.3
    vendor: paloalto
    connection: api
    role: firewall
    loopbacks: []
    interfaces:
      eth1: 10.1.2.2
"""


def _load_sample() -> Inventory:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
        f.write(SAMPLE_YAML)
        f.flush()
        return Inventory.from_yaml(f.name)


class TestInventoryLoad:
    def test_loads_all_devices(self):
        inv = _load_sample()
        assert len(inv.devices) == 3

    def test_device_attributes(self):
        inv = _load_sample()
        dev = inv.get_device("router-a")
        assert dev is not None
        assert dev.vendor == "juniper"
        assert dev.role == "core"
        assert dev.management_ip == "10.0.0.1"
        assert len(dev.loopbacks) == 2
        assert len(dev.interfaces) == 2

    def test_list_devices(self):
        inv = _load_sample()
        names = inv.list_devices()
        assert "router-a" in names
        assert "router-b" in names
        assert "firewall-1" in names


class TestIPResolution:
    def test_resolve_management_ip(self):
        inv = _load_sample()
        assert inv.resolve_ip("10.0.0.1") == "router-a"
        assert inv.resolve_ip("10.0.0.2") == "router-b"
        assert inv.resolve_ip("10.0.0.3") == "firewall-1"

    def test_resolve_loopback(self):
        inv = _load_sample()
        assert inv.resolve_ip("192.168.255.1") == "router-a"
        assert inv.resolve_ip("192.168.255.2") == "router-a"
        assert inv.resolve_ip("192.168.255.3") == "router-b"

    def test_resolve_interface_ip(self):
        inv = _load_sample()
        assert inv.resolve_ip("10.1.1.1") == "router-a"
        assert inv.resolve_ip("10.1.1.2") == "router-b"
        assert inv.resolve_ip("10.1.2.1") == "router-a"
        assert inv.resolve_ip("10.1.2.2") == "firewall-1"

    def test_resolve_unknown_returns_none(self):
        inv = _load_sample()
        assert inv.resolve_ip("99.99.99.99") is None
        assert inv.resolve_ip("") is None

    def test_resolve_all_ips_covered(self):
        """Every IP in inventory should resolve to something."""
        inv = _load_sample()
        all_ips = []
        for dev in inv.devices.values():
            if dev.management_ip:
                all_ips.append((dev.management_ip, dev.hostname))
            for lb in dev.loopbacks:
                all_ips.append((lb, dev.hostname))
            for ip in dev.interfaces.values():
                all_ips.append((ip, dev.hostname))

        for ip, expected in all_ips:
            assert inv.resolve_ip(ip) == expected, f"{ip} should resolve to {expected}"


class TestEmptyInventory:
    def test_empty_yaml(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("---\n")
            f.flush()
            inv = Inventory.from_yaml(f.name)
        assert len(inv.devices) == 0
        assert inv.resolve_ip("1.2.3.4") is None

    def test_no_devices_key(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write("something_else: true\n")
            f.flush()
            inv = Inventory.from_yaml(f.name)
        assert len(inv.devices) == 0
