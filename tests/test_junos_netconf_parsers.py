import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from parsers.junos_netconf import parse_bgp_rib, parse_mpls_lsp, parse_isis_lsdb


FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text()


def test_parse_bgp_rib():
    routes = parse_bgp_rib(_load("junos-bgp.xml"))
    assert len(routes) == 1
    r = routes[0]
    assert r.prefix == "8.8.8.0/24"
    assert r.next_hop == "10.0.0.2"
    assert r.as_path == ["7018", "15169"]
    assert r.local_pref == 200


def test_parse_mpls_lsp():
    lsps = parse_mpls_lsp(_load("junos-mpls.xml"))
    assert len(lsps) == 1
    assert lsps[0].name == "LSP-TO-PE2"
    assert lsps[0].state.lower() == "up"
    assert len(lsps[0].path) == 2


def test_parse_isis_lsdb():
    entries = parse_isis_lsdb(_load("junos-isis.xml"))
    assert len(entries) == 1
    assert entries[0].system_id == "0000"
    assert entries[0].neighbors[0]["metric"] == 10
    assert "10.100.0.0/16" in entries[0].ip_reachability
