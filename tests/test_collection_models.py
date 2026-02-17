import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from models import BGPRoute, MPLSLsp, ISISEntry


def test_bgp_route_model_validation():
    route = BGPRoute(
        prefix="8.8.8.0/24",
        next_hop="10.0.0.2",
        as_path=["7018", "15169"],
        communities=["7018:2500"],
        local_pref=100,
        origin="igp",
        source_router="router1",
        timestamp=datetime.now(timezone.utc),
    )
    assert route.prefix == "8.8.8.0/24"


def test_mpls_lsp_model_validation():
    lsp = MPLSLsp(name="LSP1", from_router="r1", to_router="r2", path=["p1"], labels=["100"], state="Up")
    assert lsp.state == "Up"


def test_isis_entry_model_validation():
    isis = ISISEntry(system_id="0000.0000.0001", hostname="r1", neighbors=[{"system_id": "r2", "metric": 10}], ip_reachability=["10.0.0.0/24"])
    assert isis.neighbors[0]["metric"] == 10
