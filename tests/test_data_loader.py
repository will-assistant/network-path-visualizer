import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from data_loader import CollectedDataLoader


def test_data_loader_lookup_and_stale_warning(tmp_path: Path):
    host_dir = tmp_path / "router1"
    host_dir.mkdir(parents=True)

    payload = {
        "collected_at": "2020-01-01T00:00:00Z",
        "routes": [
            {
                "prefix": "8.8.8.0/24",
                "next_hop": "10.0.0.2",
                "as_path": ["7018", "15169"],
                "communities": ["7018:2500"],
                "local_pref": 100,
                "origin": "igp",
                "source_router": "router1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        ],
    }
    (host_dir / "bgp-rib.json").write_text(json.dumps(payload))

    loader = CollectedDataLoader(tmp_path)
    routes = loader.lookup_routes("router1", "8.8.8.0/24")
    assert len(routes) == 1
    assert routes[0].next_hop == "10.0.0.2"
    assert loader.stale_warnings()
