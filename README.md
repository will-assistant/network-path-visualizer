# Network Path Visualizer (NPV) — V3

**Generic next-hop follower — give it a prefix and a starting router, and it walks the routing table hop by hop.**

NPV traces actual forwarding paths across your network. No hardcoded architecture, no tier model — it just follows next-hops like a packet would.

## What It Does

- **Prefix → Origin**: Input a prefix + starting device, see the full path to where it's originated
- **ECMP aware**: Branches on equal-cost multi-path, shows all forwarding paths
- **Plugin system**: Optional community decoders add human-readable labels (e.g., "customer route", "primary path")
- **Multi-vendor**: Junos today, extensible to IOS-XR, PAN-OS, FortiOS
- **Web UI**: Dark-mode frontend with hop-by-hop visualization

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure inventory (add your devices)
cp inventories/example-generic.yml inventories/my-network.yml
vim inventories/my-network.yml

# Start the API + frontend
cd backend && uvicorn main:app --host 0.0.0.0 --port 8080

# Open http://localhost:8080 — pick a device, enter a prefix, hit Trace
```

## Live Test (Public Route Servers)

```bash
# Test against AT&T's public route server — no credentials needed beyond rviews/rviews
python3 scripts/live_test.py 8.8.8.0/24
```

Example output:

```
Parsed 16 RouteEntry objects:

  [1] ★ ACTIVE
      Prefix:    8.8.8.0/24
      Next-hop:  12.122.83.238
      AS Path:   7018 15169
      LP:        100
      Communities: 7018:2500 7018:36244
      Peer AS:   7018

  [2]   inactive
      Next-hop:  12.122.120.7
      AS Path:   7018 15169
      Reason:    Not Best in its group - Router ID
  ...

Summary: 16 entries, 1 active
✓ All validations passed!
```

## Inventory Format

Inventory is a YAML file that maps device hostnames to connection info and IP addresses. The key job: **resolve a next-hop IP back to a device hostname** so the walker knows where to query next.

```yaml
devices:
  my-router:
    management_ip: 10.0.0.1          # IP or hostname to connect to
    vendor: juniper                   # juniper (more coming)
    connection: telnet                # telnet | ssh | netconf
    credentials:
      username: admin
      password: secret               # or vault:my-router for external lookup
    role: core                        # freeform label
    site: dc1                         # freeform label
    loopbacks:                        # IPs that identify this device as a next-hop
      - 192.168.255.1
    interfaces:                       # interface-name → IP mapping
      et-0/0/0: 10.1.1.1
      et-0/0/1: 10.1.2.1
```

The `loopbacks` and `interfaces` fields are used for next-hop resolution. When the walker sees next-hop `10.1.1.1`, it looks up which device owns that IP and queries it next.

See `inventories/example-generic.yml` for a working example with public route servers.

## How Plugins Work

Plugins are optional enrichment — they decode BGP communities into human-readable labels without affecting the core trace logic.

```python
from plugins import CommunityDecoderPlugin

class MyDecoder(CommunityDecoderPlugin):
    def name(self) -> str:
        return "my-network"

    def decode(self, communities: list[str], local_pref: int | None = None) -> dict:
        labels = {}
        if "65000:100" in communities:
            labels["type"] = "customer"
        if local_pref and local_pref >= 200:
            labels["preference"] = "primary"
        return labels
```

Drop your plugin in `backend/plugins/`, import it in `main.py`, and labels appear on each hop in the UI.

## Architecture

```
frontend/index.html          Single-page dark-mode UI
        │
        ▼  POST /api/trace, GET /api/devices
backend/main.py              FastAPI app
backend/path_walker.py       Generic next-hop follower (the core)
backend/inventory.py         YAML inventory + IP resolution
backend/collectors/          Vendor-specific route collectors
  junos_collector.py         Telnet/pexpect → Junos parser
  (iosxr, panos, fortios)    Stubs for future vendors
backend/plugins/             Community decoder plugins
```

## API

**POST /api/trace** — Trace a prefix from a starting device
```json
{"prefix": "8.8.8.0/24", "start_device": "att-rs", "vrf": null}
```

**POST /api/collect** — Trigger background collection
```json
{"hosts": ["pe-nyc-1"], "types": ["bgp", "mpls", "isis"]}
```

**GET /api/collect/{job_id}** — Get collection status

**GET /api/collected** — List cached files + stale data warnings

**GET /api/devices** — List all inventory devices (for frontend dropdown)

**GET /api/health** — Health check + device count

## Collection Layer (Phase 2)

Junos collection playbooks are in `ansible/playbooks/` and use NETCONF RPCs only (read-only):

- `collect-junos-bgp.yml` → `data/collected/<host>/bgp-rib.json`
- `collect-junos-mpls.yml` → `data/collected/<host>/mpls-lsp.json`
- `collect-junos-isis.yml` → `data/collected/<host>/isis-lsdb.json`
- `collect-all.yml` orchestrates all with tags (`bgp`, `mpls`, `isis`)

See `docs/COLLECTION.md` for full architecture.

## Development

```bash
# Run tests
python3 -m pytest tests/ -v

# 82 tests covering: parser, inventory, path walker, ECMP, plugins, integration
```

## License

MIT
