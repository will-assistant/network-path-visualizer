# Network Path Visualizer (NPV)

**A multi-domain network path analyzer that traces actual forwarding paths across routing domains, firewalls, and MPLS backbones.**

Unlike traditional tools that show a single router's view or only read control-plane tables, NPV **walks the forwarding path** hop-by-hop across domain boundaries — including firewalls with static routes — to show you where traffic actually goes.

## What It Does

- **Subnet → Origin**: Input a prefix, find where it's actually originated (not just where the RR thinks it lives)
- **Source → Destination**: Input source and dest IPs, see all primary and backup forwarding paths
- **Multi-domain aware**: Traces through PE zones → firewalls → MPLS backbone → firewalls → internet edge
- **ECMP/multipath**: Shows all equal-cost paths, not just "the best one"
- **Failure simulation**: "What if this node dies?" → shows reroute paths and capacity impact

## Architecture

```
┌─────────────────────────────────────┐
│           Web Frontend              │
│  (Search bar → topology + path viz) │
└──────────────┬──────────────────────┘
               │ REST API
┌──────────────┴──────────────────────┐
│         FastAPI Backend             │
│  - Path walker engine               │
│  - Domain/boundary model            │
│  - Graph builder (NetworkX)         │
└──────────────┬──────────────────────┘
               │
┌──────────────┴──────────────────────┐
│     Ansible + NETCONF Collectors    │
│  - Per-vendor playbooks             │
│  - Structured data extraction       │
│  - Scheduled + on-demand collection │
└─────────────────────────────────────┘
```

## Supported Vendors

| Vendor | Protocol | Data |
|--------|----------|------|
| Juniper (Junos) | NETCONF | BGP RIB, MPLS LSP, ISIS LSDB, FIB |
| Cisco (IOS-XR) | NETCONF / SSH | BGP RIB, MPLS TE, OSPF/ISIS, FIB |
| Palo Alto | PAN-OS XML API | Static routes, policy routes, NAT |
| Fortinet | FortiOS REST API | Static routes, policy routes |

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Configure inventory
cp ansible/inventories/example.yml ansible/inventories/production.yml
# Edit with your router details

# Collect data
ansible-playbook ansible/playbooks/collect-all.yml -i ansible/inventories/production.yml

# Start the backend
cd backend && uvicorn main:app --reload

# Open frontend
open http://localhost:8000
```

## Development

Testing against AT&T public route server (route-server.ip.att.net) for BGP path validation.

## License

MIT
