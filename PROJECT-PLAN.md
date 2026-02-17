# Network Path Visualizer — Project Plan

**PM:** Will | **Builder:** Forge | **Owner:** Jeremy

## Vision
Input a source IP/prefix → find where it originates. Input source + destination → see all primary and backup forwarding paths. Traces the actual forwarding plane across routing domains, not just control plane tables.

## Architecture
```
Frontend (vis.js + FastAPI static) 
    ↕ REST API
Backend (FastAPI + NetworkX + PathWalker)
    ↕ reads cached JSON
Ansible Collection Layer (NETCONF + API)
    ↕ talks to routers
Network Devices (Juniper, Cisco, Palo/Panorama, Fortinet)
```

## Target Network Model
- **PE routers** → customer-facing, BGP + MPLS
- **Firewalls** → domain boundaries, static/policy routes (Palo Alto via Panorama)
- **AGG/Backbone** → MPLS core, ISIS/OSPF
- **Internet Edge** → eBGP peering
- Flow: PE → FW → AGG backbone → FW → Edge → Internet
- East-west: PE → FW → AGG → FW → PE
- Route reflectors have everything but are noisy (1 prefix in 30 tables)

## Inventory File
Central YAML inventory controls:
- What routers exist and their roles (PE, AGG, FW, Edge, RR)
- Which routing domain each belongs to
- Domain boundaries (which FW connects which domains)
- Credentials / connection method per vendor
- **This is the source of truth for the tool**

## Vendor Access
| Vendor | Protocol | Status |
|--------|----------|--------|
| Juniper | NETCONF (ncclient/PyEZ) + CLI | **Phase 1 — build now** |
| Cisco IOS-XR | NETCONF | Later — Jeremy will provide access |
| Palo Alto | Panorama API (XML/REST) | Later — Jeremy will provide access |
| Fortinet | FortiOS REST API | Later — Jeremy will provide access |

**⚠️ Juniper first. Other vendors only after Jeremy provides examples and access.**

## Testing Strategy
1. **Public Junos route servers** — AT&T RS + others. Real Junos, real BGP data. Build and test all parsing here.
2. **Mock internal topology** — Juniper-only for now. Prove path walking + domain crossing.
3. **Real devices** — when Jeremy provides access/creds later.

## Build Phases

### Phase 1: Parser + Display (Forge builds, Will reviews)
- [ ] Fix AT&T RS telnet session handling (paging, output truncation)
- [ ] Parse Junos `show route <prefix> detail` — extract all paths: AS-path, next-hop, communities, local-pref, origin, source router
- [ ] Parse Junos `show route <prefix>` terse format as fallback
- [ ] Build mock inventory YAML matching Jeremy's architecture (PE→FW→AGG→FW→Edge)
- [ ] Load inventory into GraphEngine, render topology in vis.js frontend
- [ ] Wire up `/api/trace` endpoint: query AT&T RS → parse → return structured PathResult
- [ ] Frontend: type prefix → see paths rendered on topology + sidebar hop list
- [ ] **Milestone: Type 8.8.8.0/24, see 16 AT&T paths with AS-paths and next-hops**

### Phase 2: Ansible Collection
- [x] Junos NETCONF playbook: pull BGP RIB (`get-route-information`)
- [x] Junos NETCONF playbook: pull MPLS LSPs (`get-mpls-lsp-information`)
- [x] Junos NETCONF playbook: pull ISIS LSDB (`get-isis-database-information`)
- [x] Cisco XR NETCONF playbook: pull BGP RIB + MPLS TE + ISIS topology
- [x] Panorama API playbook: pull managed firewall static routes + policy routes
- [x] Fortinet REST playbook: pull static routes
- [x] Collection output: structured JSON per device, saved to `data/collected/`
- [x] Collection runner: on-demand via API + scheduled via cron
- [x] **Milestone: Run `ansible-playbook collect-all.yml`, get JSON from all device types**

### Phase 3: Path Walker
- [ ] FIB query: read cached Ansible JSON, resolve prefix → next-hop per router
- [ ] Domain boundary crossing: detect firewall hop, switch to static route lookup
- [ ] Walk one complete path: PE → FW → AGG → FW → Edge (single domain chain)
- [ ] ECMP branching: when FIB shows multiple next-hops, fork into parallel paths
- [ ] MPLS label tracking: record push/swap/pop at each hop from LSP data
- [ ] Reverse path trace: walk destination → source, compare for asymmetry
- [ ] Failure simulation: remove a node from graph, re-walk, show reroute
- [ ] **Milestone: Input src + dst, see full multi-domain path with labels and ECMP branches**

### Phase 4: Production Polish
- [ ] Historical path storage (SQLite — when did paths change?)
- [ ] Link utilization overlay (color-coded by load)
- [ ] Inventory auto-discovery from ISIS/OSPF LSDB
- [ ] Panorama integration for firewall rule context (not just static routes)
- [ ] NAT tracking through firewalls (original + translated)
- [ ] Blast radius calculator (fail node → list affected prefixes/customers)
- [ ] ECMP hash prediction (5-tuple → which specific path)
- [ ] Export: PDF/HTML report of any trace
- [ ] **Milestone: Production-ready tool Jeremy can use daily**

## Code Standards
- Python 3.11+, type hints everywhere
- Pydantic v2 for all data models
- Tests for every parser (AT&T output, Junos NETCONF XML, Panorama XML)
- Ansible playbooks must be idempotent and read-only (no config changes ever)
- All collected data cached locally as JSON — never query routers in the hot path
- Frontend: vanilla JS + vis.js, no build step, no npm

## Repo
- GitHub: `will-assistant/network-path-visualizer`
- Branch strategy: `main` for stable, feature branches for new phases
- Forge commits directly, Will reviews PRs or commits

## Review Cadence
- Will checks progress at least weekly
- Phase milestones trigger a demo/review
- Jeremy gets pinged on major milestones
