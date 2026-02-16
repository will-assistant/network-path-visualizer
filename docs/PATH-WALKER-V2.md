# Path Walker V2 — AGG-First Design
*Based on how Jeremy actually troubleshoots*

## Core Insight
Don't walk hop-by-hop from source. Start at the AGG — it's the index. Communities on the AGG route tell you the entire path before you touch any other device.

## Algorithm

### Step 1: Query AGG (the index)
```
Input: prefix (source or destination)
Target: wcr01 (RR) at any site — it has all routes

show route table <vrf>.inet.0 <prefix> detail
```

**What you get back:**
- `next-hop` → points toward the DCPE/SPE direction
- `communities` → OID:AID compound tells you origin site + advertising site
- `localpref` → 200=primary, 150=secondary, 50=tertiary
- `as-path` → confirms which ASN originated it
- `protocol` → BGP, static, connected — tells you if it's local

**What you now KNOW without querying anything else:**
- Which site originated the prefix (OID)
- Which site is advertising it to you (AID)
- Whether this is the primary, secondary, or tertiary path
- ALL alternative paths (ECMP or backup) from the same query

### Step 2: Decode communities → map the path
```python
oid = extract_oid(communities)   # origin site
aid = extract_aid(communities)   # advertising site  
lp = route.localpref             # path preference

site = oid_to_site(oid)          # "site 1 = Little Rock"
dcpe = site_to_dcpe(site)        # "wed03/wed04"
spe = site_to_spe(site)          # "wex03/wex04"
fw = derive_fw_from_nexthop(nh)  # 100.120.x.x pattern → T2 identity
```

At this point you have the full path: DCPE → SPE → T2 FW → AGG → (T1 FW → IPE if internet-bound)

### Step 3: Validate endpoints (optional, confirms reality)
- Query the DCPE: does it actually have this prefix in the VRF?
- Query the IPE: does it have the internet route? (if destination is external)
- Query the SPE: confirm next-hop alignment

This step catches stale routes, blackholes, or misconfigurations.

### Step 4: Build the visualization
```
Path object = ordered list of:
  { device, role, domain, vrf, next_hop, communities, localpref, interface }

Multiple paths (primary + backup) shown as parallel tracks
Community-decoded labels explain WHY each path exists
```

## What This Replaces
V1 walked hop-by-hop: DCPE → SPE → FW → AGG → FW → IPE
- Required querying every device in sequence
- Slow — 6+ sequential NETCONF calls
- Fragile — one unreachable device breaks the whole trace

V2 queries AGG first:
- 1 query gives you 80% of the answer
- Parallel validation queries for confirmation
- Community decode does the pathfinding, not recursive lookups

## Data the AGG Gives You (per route)
| Field | What it tells NPV |
|-------|-------------------|
| communities (OID) | Origin site — where prefix was born |
| communities (AID) | Advertising site — who's telling you about it |
| localpref | Path preference (200/150/50) |
| next-hop | Direction — toward which SPE/FW |
| as-path | Originating ASN — backbone vs carrier vs internet |
| protocol | BGP/static/connected — is this a real route or override? |
| metric | IGP cost — tiebreaker for ECMP |
| route-target | Which VRF/COI this belongs to |

## Firewall Boundary Detection
T2 FW identity derived from next-hop addressing:
- `100.120.{vrf_id}.x/29` → Americas T2
- `100.123.{vrf_id}.x/29` → EMEA T2
- `100.124.{vrf_id}.x/29` → APAC T2
- `100.127.{vrf_id}.x/29` → EMEA GMN

No need to query the firewall to find it — the address pattern IS the identifier.

## When You DO Need the Firewall
- Policy verification: "is this flow actually permitted?"
- NAT detection: "does the source IP change at this boundary?"
- These are Phase 3+ features — via Panorama API

## Edge Cases
1. **Route not on AGG** → prefix is local to a single DCPE, never advertised to backbone
2. **Multiple equal paths** → ECMP — show all paths, highlight active
3. **Carrier VRF routes** → WEE routers, different path (I03006 → I00110 translation)
4. **Cross-region** → OID from EMEA, AID from Americas — path crosses ocean
5. **Legacy VRF** → IDCIN-era routes may not have OID/AID communities

## Implementation Priority
1. AGG query + community decode (this IS the feature)
2. Site/device mapping from inventory
3. Visualization with path preference labels
4. Endpoint validation (parallel, optional)
5. Firewall policy lookup via Panorama (Phase 3)
