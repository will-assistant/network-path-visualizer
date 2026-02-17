# Path Walker V3 Enhanced (Phase 3)

## Capabilities

- Generic hop-by-hop path walking from cached/live route lookups
- ECMP branch tree generation with per-hop cap (`max_ecmp_branches`, default `8`)
- MPLS label operations attached to hops (`push`, `swap`, `pop`)
- Domain crossing events at firewall boundaries
- Reverse trace and asymmetry comparison (forward vs reverse)
- Failure simulation via temporary node exclusion
- Prefix origin detection (`connected`, `static`, `ebgp`)

## Data Structures

- `ECMPBranch(parent_hop, branch_index, next_hops, selected_paths)`
- `LabelOp(action, label, lsp_name)`
- `DomainCrossing(firewall, from_domain, to_domain, route_type)`
- `AsymmetryResult(forward_path, reverse_path, symmetric, divergence_points)`
- `FailureSimResult(original, failover, failed_node, impact_summary)`

## API Additions

- `POST /api/trace/reverse`
- `POST /api/trace/compare`
- `POST /api/simulate/failure`
- `GET /api/origin/{prefix}?start_device=<hostname>`

## Notes

- Walker remains read-only (no device config/state mutations)
- Works with cached collector data first, falls back to live collector
- Existing `POST /api/trace` remains backward compatible and includes new fields
