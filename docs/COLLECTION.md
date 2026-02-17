# Collection Architecture

NPV Phase 2 introduces an offline collection layer:

1. **Ansible NETCONF playbooks** gather Junos BGP/MPLS/ISIS data (read-only)
2. Raw NETCONF XML is stored as JSON under `data/collected/<hostname>/`
3. Python parsers convert XML to typed models (`BGPRoute`, `MPLSLsp`, `ISISEntry`)
4. `CollectedDataLoader` indexes cached routes by hostname/prefix
5. Path tracing reads cache first and only falls back to live collection when cache misses

## Playbooks

- `ansible/playbooks/collect-junos-bgp.yml`
- `ansible/playbooks/collect-junos-mpls.yml`
- `ansible/playbooks/collect-junos-isis.yml`
- `ansible/playbooks/collect-all.yml`

Selective collection:

```bash
ansible-playbook ansible/playbooks/collect-all.yml -i inventories/example-generic.yml --tags bgp
ansible-playbook ansible/playbooks/collect-all.yml -i inventories/example-generic.yml --limit pe-nyc-1
```

## API

- `POST /api/collect` triggers ansible collection in background
- `GET /api/collect/{job_id}` returns status
- `GET /api/collected` lists stored files and stale-cache warnings (>1 hour)

## Data Contract

- `bgp-rib.json`: collection metadata + route list
- `mpls-lsp.json`: collection metadata + raw NETCONF XML response
- `isis-lsdb.json`: collection metadata + raw NETCONF XML response

All operations are read-only; no config RPCs are used.
