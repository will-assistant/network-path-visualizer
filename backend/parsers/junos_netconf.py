"""Parse Junos NETCONF XML payloads into internal models."""

from __future__ import annotations

from datetime import datetime, timezone
from xml.etree import ElementTree as ET

from models import BGPRoute, MPLSLsp, ISISEntry


def _to_xml_root(xml: str) -> ET.Element:
    return ET.fromstring(xml.strip())


def _txt(node: ET.Element | None, path: str, default: str = "") -> str:
    if node is None:
        return default
    child = node.find(path)
    if child is None or child.text is None:
        return default
    return child.text.strip()


def _txts(node: ET.Element | None, path: str) -> list[str]:
    if node is None:
        return []
    out: list[str] = []
    for child in node.findall(path):
        if child.text and child.text.strip():
            out.append(child.text.strip())
    return out


def parse_bgp_rib(xml: str) -> list[BGPRoute]:
    root = _to_xml_root(xml)
    routes: list[BGPRoute] = []
    now = datetime.now(timezone.utc)

    for rt in root.findall(".//{*}rt"):
        prefix = _txt(rt, "{*}rt-destination")
        for entry in rt.findall("{*}rt-entry"):
            nh = _txt(entry, ".//{*}to") or _txt(entry, ".//{*}nh-local-interface")
            as_path_raw = _txt(entry, ".//{*}as-path")
            as_path = [token for token in as_path_raw.replace("AS path:", "").split() if token.isdigit()]
            communities = _txts(entry, ".//{*}community")
            local_pref_str = _txt(entry, ".//{*}local-preference")
            local_pref = int(local_pref_str) if local_pref_str.isdigit() else None
            origin = _txt(entry, ".//{*}validation-state") or _txt(entry, ".//{*}origin") or "unknown"
            source = _txt(entry, ".//{*}peer-id") or _txt(entry, ".//{*}current-active")

            routes.append(BGPRoute(
                prefix=prefix,
                next_hop=nh,
                as_path=as_path,
                communities=communities,
                local_pref=local_pref,
                origin=origin,
                source_router=source or "unknown",
                timestamp=now,
            ))

    return routes


def parse_mpls_lsp(xml: str) -> list[MPLSLsp]:
    root = _to_xml_root(xml)
    lsps: list[MPLSLsp] = []

    for lsp in root.findall(".//{*}rsvp-session-data"):
        name = _txt(lsp, "{*}session-name") or _txt(lsp, "{*}name")
        from_router = _txt(lsp, "{*}source-address")
        to_router = _txt(lsp, "{*}destination-address")
        state = _txt(lsp, ".//{*}lsp-state") or _txt(lsp, ".//{*}session-state") or "unknown"
        path = _txts(lsp, ".//{*}address")
        labels = _txts(lsp, ".//{*}label")

        if name:
            lsps.append(MPLSLsp(
                name=name,
                from_router=from_router or "unknown",
                to_router=to_router or "unknown",
                path=path,
                labels=labels,
                state=state,
            ))

    return lsps


def parse_isis_lsdb(xml: str) -> list[ISISEntry]:
    root = _to_xml_root(xml)
    entries: list[ISISEntry] = []

    for lsp in root.findall(".//{*}isis-database-entry"):
        system_id = _txt(lsp, "{*}lsp-id").split(".")[0]
        hostname = _txt(lsp, "{*}lsp-id")

        neighbors = []
        for is_neighbor in lsp.findall(".//{*}isis-neighbor"):
            nbr_id = _txt(is_neighbor, "{*}is-neighbor-id")
            metric_str = _txt(is_neighbor, "{*}metric")
            neighbors.append({
                "system_id": nbr_id,
                "metric": int(metric_str) if metric_str.isdigit() else 0,
            })

        ip_reachability = []
        for ip in lsp.findall(".//{*}isis-prefix"):
            pref = _txt(ip, "{*}address-prefix")
            if pref:
                ip_reachability.append(pref)

        if system_id:
            entries.append(ISISEntry(
                system_id=system_id,
                hostname=hostname or system_id,
                neighbors=neighbors,
                ip_reachability=ip_reachability,
            ))

    return entries
