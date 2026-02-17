"""Load cached collection JSON and serve route lookups for the path walker."""

from __future__ import annotations

import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from collectors import RouteEntry
from models import BGPRoute

logger = logging.getLogger(__name__)


class CollectedDataLoader:
    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self._bgp_by_host: dict[str, list[BGPRoute]] = {}
        self._index: dict[str, dict[str, list[BGPRoute]]] = {}
        self._timestamps: dict[str, datetime] = {}
        self.reload()

    def reload(self):
        self._bgp_by_host.clear()
        self._index.clear()
        self._timestamps.clear()

        if not self.base_dir.exists():
            return

        for host_dir in self.base_dir.iterdir():
            if not host_dir.is_dir():
                continue
            bgp_path = host_dir / "bgp-rib.json"
            if not bgp_path.exists():
                continue

            try:
                payload = json.loads(bgp_path.read_text())
                routes_raw = payload.get("routes", [])
                routes = [BGPRoute.model_validate(r) for r in routes_raw]
                self._bgp_by_host[host_dir.name] = routes
                self._index[host_dir.name] = {}
                for r in routes:
                    self._index[host_dir.name].setdefault(r.prefix, []).append(r)

                ts = payload.get("collected_at")
                if ts:
                    self._timestamps[host_dir.name] = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except Exception as exc:
                logger.warning("Failed to parse cached file %s: %s", bgp_path, exc)

    def stale_warnings(self) -> list[str]:
        now = datetime.now(timezone.utc)
        warnings: list[str] = []
        for host, ts in self._timestamps.items():
            if now - ts > timedelta(hours=1):
                warnings.append(f"{host}: cached data is older than 1 hour ({ts.isoformat()})")
        return warnings

    def lookup_routes(self, hostname: str, prefix: str) -> list[RouteEntry]:
        host_idx = self._index.get(hostname, {})
        if prefix in host_idx:
            return [self._to_route_entry(r) for r in host_idx[prefix]]

        try:
            target = ipaddress.ip_network(prefix, strict=False)
        except Exception:
            return []

        matches: list[BGPRoute] = []
        for route_prefix, routes in host_idx.items():
            try:
                rp = ipaddress.ip_network(route_prefix, strict=False)
            except Exception:
                continue
            if target.subnet_of(rp) or target == rp:
                matches.extend(routes)

        # Longest-prefix first
        matches.sort(key=lambda r: ipaddress.ip_network(r.prefix, strict=False).prefixlen, reverse=True)
        return [self._to_route_entry(r) for r in matches]

    @staticmethod
    def _to_route_entry(route: BGPRoute) -> RouteEntry:
        return RouteEntry(
            prefix=route.prefix,
            protocol="bgp",
            next_hop=route.next_hop,
            communities=route.communities,
            local_pref=route.local_pref,
            as_path=route.as_path,
            active=True,
            source=route.source_router,
        )
