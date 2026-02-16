"""Palo Alto Collector — stub for future implementation."""

from collectors import RouteEntry


class PanosCollector:
    """Collect routes from Palo Alto firewalls via Panorama API. Not yet implemented."""

    def __init__(self, host: str, api_key: str = ""):
        self.host = host
        self.api_key = api_key

    async def get_route(self, prefix: str, vrf: str = "") -> list[RouteEntry]:
        raise NotImplementedError("Palo Alto collector not yet implemented")
