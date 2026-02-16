"""FortiOS Collector — stub for future implementation."""

from collectors import RouteEntry


class FortiOSCollector:
    """Collect routes from Fortinet devices via REST API. Not yet implemented."""

    def __init__(self, host: str, api_key: str = ""):
        self.host = host
        self.api_key = api_key

    async def get_route(self, prefix: str, vrf: str = "") -> list[RouteEntry]:
        raise NotImplementedError("FortiOS collector not yet implemented")
