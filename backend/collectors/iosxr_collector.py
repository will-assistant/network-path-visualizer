"""IOS-XR Collector — stub for future implementation."""

from collectors import RouteEntry


class IOSXRCollector:
    """Collect routes from Cisco IOS-XR devices. Not yet implemented."""

    def __init__(self, host: str, username: str = "", password: str = "",
                 connection: str = "netconf"):
        self.host = host
        self.username = username
        self.password = password
        self.connection = connection

    async def get_route(self, prefix: str, vrf: str = "") -> list[RouteEntry]:
        raise NotImplementedError("IOS-XR collector not yet implemented")
