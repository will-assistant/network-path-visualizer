"""
FIS Community Decoder Plugin — Decodes OID/AID communities for FIS network.

Moved from V2 community_decoder.py. This is network-specific logic that
doesn't belong in the core trace engine.

Community design:
- OID (Origin ID): X:1594 — tagged at DCPE, identifies originating site
- AID (Advertising ID): X:194 — tagged at SPE, identifies advertising site
- LP mapping: 200=primary, 150=secondary, 50=tertiary
"""

from __future__ import annotations

import re
from typing import Optional
from plugins import CommunityDecoderPlugin


# Community markers
OID_MARKER = 1594   # X:1594 = OID for site X
AID_MARKER = 194    # X:194  = AID for site X

# LP values
LP_PRIMARY = 200
LP_SECONDARY = 150
LP_TERTIARY = 50

# Site → region
SITE_REGIONS: dict[int, str] = {
    1: "americas", 2: "americas", 3: "americas", 4: "americas",
    7: "emea", 8: "emea",
    17: "apac", 18: "apac", 19: "apac",
}


class FISCommunityDecoder(CommunityDecoderPlugin):
    """Decode FIS OID/AID community conventions."""

    def name(self) -> str:
        return "fis-community-decoder"

    def decode(self, communities: list[str], local_pref: int | None = None) -> dict:
        result: dict = {}
        oid = None
        aid = None

        for comm in communities:
            m = re.match(r'^(\d+):(\d+)$', comm)
            if not m:
                continue
            left, right = int(m.group(1)), int(m.group(2))

            if right == OID_MARKER:
                oid = left
                result["origin_site"] = f"Site-{left}"
                result["region"] = SITE_REGIONS.get(left, "unknown")
            elif right == AID_MARKER:
                aid = left
                result["advertising_site"] = f"Site-{left}"

        if local_pref is not None:
            if local_pref >= LP_PRIMARY:
                result["preference"] = "primary"
            elif local_pref >= LP_SECONDARY:
                result["preference"] = "secondary"
            elif local_pref <= LP_TERTIARY:
                result["preference"] = "tertiary"

        return result
