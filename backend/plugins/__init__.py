"""Plugins — optional enrichment for path traces. Don't affect core trace logic."""

from __future__ import annotations
from abc import ABC, abstractmethod


class CommunityDecoderPlugin(ABC):
    """Base class for community decoder plugins."""

    @abstractmethod
    def name(self) -> str:
        """Plugin name."""
        ...

    @abstractmethod
    def decode(self, communities: list[str], local_pref: int | None = None) -> dict:
        """
        Decode communities into labels/metadata.
        
        Returns a dict of labels to attach to a hop. Keys are plugin-defined.
        Example: {"origin": "Site-1", "preference": "primary"}
        """
        ...
