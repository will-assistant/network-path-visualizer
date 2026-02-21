from __future__ import annotations

from dataclasses import dataclass, field
from itertools import islice

import networkx as nx

from graph_engine import GraphEngine


@dataclass
class AffectedPair:
    source: str
    destination: str
    original_path: list[str]
    alternate_path: list[str]
    status: str


@dataclass
class BlastRadiusResult:
    failed_node: str
    isolated_pairs: list[AffectedPair] = field(default_factory=list)
    rerouted_pairs: list[AffectedPair] = field(default_factory=list)
    unaffected_node_count: int = 0
    summary: str = ""


class BlastRadiusCalculator:
    def __init__(self, graph_engine: GraphEngine):
        self.ge = graph_engine

    def calculate(self, failed_node: str) -> BlastRadiusResult:
        nodes = list(self.ge.graph.nodes())
        if failed_node not in nodes:
            raise ValueError("Node not in graph")

        isolated_pairs: list[AffectedPair] = []
        rerouted_pairs: list[AffectedPair] = []
        skipped_pairs = 0

        affected_sources: set[str] = set()
        affected_destinations: set[str] = set()

        for src in nodes:
            if src == failed_node:
                continue
            for dst in nodes:
                if dst == failed_node or dst == src:
                    continue

                try:
                    gen = nx.all_simple_paths(self.ge.graph, src, dst, cutoff=15)
                    all_paths = list(islice(gen, 51))
                except Exception:
                    continue

                if len(all_paths) > 50:
                    skipped_pairs += 1
                    continue

                through_failed = [p for p in all_paths if failed_node in p]
                if not through_failed:
                    continue

                affected_sources.add(src)
                affected_destinations.add(dst)

                original_path = through_failed[0]
                alternate_path = self.ge.shortest_path(src, dst, exclude=[failed_node])

                if alternate_path:
                    rerouted_pairs.append(
                        AffectedPair(
                            source=src,
                            destination=dst,
                            original_path=original_path,
                            alternate_path=alternate_path,
                            status="rerouted",
                        )
                    )
                else:
                    isolated_pairs.append(
                        AffectedPair(
                            source=src,
                            destination=dst,
                            original_path=original_path,
                            alternate_path=[],
                            status="isolated",
                        )
                    )

        affected_nodes = affected_sources | affected_destinations
        unaffected_node_count = len([n for n in nodes if n != failed_node and n not in affected_nodes])

        summary = (
            f"Failing {failed_node} breaks {len(isolated_pairs)} path(s) with no alternate "
            f"and reroutes {len(rerouted_pairs)} path(s)."
        )
        if skipped_pairs:
            summary += f" Skipped {skipped_pairs} dense pair(s) with >50 simple paths."

        return BlastRadiusResult(
            failed_node=failed_node,
            isolated_pairs=isolated_pairs,
            rerouted_pairs=rerouted_pairs,
            unaffected_node_count=unaffected_node_count,
            summary=summary,
        )
