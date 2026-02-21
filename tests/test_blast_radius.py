import sys
from pathlib import Path

import networkx as nx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from blast_radius import BlastRadiusCalculator
from graph_engine import GraphEngine
import main


def _build_test_graph_engine() -> GraphEngine:
    ge = GraphEngine()
    ge.graph = nx.DiGraph()
    ge.graph.add_edges_from([
        ("A", "B"),
        ("B", "C"),
        ("C", "D"),
        ("A", "E"),
        ("E", "D"),
        ("B", "F"),
    ])
    return ge


def test_blast_center_node_isolated():
    calc = BlastRadiusCalculator(_build_test_graph_engine())
    result = calc.calculate("B")

    rerouted = {(p.source, p.destination) for p in result.rerouted_pairs}
    isolated = {(p.source, p.destination) for p in result.isolated_pairs}

    assert ("A", "D") in rerouted
    assert ("A", "F") in isolated
    assert len(result.rerouted_pairs) >= 1
    assert len(result.isolated_pairs) >= 1


def test_blast_no_paths_through_node():
    ge = _build_test_graph_engine()
    calc = BlastRadiusCalculator(ge)
    result = calc.calculate("F")

    # F is a leaf node (only incoming edge B→F, no outgoing edges).
    # No path can transit through F, so blast radius should be empty.
    assert result.rerouted_pairs == []
    assert result.isolated_pairs == []
    assert "F" in result.summary


def test_blast_fully_isolated_node():
    ge = GraphEngine()
    ge.graph = nx.DiGraph()
    ge.graph.add_edges_from([
        ("A", "E"),
        ("B", "E"),
        ("E", "C"),
        ("E", "D"),
    ])
    calc = BlastRadiusCalculator(ge)
    result = calc.calculate("E")

    assert len(result.rerouted_pairs) == 0
    assert len(result.isolated_pairs) > 0


def test_blast_invalid_node():
    calc = BlastRadiusCalculator(_build_test_graph_engine())
    with pytest.raises(ValueError, match="Node not in graph"):
        calc.calculate("nonexistent")


def test_blast_all_paths_deduplicated():
    ge = GraphEngine()
    ge.graph = nx.DiGraph()
    ge.graph.add_edges_from([
        ("A", "X",),
        ("X", "B"),
        ("A", "Y"),
        ("Y", "B"),
        ("B", "D"),
        ("A", "D"),
    ])
    calc = BlastRadiusCalculator(ge)
    result = calc.calculate("B")

    combined = result.rerouted_pairs + result.isolated_pairs
    pairs = [(p.source, p.destination) for p in combined]
    assert len(pairs) == len(set(pairs))


def test_blast_rerouted_correct_path():
    calc = BlastRadiusCalculator(_build_test_graph_engine())
    result = calc.calculate("B")

    target = next(p for p in result.rerouted_pairs if p.source == "A" and p.destination == "D")
    assert "B" not in target.alternate_path


def test_blast_summary_string():
    calc = BlastRadiusCalculator(_build_test_graph_engine())
    result = calc.calculate("B")

    assert "Failing B breaks" in result.summary
    assert str(len(result.isolated_pairs)) in result.summary
    assert str(len(result.rerouted_pairs)) in result.summary


def test_blast_nodes_api():
    client = TestClient(main.app)
    resp = client.get("/api/blast-radius/nodes")
    assert resp.status_code == 200
    data = resp.json()
    assert "nodes" in data
    assert isinstance(data["nodes"], list)
