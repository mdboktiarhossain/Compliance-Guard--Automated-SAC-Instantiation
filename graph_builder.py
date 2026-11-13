"""
graph_builder.py — LPG Helper
==============================
Loads the system_architecture_graph.json (LPG) and provides
utility functions to query nodes, edges, and capabilities.
No external dependencies — pure Python.
"""
import json
from pathlib import Path
from typing import Optional

GRAPH_PATH = Path(__file__).parent / "system_architecture_graph.json"


def load_graph(graph_path: Path = GRAPH_PATH) -> dict:
    """Load the LPG from disk."""
    return json.loads(graph_path.read_text(encoding="utf-8"))


def save_graph(graph: dict, graph_path: Path = GRAPH_PATH) -> None:
    """Save the LPG back to disk."""
    graph_path.write_text(json.dumps(graph, indent=2), encoding="utf-8")


def get_nodes_by_label(graph: dict, label: str) -> list[dict]:
    """Return all nodes with a given label (e.g. 'Service', 'Function', 'Capability')."""
    return [n for n in graph["nodes"] if n["label"] == label]


def get_node(graph: dict, node_id: str) -> Optional[dict]:
    """Return a single node by its id, or None."""
    for n in graph["nodes"]:
        if n["id"] == node_id:
            return n
    return None


def get_edges_by_label(graph: dict, label: str) -> list[dict]:
    """Return all edges with a given label (e.g. 'HAS_CAPABILITY', 'DEPENDS_ON')."""
    return [e for e in graph["edges"] if e["label"] == label]


def get_outgoing_edges(graph: dict, node_id: str, label: Optional[str] = None) -> list[dict]:
    """Return edges where source == node_id, optionally filtered by label."""
    return [
        e for e in graph["edges"]
        if e["source"] == node_id and (label is None or e["label"] == label)
    ]


def get_incoming_edges(graph: dict, node_id: str, label: Optional[str] = None) -> list[dict]:
    """Return edges where target == node_id, optionally filtered by label."""
    return [
        e for e in graph["edges"]
        if e["target"] == node_id and (label is None or e["label"] == label)
    ]


def get_capabilities_of_service(graph: dict, service_id: str) -> list[str]:
    """
    Return all capability names reachable from a service via:
      Service --HAS_FUNCTION--> Function --HAS_CAPABILITY--> Capability
    """
    capabilities = []
    fn_edges = get_outgoing_edges(graph, service_id, "HAS_FUNCTION")
    for fn_edge in fn_edges:
        fn_id = fn_edge["target"]
        cap_edges = get_outgoing_edges(graph, fn_id, "HAS_CAPABILITY")
        for cap_edge in cap_edges:
            cap_node = get_node(graph, cap_edge["target"])
            if cap_node:
                capabilities.append(cap_node["properties"]["capability_name"])
    return list(set(capabilities))


def get_properties_of_service(graph: dict, service_id: str) -> dict:
    """Return the properties dict of a service node."""
    node = get_node(graph, service_id)
    if node:
        return node["properties"]
    return {}


def get_alternatives(graph: dict, service_id: str) -> list[str]:
    """Return all alternative service IDs that CAN_REPLACE the given service."""
    return [
        e["source"] for e in graph["edges"]
        if e["label"] == "CAN_REPLACE" and e["target"] == service_id
    ]


def get_active_services(graph: dict) -> list[dict]:
    """Return all Service nodes with status == 'active'."""
    return [
        n for n in graph["nodes"]
        if n["label"] == "Service" and n["properties"].get("status") == "active"
    ]


def set_service_status(graph: dict, service_id: str, status: str) -> bool:
    """Update a service node's status field. Returns True if found."""
    for n in graph["nodes"]:
        if n["id"] == service_id and n["label"] == "Service":
            n["properties"]["status"] = status
            return True
    return False


def replace_service_in_graph(graph: dict, old_service_id: str, new_service_id: str) -> dict:
    """
    Return a COPY of the graph where old_service is set to inactive
    and new_service is set to active. Does NOT modify the original.
    """
    import copy
    new_graph = copy.deepcopy(graph)
    set_service_status(new_graph, old_service_id, "inactive")
    set_service_status(new_graph, new_service_id, "active")
    return new_graph


def graph_summary(graph: dict) -> dict:
    """Return a quick summary of the graph."""
    services   = get_nodes_by_label(graph, "Service")
    functions  = get_nodes_by_label(graph, "Function")
    caps       = get_nodes_by_label(graph, "Capability")
    active     = [s for s in services if s["properties"].get("status") == "active"]
    inactive   = [s for s in services if s["properties"].get("status") == "inactive"]
    return {
        "total_nodes":    len(graph["nodes"]),
        "total_edges":    len(graph["edges"]),
        "services":       len(services),
        "active_services":   [s["id"] for s in active],
        "inactive_services": [s["id"] for s in inactive],
        "functions":      len(functions),
        "capabilities":   len(caps),
    }


if __name__ == "__main__":
    g = load_graph()
    summary = graph_summary(g)
    print("=== LPG Summary ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")

    print("\n=== Capabilities of auth-service ===")
    print(get_capabilities_of_service(g, "auth-service"))

    print("\n=== Capabilities of auth-service-v2 ===")
    print(get_capabilities_of_service(g, "auth-service-v2"))

    print("\n=== Alternatives for auth-service ===")
    print(get_alternatives(g, "auth-service"))
