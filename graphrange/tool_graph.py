"""
ARGUS-LAYER-7: GraphRange tool graph.

Tool nodes live in the same Neo4j instance as ARGUS, distinguished by
node_type='tool'. Populated by graphrange/crawler/tool_crawler.py, queried by
graphrange/docker/supervisor/supervisor.py's receive_tool_request().

Properties on a tool node (per GRAPHRANGE.md Phase 2 spec):
{
  "capability": "network_scanning",
  "supports_json_output": True,
  "json_flag": "-oJ",
  "has_parser_library": True,
  "parser_library": "python-nmap",
  "install_command": "apt-get install -y nmap",
  "os_requirements": ["linux"],
  "requires_root": False,
  "last_crawled_at": "iso timestamp",
}
"""

import ast

from graph.schema import Node, NodeSource


def get_tools_by_capability(driver, capability: str) -> list[dict]:
    """ARGUS-LAYER-7: Return tool nodes matching a capability string,
    ordered by grain_confidence DESC (best-evidenced match first)."""
    cypher = """
    MATCH (n:Node {node_type: 'tool'})
    WHERE n.properties CONTAINS $capability
    RETURN n
    ORDER BY n.grain_confidence DESC
    """
    with driver.session() as session:
        result = session.run(cypher, capability=capability)
        tools = []
        for record in result:
            node = dict(record["n"])
            try:
                node["properties"] = ast.literal_eval(node.get("properties", "{}"))
            except (ValueError, SyntaxError):
                node["properties"] = {}
            tools.append(node)
        return tools


def get_tool_by_name(driver, name: str) -> dict | None:
    """ARGUS-LAYER-7: Return a single tool node by node_id (the tool's name)."""
    cypher = "MATCH (n:Node {node_type: 'tool', node_id: $name}) RETURN n"
    with driver.session() as session:
        record = session.run(cypher, name=name).single()
    if record is None:
        return None
    node = dict(record["n"])
    try:
        node["properties"] = ast.literal_eval(node.get("properties", "{}"))
    except (ValueError, SyntaxError):
        node["properties"] = {}
    return node


def write_tool_node(driver, tool: dict) -> None:
    """ARGUS-LAYER-7: MERGE a tool node into Neo4j via the shared Node schema.

    `tool` must contain at least "name" and "capability"; other property
    keys (see module docstring) are optional and merged in as-is.
    grain_confidence: 0.8 if crawled from a structured source (Kali listing,
    --help/README parse), 0.5 if the LLM fallback filled in gaps — the
    caller (tool_crawler.py) decides which, this function just persists it.
    """
    name = tool["name"]
    properties = {k: v for k, v in tool.items() if k != "name"}
    node = Node(
        node_id=name,
        label=name,
        node_type="tool",
        properties=properties,
        grain_confidence=tool.get("grain_confidence", 0.5),
        open_questions=[],
        source=tool.get("source", NodeSource.AGENT),
    )
    cypher = """
    MERGE (n:Node {node_id: $node_id})
    SET n += $props
    SET n:Tool
    """
    with driver.session() as session:
        session.run(cypher, node_id=node.node_id, props=node.to_neo4j())
