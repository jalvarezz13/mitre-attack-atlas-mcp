import json
from functools import lru_cache
from typing import List, Dict, Any, Union, Optional

from fastmcp import FastMCP

FRAMEWORK_FILES = {
    "mitre_attack": "data/stix-attack-enterprise.json",  # https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/heads/master/enterprise-attack/enterprise-attack.json
    "mitre_atlas": "data/stix-atlas-enterprise.json",  # https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/refs/heads/main/dist/stix-atlas-attack-enterprise.json
}

mcp = FastMCP("MITRE ATT&CK / ATLAS Server", "1.0.0")


# Helper functions
@lru_cache(maxsize=4)
def load_framework(framework: str) -> List[Dict[str, Any]]:
    if framework not in FRAMEWORK_FILES:
        raise ValueError("Framework must be 'mitre_attack' or 'mitre_atlas'")

    path = FRAMEWORK_FILES[framework]

    try:
        with open(path, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except FileNotFoundError as exc:
        raise ValueError(f"Framework file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in framework file {path}") from exc

    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValueError("Invalid STIX bundle format: 'objects' is missing or not a list")

    return objects


def get_attack_id(obj: Dict[str, Any]) -> Optional[str]:
    for ref in obj.get("external_references", []) or []:
        if isinstance(ref, dict) and "external_id" in ref:
            return ref["external_id"]
    return None


def is_attack_id(obj: Dict[str, Any], attack_id: str) -> bool:
    return get_attack_id(obj) == attack_id


def find_technique_by_attack_id(objects: List[Dict[str, Any]], attack_id: str) -> Optional[Dict[str, Any]]:
    for obj in objects:
        if obj.get("type") == "attack-pattern" and is_attack_id(obj, attack_id):
            return obj
    return None


# Tools
@mcp.tool
async def query_technique(framework: str, query: str) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Query techniques by exact ID or by name substring.

    Behavior:
      - If `query` exactly matches a technique ID (e.g. T1059.001),
        returns a dictionary with basic technique details.
      - If `query` is treated as a name search, returns a list of matching
        techniques (id and name only).

    Args:
        framework: Framework to query (mitre_attack or mitre_atlas). If not specified, ask the user.
        query: Technique ID or name.

    Returns:
        A single technique dictionary for exact ID matches,
        or a list of dictionaries for name-based searches.
    """
    objects = load_framework(framework)

    if not isinstance(query, str) or not query.strip():
        return []

    query_lower = query.strip().lower()
    results: List[Dict[str, Any]] = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        attack_id = get_attack_id(obj)

        # Exact ID match
        if attack_id and query.strip().upper() == attack_id.upper():
            return {
                "id": attack_id,
                "name": obj.get("name"),
                "description": obj.get("description"),
                "platforms": obj.get("x_mitre_platforms", []),
                "kill_chain_phases": obj.get("kill_chain_phases", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
            }

        # Name-based search (substring, case-insensitive)
        name = obj.get("name", "") or ""
        if query_lower in name.lower():
            results.append({"id": attack_id, "name": name})

    return results


@mcp.tool
async def search_technique_full(framework: str, query: str) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """
    Search for a technique and return full context information.

    Extends `query_technique` by including:
      - mitigations
      - detections
      - subtechniques

    If the query is ambiguous (multiple matches), the list of matches is returned.

    Args:
        framework: Framework to query (mitre_attack or mitre_atlas). If not specified, ask the user.
        query: Technique ID or name.

    Returns:
        A full technique dictionary or a list of matches.
    """
    base = await query_technique(framework, query)

    if not isinstance(base, dict):
        return base

    base.update(
        {
            "mitigations": await query_mitigations(framework, base["id"]),
            "detections": await query_detections(framework, base["id"]),
            "subtechniques": await query_subtechniques(framework, base["id"]),
        }
    )

    return base


@mcp.tool
async def query_mitigations(framework: str, technique_id: str) -> List[Dict[str, Optional[str]]]:
    """
    Retrieve mitigations (course-of-action objects) related to a technique.

    Args:
        framework: Framework to query (mitre_attack or mitre_atlas). If not specified, ask the user.
        technique_id: Technique external_id.

    Returns:
        List of mitigations with id, name, and description.
    """
    objects = load_framework(framework)
    technique = find_technique_by_attack_id(objects, technique_id)

    if not technique:
        return []

    mitigations: List[Dict[str, Optional[str]]] = []

    for rel in objects:
        if rel.get("type") == "relationship" and rel.get("target_ref") == technique["id"]:
            coa = next(
                (o for o in objects if o.get("id") == rel.get("source_ref") and o.get("type") == "course-of-action"),
                None,
            )
            if coa:
                mitigations.append(
                    {
                        "id": get_attack_id(coa),
                        "name": coa.get("name"),
                        "description": coa.get("description"),
                    }
                )

    return mitigations


@mcp.tool
async def query_detections(framework: str, technique_id: str) -> List[Dict[str, Optional[str]]]:
    """
    Retrieve detection-related data components for a technique.

    Args:
        framework: Framework to query (mitre_attack or mitre_atlas). If not specified, ask the user.
        technique_id: Technique external_id.

    Returns:
        List of detection sources and descriptions.
    """
    objects = load_framework(framework)
    technique = find_technique_by_attack_id(objects, technique_id)

    if not technique:
        return []

    detections: List[Dict[str, Optional[str]]] = []

    for rel in objects:
        if rel.get("type") == "relationship" and rel.get("target_ref") == technique["id"]:
            src = next((o for o in objects if o.get("id") == rel.get("source_ref")), None)
            if src and src.get("type") == "x-mitre-data-component":
                detections.append(
                    {
                        "source": src.get("name"),
                        "description": src.get("description"),
                    }
                )

    return detections


@mcp.tool
async def list_tactics(framework: str) -> List[Dict[str, Optional[str]]]:
    """
    List all tactics in the selected framework.

    Args:
        framework: Framework to query (mitre_attack or mitre_atlas). If not specified, ask the user.

    Returns:
        List of tactics with id, name, and description.
    """
    objects = load_framework(framework)
    tactics: List[Dict[str, Optional[str]]] = []

    for obj in objects:
        if obj.get("type") == "x-mitre-tactic":
            tactics.append(
                {
                    "id": get_attack_id(obj),
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                }
            )

    return tactics


@mcp.tool
async def query_subtechniques(framework: str, technique_id: str) -> List[Dict[str, Optional[str]]]:
    """
    Retrieve subtechniques for a given parent technique.

    Args:
        framework: Framework to query (mitre_attack or mitre_atlas). If not specified, ask the user.
        technique_id: Parent technique external_id.

    Returns:
        List of subtechniques with id, name, and description.
    """
    objects = load_framework(framework)
    parent = find_technique_by_attack_id(objects, technique_id)

    if not parent:
        return []

    subtechniques: List[Dict[str, Optional[str]]] = []

    for obj in objects:
        if (
            obj.get("type") == "attack-pattern"
            and obj.get("x_mitre_is_subtechnique")
            and parent["id"] in obj.get("x_mitre_parent_attack_pattern_ids", [])
        ):
            subtechniques.append(
                {
                    "id": get_attack_id(obj),
                    "name": obj.get("name"),
                    "description": obj.get("description"),
                }
            )

    return subtechniques


@mcp.tool
async def query_tactic_techniques(framework: str, tactic_id_or_name: str) -> List[Dict[str, Optional[str]]]:
    """
    List techniques associated with a given tactic.

    The tactic can be provided either as:
      - tactic ID (e.g. TA0001), or
      - tactic name (e.g. "initial-access").

    Args:
        framework: Framework to query (mitre_attack or mitre_atlas). If not specified, ask the user.
        tactic_id_or_name: Tactic ID or tactic name.

    Returns:
        List of techniques (id and name) associated with the tactic.
    """
    objects = load_framework(framework)
    techniques: List[Dict[str, Optional[str]]] = []

    if not tactic_id_or_name:
        return techniques

    target = tactic_id_or_name.strip().lower()

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        for phase in obj.get("kill_chain_phases", []) or []:
            phase_name = (phase.get("phase_name") or "").lower()
            if target == phase_name or target.upper().startswith("TA"):
                techniques.append(
                    {
                        "id": get_attack_id(obj),
                        "name": obj.get("name"),
                    }
                )
                break

    return techniques


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)
