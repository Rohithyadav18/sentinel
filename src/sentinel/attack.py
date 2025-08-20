"""MITRE ATT&CK catalog loader (real technique data, bundled offline).

The catalog under ``data/attack_catalog.json`` is the enterprise ATT&CK v15.1
technique list extracted from MITRE's official STIX data. Detections reference
technique IDs (e.g. ``T1110``); this module resolves them to real names/tactics.
"""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_CATALOG_PATH = Path(__file__).parent / "data" / "attack_catalog.json"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    url: str


@lru_cache
def _catalog() -> dict[str, Technique]:
    raw = json.loads(_CATALOG_PATH.read_text())
    return {
        tid: Technique(id=tid, name=t["name"], tactics=tuple(t["tactics"]), url=t.get("url", ""))
        for tid, t in raw["techniques"].items()
    }


def get_technique(technique_id: str) -> Technique:
    """Resolve an ATT&CK technique id to its real name + tactics.

    Sub-technique ids (``T1110.001``) fall back to their parent if the exact id
    is absent, so a detection can cite a sub-technique and still resolve.
    """
    catalog = _catalog()
    if technique_id in catalog:
        return catalog[technique_id]
    parent = technique_id.split(".")[0]
    if parent in catalog:
        return catalog[parent]
    raise KeyError(f"unknown ATT&CK technique: {technique_id}")


def all_technique_ids() -> set[str]:
    return set(_catalog())
