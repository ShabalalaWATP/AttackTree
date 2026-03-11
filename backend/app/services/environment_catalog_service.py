"""Shared helpers for bundled environment catalogs used by References and AI prompts."""

from __future__ import annotations

from copy import deepcopy

from .environment_catalog_data import ENVIRONMENT_CATALOGS


_CATALOG_KEYWORDS = {
    "data_centre": [
        "data centre",
        "data center",
        "colocation",
        "colo",
        "dcim",
        "remote hands",
        "rack",
        "bmc",
        "ipmi",
        "hvac",
        "ups",
        "generator",
    ],
    "telecoms_base_station": [
        "telecom",
        "telecommunications",
        "base station",
        "cell site",
        "tower site",
        "enodeb",
        "gnodeb",
        "bts",
        "ran",
        "rru",
        "backhaul",
        "fronthaul",
        "microwave link",
    ],
    "telecoms_5g_core": [
        "5g core",
        "telecom core",
        "carrier core",
        "subscriber data",
        "network slice",
        "lawful intercept",
        "diameter",
        "ss7",
        "amf",
        "smf",
        "upf",
        "udm",
        "udr",
        "ims",
        "roaming",
    ],
    "satellite_ground_station": [
        "satellite ground station",
        "ground station",
        "teleport",
        "tt&c",
        "ttc",
        "uplink",
        "downlink",
        "antenna controller",
        "mission control",
        "telemetry processor",
    ],
    "airport": [
        "airport",
        "terminal operations",
        "aodb",
        "fids",
        "baggage handling",
        "airside",
        "ground handling",
        "gate allocation",
        "airport fuel farm",
        "airfield lighting",
    ],
    "military_headquarters": [
        "military headquarters",
        "defence headquarters",
        "defense headquarters",
        "command headquarters",
        "command center",
        "command centre",
        "scif",
        "cross-domain",
        "coalition network",
        "secure briefing",
    ],
    "oil_refinery": [
        "oil refinery",
        "refinery",
        "crude unit",
        "distillation column",
        "hydrocracker",
        "cracker unit",
        "tank farm",
        "loading rack",
        "refinery dcs",
        "turnaround",
    ],
    "drilling_rig": [
        "drilling rig",
        "offshore rig",
        "onshore rig",
        "drill floor",
        "bop",
        "blowout preventer",
        "mud logging",
        "well control",
        "toolpusher",
        "driller",
    ],
    "defence_manufacturing_plant": [
        "defence manufacturing",
        "defense manufacturing",
        "defence plant",
        "defense plant",
        "secure production line",
        "military manufacturing",
        "program security",
        "plm",
        "traceability record",
        "acceptance test rig",
    ],
    "shipyard_naval_base": [
        "shipyard",
        "naval base",
        "dry dock",
        "dockyard",
        "shore power",
        "waterside",
        "pier operations",
        "base maintenance",
        "crane control",
        "dock gate",
    ],
    "manufacturing_facility": [
        "manufacturing facility",
        "factory",
        "production line",
        "assembly line",
        "industrial robot",
        "mes",
        "industrial plant",
        "warehouse automation",
        "packaging line",
        "machine cell",
    ],
    "pharma_manufacturing_plant": [
        "pharma manufacturing",
        "pharmaceutical manufacturing",
        "batch control",
        "cleanroom",
        "lims",
        "electronic batch record",
        "hplc",
        "cold chain",
        "qc lab",
        "qa release",
    ],
    "ev_charging_network": [
        "ev charging",
        "charging network",
        "charging station",
        "charge point",
        "ocpp",
        "cpo",
        "fleet charging",
        "dc fast charger",
        "roaming hub",
        "load balancing charger",
    ],
    "lng_terminal": [
        "lng terminal",
        "liquefied natural gas",
        "regasification",
        "boil off gas",
        "cryogenic tank",
        "loading arm",
        "lng jetty",
        "lng storage",
        "lng process",
        "vaporizer",
    ],
    "electrical_substation": [
        "substation",
        "control house",
        "bay controller",
        "protective relay",
        "protection relay",
        "ied",
        "breaker",
        "switchyard",
        "iec 61850",
        "goose",
        "disturbance recorder",
    ],
    "water_treatment_plant": [
        "water treatment",
        "water utility",
        "water plant",
        "chemical dosing",
        "chlorine",
        "fluoride",
        "clarifier",
        "filtration",
        "booster pump",
        "reservoir",
        "oldsmar",
    ],
    "port_maritime_terminal": [
        "port terminal",
        "maritime terminal",
        "container terminal",
        "terminal operating system",
        "crane plc",
        "ship to shore crane",
        "yard automation",
        "vts",
        "ais",
        "berth",
        "customs manifest",
    ],
    "oil_gas_pipeline": [
        "gas pipeline",
        "oil pipeline",
        "compressor station",
        "meter station",
        "block valve",
        "leak detection",
        "pipeline scada",
        "pipeline control",
        "custody transfer",
        "midstream",
        "esd",
    ],
    "power_station": [
        "power station",
        "power plant",
        "generation plant",
        "turbine hall",
        "boiler",
        "balance of plant",
        "dcs",
        "switchyard",
        "black start",
    ],
    "nuclear_power_plant": [
        "nuclear",
        "reactor",
        "spent fuel",
        "refuel outage",
        "health physics",
        "vital area",
        "engineered safety feature",
        "containment",
        "radiological",
    ],
}


def load_environment_catalogs() -> list[dict]:
    return deepcopy(ENVIRONMENT_CATALOGS)


def list_environment_catalog_summaries() -> list[dict]:
    summaries: list[dict] = []
    for catalog in load_environment_catalogs():
        nodes = catalog.get("nodes", [])
        top_level = [node for node in nodes if not node.get("parent_id")]
        categories = sorted({str(node.get("category", "")).strip() for node in nodes if node.get("category")})
        summaries.append(
            {
                "id": catalog["id"],
                "name": catalog["name"],
                "sector": catalog.get("sector", ""),
                "description": catalog.get("description", ""),
                "context_presets": list(catalog.get("context_presets", [])),
                "node_count": len(nodes),
                "top_level_count": len(top_level),
                "categories": categories,
            }
        )
    return summaries


def get_environment_catalog(catalog_id: str) -> dict | None:
    for catalog in load_environment_catalogs():
        if catalog.get("id") == catalog_id:
            nodes = catalog.get("nodes", [])
            top_level = [node for node in nodes if not node.get("parent_id")]
            catalog["node_count"] = len(nodes)
            catalog["top_level_count"] = len(top_level)
            catalog["categories"] = sorted({str(node.get("category", "")).strip() for node in nodes if node.get("category")})
            return catalog
    return None


def find_environment_catalog_id(objective: str, scope: str = "", context_preset: str = "") -> str | None:
    normalized_preset = str(context_preset or "").strip().lower()
    for summary in list_environment_catalog_summaries():
        if normalized_preset and normalized_preset in {preset.lower() for preset in summary.get("context_presets", [])}:
            return summary["id"]

    haystack = f"{objective} {scope}".lower()
    scores: dict[str, int] = {}
    for catalog_id, keywords in _CATALOG_KEYWORDS.items():
        score = sum(1 for keyword in keywords if keyword in haystack)
        if score:
            scores[catalog_id] = score
    if not scores:
        return None
    return max(scores, key=scores.get)


def build_environment_catalog_outline(catalog_id: str, *, max_top_level: int = 6, max_children: int = 4) -> str:
    catalog = get_environment_catalog(catalog_id)
    if not catalog:
        return ""

    nodes = catalog.get("nodes", [])
    children_by_parent: dict[str, list[dict]] = {}
    for node in nodes:
        parent_id = node.get("parent_id")
        if not parent_id:
            continue
        children_by_parent.setdefault(parent_id, []).append(node)

    lines = [
        f"Environment catalog anchor: {catalog['name']}",
        f"- Sector: {catalog.get('sector', 'Unknown')}",
        f"- Summary: {catalog.get('description', '')}",
        "- Planning branches to preserve:",
    ]
    top_level = [node for node in nodes if not node.get("parent_id")]
    for node in top_level[:max_top_level]:
        child_labels = [child.get("label", "") for child in children_by_parent.get(node["id"], [])[:max_children]]
        child_suffix = f" -> {', '.join(child_labels)}" if child_labels else ""
        lines.append(f"  - {node.get('label', 'Unknown')}{child_suffix}")
    return "\n".join(lines)


def build_environment_catalog_outline_for_context(objective: str, scope: str = "", context_preset: str = "") -> str:
    catalog_id = find_environment_catalog_id(objective, scope, context_preset)
    if not catalog_id:
        return ""
    return build_environment_catalog_outline(catalog_id)
