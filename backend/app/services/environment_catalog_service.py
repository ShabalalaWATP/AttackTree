"""Shared helpers for bundled environment catalogs used by References and AI prompts."""

from __future__ import annotations

from copy import deepcopy

from .environment_catalog_data import ENVIRONMENT_CATALOGS


_SHARED_CONCEPT_RULES = [
    {
        "id": "management_plane",
        "label": "Management / Operations Plane",
        "weight": 1,
        "keywords": [
            "management plane",
            "operations plane",
            "oam",
            "ems",
            "element manager",
            "oss",
            "bss",
            "head-end",
            "supervisory platform",
            "provisioning",
            "admin console",
            "operations software",
            "dcim",
        ],
    },
    {
        "id": "identity_secrets_pki",
        "label": "Identity / Secrets / PKI",
        "weight": 2,
        "keywords": [
            "identity",
            "ldap",
            "sso",
            "federation",
            "kerberos",
            "directory",
            "pam",
            "secret",
            "vault",
            "certificate",
            "certificate authority",
            "pki",
            "hsm",
            "key material",
            "authentication",
        ],
    },
    {
        "id": "automation_orchestration",
        "label": "Automation / Orchestration",
        "weight": 2,
        "keywords": [
            "automation",
            "orchestration",
            "kubernetes",
            "openshift",
            "openstack",
            "ci/cd",
            "gitops",
            "helm",
            "ansible",
            "terraform",
            "package management",
            "runner",
            "deployment",
        ],
    },
    {
        "id": "networking_transport",
        "label": "Networking / Transport",
        "weight": 1,
        "keywords": [
            "networking",
            "network",
            "router",
            "switch",
            "firewall",
            "gateway",
            "transport",
            "wan",
            "ip/mpls",
            "backhaul",
            "fronthaul",
            "midhaul",
            "microwave",
            "fibre",
            "interconnect",
            "peering",
            "segment routing",
        ],
    },
    {
        "id": "remote_access_vendor",
        "label": "Remote Access / Vendor Access",
        "weight": 1,
        "keywords": [
            "remote access",
            "vendor",
            "vpn",
            "jump host",
            "support path",
            "support portal",
            "remote support",
            "third-party",
            "managed service",
            "remote hands",
            "field service",
            "maintenance window",
        ],
    },
    {
        "id": "monitoring_assurance",
        "label": "Monitoring / Assurance",
        "weight": 1,
        "keywords": [
            "monitoring",
            "telemetry",
            "observability",
            "siem",
            "nms",
            "alarm",
            "trace",
            "kpi",
            "analytics",
            "historian",
            "fault",
            "assurance",
            "log",
        ],
    },
    {
        "id": "timing_pnt",
        "label": "Timing / PNT",
        "weight": 2,
        "keywords": [
            "timing",
            "pnt",
            "gnss",
            "gps",
            "ptp",
            "synce",
            "prtc",
            "eprtc",
            "holdover",
            "boundary clock",
            "grandmaster",
            "time synchronisation",
            "time synchronization",
            "clock drift",
        ],
    },
    {
        "id": "inventory_capacity",
        "label": "Inventory / Asset / Capacity",
        "weight": 2,
        "keywords": [
            "inventory",
            "asset",
            "capacity",
            "cmdb",
            "rack capacity",
            "discovery",
            "subscriber admin",
            "provisioning system",
            "telemetry platform",
        ],
    },
    {
        "id": "power_backup",
        "label": "Power / Backup Power",
        "weight": 2,
        "keywords": [
            "power",
            "ups",
            "battery",
            "generator",
            "pdu",
            "rectifier",
            "switchgear",
            "transformer",
            "sts",
            "ats",
            "dc power",
            "busway",
            "rpp",
            "epms",
        ],
    },
    {
        "id": "cooling_environmental",
        "label": "Cooling / Environmental",
        "weight": 2,
        "keywords": [
            "cooling",
            "hvac",
            "chiller",
            "crac",
            "crah",
            "condenser",
            "pump",
            "cooling tower",
            "temperature",
            "humidity",
            "environmental",
            "water ingress",
        ],
    },
    {
        "id": "facility_ot_supervision",
        "label": "Supervisory Control / OT",
        "weight": 2,
        "keywords": [
            "bms",
            "scada",
            "plc",
            "hmi",
            "dcs",
            "engineering workstation",
            "rtu",
            "process control",
            "field controller",
            "relay panel",
            "supervisory",
        ],
    },
    {
        "id": "physical_access_cctv",
        "label": "Physical Access / CCTV",
        "weight": 2,
        "keywords": [
            "access control",
            "badge",
            "door",
            "pacs",
            "mantrap",
            "turnstile",
            "cctv",
            "camera",
            "guard",
            "visitor",
            "perimeter",
            "nvr",
            "vms",
            "cabinet lock",
        ],
    },
    {
        "id": "safety_recovery",
        "label": "Safety / Recovery",
        "weight": 2,
        "keywords": [
            "safety",
            "protection",
            "fire suppression",
            "trip",
            "interlock",
            "shutdown",
            "recovery",
            "restoration",
            "continuity",
            "incident response",
            "failover",
            "black-start",
            "black start",
        ],
    },
]

_SHARED_CONCEPT_LABELS = {rule["id"]: rule["label"] for rule in _SHARED_CONCEPT_RULES}
_SHARED_CONCEPT_WEIGHTS = {rule["id"]: int(rule["weight"]) for rule in _SHARED_CONCEPT_RULES}


_CATALOG_KEYWORDS = {
    "data_centre": [
        "data centre",
        "data center",
        "colocation",
        "colo",
        "dcim",
        "epms",
        "remote hands",
        "rack",
        "bmc",
        "ipmi",
        "vcenter",
        "hyper-v",
        "kubernetes",
        "pam",
        "cyberark",
        "veeam",
        "commvault",
        "servicenow",
        "ansible",
        "terraform",
        "vault",
        "splunk",
        "sentinel",
        "edr",
        "pacs",
        "access control",
        "badge reader",
        "badge access",
        "mantrap",
        "turnstile",
        "cctv",
        "nvr",
        "vms",
        "camera",
        "bms",
        "hvac",
        "cooling",
        "crac",
        "crah",
        "chiller",
        "pdu",
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
        "oru",
        "backhaul",
        "fronthaul",
        "microwave link",
        "midhaul",
        "o-ran",
        "open ran",
        "ric",
        "son",
        "enm",
        "netact",
        "massive mimo",
        "ret control",
        "cell site gateway",
        "synce",
        "gnss timing",
        "gps timing",
        "pnt",
        "prtc",
        "timing receiver",
        "gnss antenna",
        "ptp grandmaster",
        "boundary clock",
        "holdover",
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
        "nssf",
        "chf",
        "ocs",
        "sepp",
        "nef",
        "scp",
        "ipx",
        "sbc",
        "dra",
        "eir",
        "hss",
        "hlr",
        "smsc",
        "rcs",
        "cdr mediation",
        "lawful intercept mediation",
        "eprtc",
        "ptp grandmaster",
        "boundary clock",
        "timing assurance",
        "clock drift",
        "grandmaster failover",
        "ordered event records",
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
    return _annotate_environment_catalogs(deepcopy(ENVIRONMENT_CATALOGS))


def _stringify_node(node: dict) -> str:
    parts = [
        str(node.get("label", "")),
        str(node.get("description", "")),
        str(node.get("category", "")),
    ]
    for field in (
        "attack_surfaces",
        "telemetry",
        "management_interfaces",
        "dependencies",
        "common_protocols",
        "example_technologies",
    ):
        parts.extend(str(value) for value in node.get(field, []) or [])
    return " ".join(parts).lower()


def _build_shared_concept_tags(concept_ids: list[str]) -> list[dict]:
    return [{"id": concept_id, "label": _SHARED_CONCEPT_LABELS[concept_id]} for concept_id in concept_ids]


def _derive_shared_concept_ids(node: dict) -> list[str]:
    haystack = _stringify_node(node)
    matches: list[str] = []
    for rule in _SHARED_CONCEPT_RULES:
        if any(keyword in haystack for keyword in rule["keywords"]):
            matches.append(rule["id"])
    return matches


def _annotate_environment_catalogs(catalogs: list[dict]) -> list[dict]:
    concept_to_catalogs: dict[str, set[str]] = {}
    catalog_lookup = {catalog["id"]: catalog for catalog in catalogs}

    for catalog in catalogs:
        concept_counts: dict[str, int] = {}
        for node in catalog.get("nodes", []):
            concept_ids = _derive_shared_concept_ids(node)
            node["_shared_concept_ids"] = concept_ids
            node["shared_concepts"] = _build_shared_concept_tags(concept_ids)
            for concept_id in concept_ids:
                concept_counts[concept_id] = concept_counts.get(concept_id, 0) + 1
                concept_to_catalogs.setdefault(concept_id, set()).add(catalog["id"])

        sorted_catalog_concepts = sorted(
            concept_counts,
            key=lambda concept_id: (-concept_counts[concept_id], _SHARED_CONCEPT_LABELS[concept_id]),
        )
        catalog["shared_concepts"] = _build_shared_concept_tags(sorted_catalog_concepts[:8])

    for catalog in catalogs:
        for node in catalog.get("nodes", []):
            overlap_scores: dict[str, int] = {}
            for concept_id in node.get("_shared_concept_ids", []):
                for related_catalog_id in concept_to_catalogs.get(concept_id, set()):
                    if related_catalog_id == catalog["id"]:
                        continue
                    overlap_scores[related_catalog_id] = overlap_scores.get(related_catalog_id, 0) + _SHARED_CONCEPT_WEIGHTS[concept_id]

            related_catalogs = sorted(
                (
                    {"id": related_catalog_id, "name": catalog_lookup[related_catalog_id]["name"], "score": score}
                    for related_catalog_id, score in overlap_scores.items()
                    if score >= 2
                ),
                key=lambda item: (-item["score"], item["name"]),
            )
            node["related_catalogs"] = [
                {"id": item["id"], "name": item["name"]}
                for item in related_catalogs[:4]
            ]
            node.pop("_shared_concept_ids", None)

    return catalogs


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
                "shared_concepts": list(catalog.get("shared_concepts", [])),
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


def build_environment_catalog_outline(catalog_id: str, *, max_top_level: int = 6, max_children: int = 6) -> str:
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
