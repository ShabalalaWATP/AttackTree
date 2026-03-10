"""Template API for starter attack trees."""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/templates", tags=["templates"])

TEMPLATES_DIR = Path(__file__).parent.parent / "templates_data"


def _template_summary(template_id: str, data: dict) -> dict:
    return {
        "id": template_id,
        "name": data.get("name", template_id),
        "description": data.get("description", ""),
        "context_preset": data.get("context_preset", "general"),
        "node_count": len(data.get("nodes", [])),
        "template_family": data.get("template_family", "general"),
        "technical_profile": data.get("technical_profile", "standard"),
        "focus_areas": data.get("focus_areas", []),
        "prompt_hints": data.get("prompt_hints", []),
    }


@router.get("")
async def list_templates():
    """List all available attack tree templates."""
    templates = []
    if TEMPLATES_DIR.exists():
        for f in sorted(TEMPLATES_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                templates.append(_template_summary(f.stem, data))
            except Exception:
                continue
    return {"templates": templates}


@router.get("/{template_id}")
async def get_template(template_id: str):
    """Get a specific template's full data."""
    file_path = TEMPLATES_DIR / f"{template_id}.json"
    if not file_path.exists():
        raise HTTPException(404, "Template not found")
    data = json.loads(file_path.read_text(encoding="utf-8"))
    return data
