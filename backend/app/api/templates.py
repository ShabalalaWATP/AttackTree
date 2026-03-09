"""Template API for starter attack trees."""
import json
from pathlib import Path
from fastapi import APIRouter, HTTPException

router = APIRouter(prefix="/templates", tags=["templates"])

TEMPLATES_DIR = Path(__file__).parent.parent / "templates_data"


@router.get("")
async def list_templates():
    """List all available attack tree templates."""
    templates = []
    if TEMPLATES_DIR.exists():
        for f in sorted(TEMPLATES_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                templates.append({
                    "id": f.stem,
                    "name": data.get("name", f.stem),
                    "description": data.get("description", ""),
                    "context_preset": data.get("context_preset", "general"),
                    "node_count": len(data.get("nodes", [])),
                })
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
