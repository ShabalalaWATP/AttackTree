import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path

from .config import settings
from .database import init_db
from .api import projects, nodes, mitigations, detections, references, snapshots, comments, llm, export, templates, tags, audit, scenarios, kill_chains, threat_models, ai_chat

logging.basicConfig(level=settings.LOG_LEVEL)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("AttackTree Builder starting up...")
    await init_db()
    logger.info("Database initialized")
    yield
    logger.info("AttackTree Builder shutting down...")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
app.include_router(projects.router, prefix="/api")
app.include_router(nodes.router, prefix="/api")
app.include_router(mitigations.router, prefix="/api")
app.include_router(detections.router, prefix="/api")
app.include_router(references.router, prefix="/api")
app.include_router(snapshots.router, prefix="/api")
app.include_router(comments.router, prefix="/api")
app.include_router(llm.router, prefix="/api")
app.include_router(export.router, prefix="/api")
app.include_router(templates.router, prefix="/api")
app.include_router(tags.router, prefix="/api")
app.include_router(audit.router, prefix="/api")
app.include_router(scenarios.router, prefix="/api")
app.include_router(kill_chains.router, prefix="/api")
app.include_router(threat_models.router, prefix="/api")
app.include_router(ai_chat.router, prefix="/api")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}


# Serve frontend static files in production
frontend_dist = Path(__file__).parent.parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
