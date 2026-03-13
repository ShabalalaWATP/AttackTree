import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.responses import JSONResponse

from .config import settings
from .database import async_session_factory, init_db
from .api import auth, projects, nodes, mitigations, detections, references, snapshots, comments, llm, export, templates, tags, audit, scenarios, kill_chains, threat_models, ai_chat, infra_maps, analysis_runs, dashboard
from .models.user import User
from .services.auth import AuthContext, decode_access_token, reset_auth_context, set_auth_context

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


PUBLIC_API_PATHS = {
    "/api/health",
    "/api/auth/login",
    "/api/auth/signup",
}


@app.middleware("http")
async def authenticate_api_requests(request: Request, call_next):
    path = request.url.path
    if request.method == "OPTIONS" or not path.startswith("/api") or path in PUBLIC_API_PATHS:
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    try:
        payload = decode_access_token(auth_header.split(" ", 1)[1])
    except Exception as exc:  # noqa: BLE001
        detail = getattr(exc, "detail", "Authentication required")
        status_code = getattr(exc, "status_code", 401)
        return JSONResponse(status_code=status_code, content={"detail": detail})

    async with async_session_factory() as session:
        user = await session.get(User, payload.get("sub"))
        if not user or not user.is_active:
            return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    context_token = set_auth_context(
        AuthContext(
            user_id=user.id,
            name=user.name,
            email=user.email,
            role=user.role,
            is_active=user.is_active,
        )
    )
    request.state.user = user
    try:
        return await call_next(request)
    finally:
        reset_auth_context(context_token)

# API routes
app.include_router(auth.router, prefix="/api")
app.include_router(projects.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
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
app.include_router(analysis_runs.router, prefix="/api")
app.include_router(scenarios.router, prefix="/api")
app.include_router(kill_chains.router, prefix="/api")
app.include_router(threat_models.router, prefix="/api")
app.include_router(ai_chat.router, prefix="/api")
app.include_router(infra_maps.router, prefix="/api")


@app.get("/api/health")
async def health():
    return {"status": "ok", "version": settings.APP_VERSION}


# Serve frontend static files in production
frontend_dist = Path(__file__).parent.parent.parent / "frontend" / "dist"
if frontend_dist.exists():
    app.mount("/", StaticFiles(directory=str(frontend_dist), html=True), name="frontend")
