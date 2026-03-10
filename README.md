# OCP - Offensive Cyber Planner

OCP is an offline-first cyber operations planning platform built around attack trees, workspace-based analysis, and optional AI assistance. The current app is login-gated, multi-user aware, and organized around two workspace modes:

- `Standalone Scan`: an ad hoc workspace for one-off research, exploratory planning, and rapid assessment
- `Project Scan`: a persistent workspace for a client, product, campaign, or engagement

Every major analysis surface now works inside that workspace model: Attack Tree, Brainstorm, Scenarios, Kill Chain, Threat Model, Infra Map, and Dashboard.

## Current State

The app is no longer a single-user MVP. The checked-in build currently includes:

- Login, signup, and session-gated UI
- Admin/user role model with in-app user management
- Per-user data isolation for workspaces, scenarios, infra maps, provider settings, and tags
- Standalone and project scan workflows across the planner
- Portfolio dashboard when no workspace is open, and workspace-specific analytics when one is open
- Infra Map as a full planning feature, not a placeholder
- Software-focused and reverse-engineering-oriented templates and AI prompt profiles
- Research metadata and vulnerability-card capture directly on attack-tree nodes

## Major Capabilities

### Workspace Model

- Create either a `Standalone Scan` or `Project Scan`
- Launch the same toolset from either workspace type
- Keep portfolio-level visibility from the global dashboard
- Import/export workspaces through JSON, plus Markdown, PDF, and CSV reporting where applicable

### Attack Tree

- Visual attack-tree editor with AND, OR, and SEQUENCE logic
- Rich node metadata for scoring, mitigations, detections, mappings, comments, tags, and analyst notes
- Risk roll-up through the tree with inherent and residual scoring
- Snapshot support and local undo/redo
- AI branch, mitigation, detection, and mapping suggestions
- Full AI agent flow to generate a tree from a high-level objective

### Brainstorm

- Workspace-aware AI brainstorming, not just generic chat
- Focus modes and context injection from the active workspace
- Deep-technical output options for software research and vulnerability work
- Better software research framing for reverse engineering and investigation tasks

### Scenarios

- Broader scenario coverage for cyber operations planning
- Standalone planning libraries or project-linked operational scenarios
- Adversary, access, tempo, stealth, and objective framing
- Control disablement and detection degradation modeling
- AI planning briefs and scenario suggestion generation

### Kill Chain

- MITRE ATT&CK, Cyber Kill Chain, and Unified-style campaign analysis
- AI generation and AI mapping from the current workspace context
- Detection windows, dwell time, break opportunities, coverage notes, and recommendations
- Hardened against malformed or partial generated payloads

### Threat Model

- STRIDE, PASTA, and LINDDUN workflows
- AI-generated DFDs, threats, summaries, and tree-linking
- Threat matrix and component-level summaries
- Hardened normalization for generated/imported threat-model payloads

### Infra Map

- Works in standalone and project workspaces
- AI generation and node expansion
- Tree and mind-map layouts
- Search, filter, coverage metrics, and node detail editing
- Better validation and normalization on the backend and frontend

### Dashboard

- Portfolio view across all of a user's workspaces
- Workspace-scoped view when a workspace is open
- Risk posture, coverage, artifact counts, top risks, recent activity, and workspace context stats
- Defensive normalization so legacy or incomplete records do not crash the view

### Software Research and Vulnerability Analysis

- Bundled templates for software reverse engineering, patch diffing, updater abuse, parser memory corruption, and embedded firmware research
- Deep-technical AI prompt profiles for software-specific analysis
- Research fields on nodes for investigation summaries, prompt profile, and research domain
- Structured vulnerability cards for team findings
- CVE and investigation context preserved through import/export

### User Management and Auth

- Login with username or email
- Self-signup with name, email, username, and password
- Admins can:
  - create users
  - promote or demote roles
  - disable users
  - reset passwords
  - delete users
- Each user has isolated provider settings and workspace data
- Main planner UI stays hidden until authentication succeeds

## Bootstrap Accounts

On first startup the app seeds placeholder users for local evaluation. Rotate or delete them before exposing the app beyond a trusted environment.

| Role | Username | Password |
|---|---|---|
| admin | `admin12345` | `admin12345` |
| admin | `administrator` | `AdminPass!234` |
| user | `alice` | `ChangeMe!101` |
| user | `bob` | `ChangeMe!102` |
| user | `carol` | `ChangeMe!103` |
| user | `dan` | `ChangeMe!104` |
| user | `erin` | `ChangeMe!105` |

Login also accepts the seeded emails under `@attacktree.local`.

## Architecture

Current high-level stack:

- Frontend: React 18, TypeScript, Vite 6, Zustand, TanStack Query, Radix UI, Tailwind CSS
- Backend: FastAPI, Pydantic v2, SQLAlchemy async
- Database: SQLite by default
- LLM integration: server-side proxy for OpenAI-compatible APIs

Repository scale in the current tree:

- 18 FastAPI routers
- 16 SQLAlchemy model files
- 58 bundled starter templates

## Key Features by Area

### Analyst Workflow

- Workspace landing and creation flow
- Project home with tool launcher cards and saved work
- Auth-aware top bar and admin dialogs
- Audit trail and references browser

### AI Workflow

- Provider configuration per user
- Server-side provider test flow
- Tree generation, branch suggestions, scenario analysis, brainstorming, kill-chain generation, threat modeling, and advisor-style outputs
- Technical-depth controls for more software-focused output

### Reporting and Data Movement

- Export: JSON, CSV, Markdown, PDF
- Import: JSON workspace import
- Risk recalculation endpoint
- API docs at `/api/docs`

## Running Locally

### Prerequisites

- Python 3.12+
- Node.js 20+
- npm

### Development

Backend:

```bash
cd backend
pip install -r requirements.txt
cd ..
python -m uvicorn backend.app.main:app --reload --port 8001
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173).

The frontend dev server proxies API traffic to the backend on port `8001`.

### Docker

```bash
docker compose up --build
```

Open [http://localhost:8001](http://localhost:8001).

The Docker image builds the frontend and serves it from the FastAPI container.

## Configuration

Primary environment variables:

| Variable | Default | Notes |
|---|---|---|
| `ATB_DATABASE_URL` | `sqlite+aiosqlite:///./attacktree.db` | Default app database |
| `ATB_SECRET_KEY` | `change-me-in-production-use-a-real-secret` | Used for encryption and auth-related secrets |
| `ATB_CORS_ORIGINS` | `["http://localhost:5173","http://localhost:3000"]` | Allowed browser origins |
| `ATB_LOG_LEVEL` | `INFO` | Backend logging level |

Docker compose overrides the database path to `sqlite+aiosqlite:///./data/attacktree.db`.

## LLM Providers

The app supports OpenAI-compatible chat-completions endpoints, including hosted APIs and local model gateways.

- Provider settings are stored per user
- API keys are kept server-side and encrypted at rest
- The app remains usable without configuring an LLM provider

## Current Deployment Notes

- The bundled and tested path is SQLite
- The app now supports isolated multi-user sessions, but the checked-in deployment is still SQLite-backed
- If you are planning sustained concurrent VM use for a larger team, treat database hardening and load validation as part of deployment work, not as already-finished platform work
- Seeded placeholder accounts must be rotated or removed before real use

## Repo Layout

```text
backend/
  app/
    api/          FastAPI routers
    models/       SQLAlchemy models
    schemas/      Pydantic schemas
    services/     Risk, auth, access control, LLM, export logic
    reference_data/
    templates_data/
frontend/
  src/
    components/
    views/
    stores/
    utils/
README.md
Dockerfile
docker-compose.yml
```

## Verification

Useful verification commands:

```bash
python -m pytest backend/tests
cd frontend
npm run lint
npx tsc --noEmit
npx vite build
```

## API Docs

When the backend is running:

- Swagger UI: [http://localhost:8001/api/docs](http://localhost:8001/api/docs)
- ReDoc: [http://localhost:8001/api/redoc](http://localhost:8001/api/redoc)

## Notes

- This repository is designed for offline-first use and bundles local reference data
- The frontend is auth-gated: users do not see planner content until they log in
- The current README reflects the current checked-in application state rather than the earlier single-user MVP design
