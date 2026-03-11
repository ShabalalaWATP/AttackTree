# OCP

OCP is an offline-first cyber operations planning platform for building attack trees, scenarios, threat models, kill chains, and infrastructure maps inside isolated user workspaces. It supports fully manual workflows, optional AI assistance through OpenAI-compatible providers, local SQLite storage by default, and authenticated multi-user access.

## What the App Does

- Builds and edits attack trees with risk scoring, mitigations, detections, references, tags, snapshots, and comments
- Supports two workspace modes:
  - `Project Scan` for persistent engagements, targets, products, or clients
  - `Standalone Scan` for ad hoc research and one-off analysis
- Provides AI-assisted tools for:
  - attack-tree generation and expansion
  - brainstorming
  - scenario design
  - infrastructure mapping
  - kill-chain analysis
  - threat modeling
- Includes environment catalogs and starter templates for enterprise, software, industrial, telecoms, energy, transport, and defence-oriented contexts
- Exports planning data to JSON, Markdown, CSV, and PDF where supported
- Isolates projects, standalone work, provider configuration, scenarios, and maps per authenticated user

## Architecture

### High-Level Stack

- Frontend: React 18, TypeScript, Vite, Zustand, TanStack Query, Radix UI, Tailwind CSS
- Backend: FastAPI, Pydantic v2, SQLAlchemy async
- Database: SQLite by default
- AI integration: server-side OpenAI-compatible chat completions client

### Runtime Layout

- The frontend runs as a browser SPA during development on `http://localhost:5173`
- The backend API runs on `http://localhost:8001` during development
- In Docker, FastAPI serves the bundled frontend and the app is exposed on `http://localhost:8001`

### Backend Responsibilities

- Authentication, authorization, and per-user data isolation
- CRUD APIs for projects, nodes, scenarios, infra maps, threat models, kill chains, references, tags, and snapshots
- Risk calculation and export/import logic
- AI provider management, provider health checks, and server-side request proxying
- Prompt construction, environment matching, template selection, and staged AI workflows

### Frontend Responsibilities

- Workspace creation and switching
- Visual editing for attack trees and supporting artifacts
- Tool-specific views for planning, simulation, mapping, and modeling
- Session state, tool navigation, dialogs, reporting actions, and provider management

### Repository Layout

```text
backend/
  app/
    api/              FastAPI routers
    models/           SQLAlchemy models
    schemas/          Pydantic request/response schemas
    services/         auth, LLM, export, risk, environment catalog logic
    reference_data/   bundled reference content
    templates_data/   bundled project templates
frontend/
  src/
    components/       reusable UI building blocks
    stores/           Zustand app state
    utils/            API client, presets, helpers
    views/            main planner screens
Dockerfile
docker-compose.yml
start-dev.bat
README.md
```

## Requirements

- Python 3.12+
- Node.js 20+
- npm

## Local Setup

### Windows

1. Clone the repository and open a PowerShell session in the repo root.
2. Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

3. Install backend dependencies:

```powershell
pip install -r backend\requirements.txt
```

4. Install frontend dependencies:

```powershell
cd frontend
npm install
cd ..
```

5. Start the app:

Option A: use the launcher

```powershell
.\start-dev.bat
```

Option B: run backend and frontend manually

```powershell
python -m uvicorn backend.app.main:app --reload --port 8001
```

Open a second terminal:

```powershell
cd frontend
npm run dev
```

6. Open `http://localhost:5173`

### Linux

1. Clone the repository and open a shell in the repo root.
2. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

3. Install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

4. Install frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

5. Start the backend:

```bash
python -m uvicorn backend.app.main:app --reload --port 8001
```

6. Start the frontend in a second terminal:

```bash
cd frontend
npm run dev
```

7. Open `http://localhost:5173`

## Docker Setup

Build and run the containerized app:

```bash
docker compose up --build
```

The app is then available at `http://localhost:8001`

Docker uses:

- `./data` for the SQLite database
- `./uploads` for generated artifacts and uploads

## Configuration

Primary environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `ATB_DATABASE_URL` | `sqlite+aiosqlite:///./attacktree.db` | Application database |
| `ATB_SECRET_KEY` | `change-me-in-production-use-a-real-secret` | Secret material for auth and encryption helpers |
| `ATB_CORS_ORIGINS` | `["http://localhost:5173","http://localhost:3000"]` | Allowed browser origins |
| `ATB_LOG_LEVEL` | `INFO` | Backend log verbosity |

For Docker, the compose file sets the database path to `sqlite+aiosqlite:///./data/attacktree.db`.

## Authentication

The app is login-gated. The initial database seeds placeholder local accounts for evaluation.

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

For real use:

- rotate or remove the placeholder credentials
- set a strong `ATB_SECRET_KEY`
- use a persistent data volume or external database strategy appropriate for the deployment

## AI Provider Setup

AI features are optional. The app remains usable without a configured provider.

To enable AI:

1. Sign in
2. Open provider settings
3. Add an OpenAI-compatible endpoint
4. Set the base URL, model, and optional API key
5. Test the connection
6. Mark the provider active

Provider settings are stored server-side and isolated per user.

## How to Use the App

### 1. Create or Open a Workspace

- Use `Project Scan` when the work belongs to a named target, product, environment, client, or operation
- Use `Standalone Scan` for exploratory work, reference building, or independent modeling

Each workspace becomes the shared context for the planning tools.

### 2. Build the Core Attack Tree

The attack tree is the central planning surface.

Use it to:

- define objectives and sub-goals
- model preconditions, attack steps, assumptions, assets, trust boundaries, weaknesses, mitigations, and detections
- score likelihood, impact, effort, exploitability, detectability, confidence, and residual risk
- add evidence, tags, mappings, comments, and analyst notes
- snapshot the tree over time

### 3. Use Supporting Planning Tools

#### Brainstorm

Use Brainstorm to generate hypotheses, attack ideas, analyst questions, pivot directions, and technical deep dives based on the active workspace context.

#### Scenarios

Use Scenarios to define concrete operational situations, assumptions, degraded controls, tempo, access conditions, and AI-assisted planning narratives.

#### Infra Map

Use Infra Map to model the environment as a hierarchical dependency map.

- Generate maps with AI or build them manually
- Switch between tree and mind-map layouts
- Search branches and edit node details
- In mind-map mode, use the mouse wheel to zoom, drag the canvas to pan, and drag nodes to persist custom positions

#### Kill Chain

Use Kill Chain to map campaigns against Cyber Kill Chain, MITRE ATT&CK-oriented, or unified-style phase structures.

- Generate analysis from the workspace
- resume partial AI runs when needed
- review campaign summaries, coverage, break opportunities, weakest links, and recommendations

#### Threat Model

Use Threat Model to build DFDs and generate threats with STRIDE, PASTA, or LINDDUN-oriented workflows.

- generate staged DFDs
- resume incomplete DFD or threat runs
- inspect summaries, highest-risk areas, attack-surface scoring, and deep-dive analysis

#### References

Use References to browse bundled frameworks and environment catalogs for planning anchors and reusable decomposition guides.

#### Dashboard

Use Dashboard for portfolio-level and workspace-level visibility across risk posture, recent activity, counts, and artifact coverage.

### 4. Export or Import Data

Available flows include:

- JSON export/import for workspace portability
- Markdown export for narrative sharing
- CSV export for tabular review
- PDF export where supported

### 5. Manage Users and Roles

Admins can:

- create users
- set or reset passwords
- promote or demote roles
- disable users
- delete users

Regular users only see their own data and providers.

## API and Developer Endpoints

- API docs: `http://localhost:8001/api/docs`
- Health check: `http://localhost:8001/api/health`

## Verification Commands

Backend tests:

```bash
python -m pytest backend/tests/test_api.py -q
```

Frontend production build:

```bash
cd frontend
npm run build
```

## Notes for Deployment

- SQLite is the default storage backend and is suitable for local use, demos, labs, and small-team setups
- For multi-user production use, plan storage, backup, and concurrency strategy explicitly
- The application stores AI provider settings per user and proxies requests from the backend, so browser clients do not call provider APIs directly
