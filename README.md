# OCP

OCP (Offensive Cyber Planner) is a browser-based cyber operations planning platform for building attack trees, scenarios, threat models, kill chains, and infrastructure maps inside isolated user workspaces. It supports fully manual workflows, optional AI assistance through OpenAI-compatible providers, local SQLite storage by default, and authenticated multi-user access. The current deployment model is a web app that runs locally on Windows or Linux for individual use, or as a shared service on a VM for small teams.

The codebase still uses some historical `AttackTree Builder` naming internally, including the `ATB_` environment variable prefix.

## What the App Does

- Opens to an OCP landing page and workspace flow designed around authenticated `Project Scan` and `Standalone Scan` workspaces
- Builds and edits attack trees with risk scoring, mitigations, detections, references, tags, snapshots, comments, critical-path analysis, export, and fullscreen canvas review
- Supports two workspace modes:
  - `Project Scan` for persistent engagements, targets, products, or clients
  - `Standalone Scan` for ad hoc research and one-off analysis
- Provides AI-assisted tools for:
  - attack-tree generation and expansion
  - brainstorming
  - red-team advisory with awareness of the current planning page
  - scenario setup with combined analysis and brief generation
  - infrastructure mapping
  - kill-chain analysis
  - threat modeling and DFD generation
- Includes environment catalogs and starter templates for enterprise, software, industrial, telecoms, energy, transport, and defence-oriented contexts
- Includes a workspace home screen and dashboard for command-style visibility across risk posture, analysis output, and recent activity
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
- In a shared VM deployment, users browse a single URL and authenticate independently; the browser does not call external LLM providers directly
- No packaged `.exe` installer is included in the repository today; the supported deployment path is the web app

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
- Docker and Docker Compose plugin are recommended for shared or VM-based deployments

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

Linux does not currently have a bundled launcher script like `start-dev.bat`; use the manual commands above or Docker.

## Docker Setup

This is the simplest way to run the current app as a single bundled service. FastAPI serves the built frontend and the API from the same container.

Before the first shared deployment, create a `.env` file in the repo root and set at least a real secret:

```bash
ATB_SECRET_KEY=replace-this-with-a-long-random-secret
ATB_LOG_LEVEL=INFO
```

Build and run the containerized app:

```bash
docker compose up -d --build
```

The app is then available at `http://localhost:8001`

Docker uses:

- `./data` for the SQLite database
- `./uploads` for generated artifacts and uploads

For a quick internal lab, you can share `http://<vm-ip>:8001` directly. For anything internet-facing, put the app behind a reverse proxy with HTTPS.

If you are using the bundled frontend from the same origin, you normally do not need to change `ATB_CORS_ORIGINS`.

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

The app is login-gated. A fresh database seeds one local admin account for evaluation:

| Role | Username | Password |
|---|---|---|
| admin | `admin12345` | `admin12345` |

The same account also works with the seeded email `adminaccount@attacktree.local`.

User self-signup is supported, but new accounts are created in a pending state until an admin approves them.

For real use:

- change the seeded admin password immediately
- create named user accounts for real operators
- approve or reject pending signups as part of user administration
- set a strong `ATB_SECRET_KEY`
- use a persistent data volume and backup strategy appropriate for the deployment

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

## Shared VM Deployment

### Recommended Profile for About 30 Concurrent Users

The current packaged deployment can support a shared VM setup where multiple users log in at the same time.

With the current codebase and default SQLite backend, the safest guidance is:

- suitable for roughly up to `~30` light-to-moderate concurrent users on one VM
- appropriate when usage is mixed across browsing, editing, and occasional AI runs
- not ideal if many users are editing heavily at the same time or kicking off lots of long AI jobs simultaneously

For this size of deployment, start with:

- `4-6 vCPU`
- `8-12 GB RAM`
- `60+ GB SSD`
- regular backups for `data/` and `uploads/`

If you expect the upper end of that user range to be active at once, prefer `6 vCPU` and `12 GB RAM`.

SQLite is still the main concurrency limit. If you start seeing lock contention, long write stalls, or sustained heavy shared usage, plan database and deployment changes before scaling further.

### VM Setup Steps

1. Provision a Linux VM and install Docker plus the Docker Compose plugin.
2. Clone the repository onto the VM.
3. Create persistent storage folders:

```bash
mkdir -p data uploads
```

4. Create a long random secret, for example:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(64))"
```

5. Create a `.env` file in the repo root:

```bash
ATB_SECRET_KEY=replace-this-with-a-long-random-secret
ATB_LOG_LEVEL=INFO
```

6. Start the bundled app:

```bash
docker compose up -d --build
```

7. Verify the service locally on the VM:

```bash
curl http://127.0.0.1:8001/api/health
```

8. For an internal-only deployment, allow inbound access to `8001` on the VM firewall and share `http://<vm-ip>:8001`.
9. For a proper shared deployment, put the app behind a reverse proxy and expose `80/443` instead of sharing the raw app port.
10. Sign in with the default admin, rotate that password, and approve real users before wider rollout.

### Reverse Proxy Example (Caddy)

If you have a DNS name such as `ocp.example.com`, use a reverse proxy and terminate HTTPS there.

Example `Caddyfile`:

```text
ocp.example.com {
    reverse_proxy 127.0.0.1:8001
    encode gzip
}
```

If you do this, it is better to bind the app container to localhost only by changing the compose port mapping from:

```yaml
ports:
  - "8001:8000"
```

to:

```yaml
ports:
  - "127.0.0.1:8001:8000"
```

### First-Run Checklist for a Shared Deployment

1. Sign in with the seeded admin account.
2. Change the seeded admin password immediately.
3. Create or approve real user accounts.
4. Confirm the app is reachable from another machine by IP or URL.
5. Configure at least one LLM provider if AI features are needed.
6. Set up backups for `data/` and `uploads/`.
7. Monitor disk usage and response times during the first week of shared use.

### Multi-User Behaviour

- Multiple users can be logged in at the same time.
- Authentication is token-based and each user gets their own session.
- Data is isolated per authenticated user.
- This is not real-time collaborative editing. Two users can open the same workspace, but simultaneous edits to the same artifact are not merged in a collaborative way.
- The recommended deployment for shared access is the bundled FastAPI-served frontend, not the Vite dev server.

## How to Use the App

### 1. Create or Open a Workspace

- Start from the landing page and enter `Workspaces`
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
- review or brief from a fullscreen canvas when needed

### 3. Use Supporting Planning Tools

#### Brainstorm

Use Brainstorm to generate hypotheses, attack ideas, analyst questions, pivot directions, and technical deep dives based on the active workspace context.

#### Red Team Advisor

Use the Red Team Advisor as a persistent tactical assistant. It can see the current page context from the main planning views and responds in the context of the active attack tree, scenario, kill chain, threat model, infra map, dashboard, or workspace home page.

#### Scenarios

Use Scenarios to define concrete operational situations, assumptions, degraded controls, tempo, access conditions, analysis output, and decision briefs.

- complete the setup wizard
- save the setup only, or generate the analysis and brief together
- return later to review or edit setup details while keeping the output in focus

#### Infra Map

Use Infra Map to model the environment as a hierarchical dependency map.

- Generate maps with AI or build them manually
- Switch between tree and mind-map layouts
- Search branches and edit node details
- In mind-map mode, use the mouse wheel to zoom, drag the canvas to pan, and drag nodes to persist custom positions

#### Kill Chain

Use Kill Chain to map campaigns against Cyber Kill Chain, MITRE ATT&CK-oriented, or unified-style phase structures.

- Generate analysis from the workspace
- follow in-progress generation status and wait messaging from the UI
- resume partial AI runs when needed
- review campaign summaries, coverage, break opportunities, weakest links, and recommendations

#### Threat Model

Use Threat Model to build DFDs and generate threats with STRIDE, PASTA, or LINDDUN-oriented workflows.

- generate staged DFDs
- inspect the DFD on a zoomable canvas with fullscreen support
- resume incomplete DFD or threat runs
- inspect summaries, highest-risk areas, attack-surface scoring, and deep-dive analysis

#### References

Use References to browse bundled frameworks and environment catalogs for planning anchors and reusable decomposition guides.

#### Dashboard

Use Dashboard for portfolio-level and workspace-level visibility across risk posture, recent activity, counts, artifact coverage, critical path pressure, and run activity.

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

Frontend lint:

```bash
cd frontend
npm run lint
```

## Notes for Deployment

- SQLite is the default storage backend and is suitable for local use, demos, labs, and small-team shared setups
- A single VM deployment is practical, but SQLite remains the limiting factor for concurrent writes
- Around `30` concurrent logged-in users is a reasonable upper target only when actual write activity is moderate rather than constant
- For heavier sustained shared usage, plan a database and scaling strategy before rollout
- Do not expose the Vite dev server publicly; use the bundled Docker deployment or a backend-served production build
- The app runs on both Windows and Linux, but the repository currently ships a Windows dev launcher only; shared access should use the web deployment path
- Put internet-facing deployments behind a reverse proxy with HTTPS
- Rotate the seeded admin credentials and maintain regular backups of `data/` and `uploads/`
- The application stores AI provider settings per user and proxies requests from the backend, so browser clients do not call provider APIs directly
