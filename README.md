# AttackTree Builder

A production-quality, offline-first web application for cyber security analysts to model, score, and communicate cyber attack trees.

## What It Does

AttackTree Builder lets analysts decompose an attacker's objective into a hierarchy of sub-goals, attack steps, preconditions, and pivot points connected by AND/OR/SEQUENCE logic. Each node carries rich security metadata — likelihood, impact, effort, exploitability, detectability, ATT&CK/CAPEC/CWE/OWASP mappings, mitigations, detections, tags, and analyst comments.

**Key capabilities:**
- **Visual tree canvas** — drag-and-drop node placement, AND/OR/SEQUENCE indicators, risk colour coding, minimap, zoom/pan
- **Rich metadata inspector** — scoring (simple + advanced), mitigations, detections, reference mappings, comments, analyst notes
- **Risk engine** — transparent formula-based scoring with automatic roll-up through AND/OR logic
- **Tags and filtering** — label nodes with custom tags, filter the tree by node type, tags, or search query
- **Comments** — per-node analyst comments with author tracking and timestamps
- **Audit trail** — full activity log tracking all node, mitigation, detection, comment, and mapping changes
- **Dashboard** — top risks, unmitigated gaps, detection coverage, attacker effort analysis, recent activity feed
- **Reporting** — JSON, CSV, Markdown, PDF export with technical and executive report modes
- **Local LLM assistant** — branch suggestions, mitigation suggestions, mapping suggestions, report drafts via any OpenAI-compatible endpoint
- **Reference browser** — bundled ATT&CK, CAPEC, CWE, OWASP data for offline lookup
- **Starter templates** — 11 pre-built attack trees covering web apps, APIs, Android, enterprise, cloud, data centres, OT/ICS, AI systems, supply chain, and more
- **Version snapshots** — save and restore tree states
- **Undo/redo** — full undo history during editing sessions

## Target Analysis Domains

- Web applications
- APIs / microservices
- Android applications
- Thick client / desktop applications
- Enterprise / Active Directory
- Cloud / IAM / Kubernetes
- Data centres / facilities
- OT / ICS
- Hybrid IT/OT
- AI / LLM / agentic systems
- Supply chain / third party

## Architecture

```
┌─────────────────────────────────────────────┐
│          React SPA (Vite + TypeScript)       │
│  React Flow canvas │ Zustand │ TanStack Query│
└───────────────────┬─────────────────────────┘
                    │ REST API
┌───────────────────┴─────────────────────────┐
│           FastAPI (Python 3.12+)            │
│  CRUD API │ Risk Engine │ LLM Proxy │ Export│
└───────────────────┬─────────────────────────┘
                    │
              SQLite / PostgreSQL
```

- **Frontend:** React 18, TypeScript, Vite, Tailwind CSS, React Flow, Zustand, TanStack Query, Radix UI
- **Backend:** FastAPI, Pydantic v2, SQLAlchemy (async), SQLite (default), ReportLab for PDF
- **LLM:** Server-side proxy to any OpenAI-compatible endpoint. API keys stay server-side.
- **No CDN dependencies at runtime.** All assets bundled locally.

---

## Quick Start

### Prerequisites
- Python 3.12+
- Node.js 20+
- npm

### Option 1: Local Development (two terminals)

```bash
# 1. Clone the repository
git clone https://github.com/ShabalalaWATP/AttackTree.git
cd AttackTree

# 2. Install backend dependencies
cd backend
pip install -r requirements.txt
cd ..

# 3. Install frontend dependencies
cd frontend
npm install
cd ..

# 4. Start backend (terminal 1)
python -m uvicorn backend.app.main:app --reload --port 8000

# 5. Start frontend dev server (terminal 2)
cd frontend
npm run dev
```

Open **http://localhost:5173** in your browser.

> The frontend dev server proxies API calls to `localhost:8000`. Both must be running.

### Option 2: Docker (single command)

```bash
git clone https://github.com/ShabalalaWATP/AttackTree.git
cd AttackTree
docker compose up --build
```

Open **http://localhost:8000**. The Docker build bundles the frontend into the backend, so only one container is needed.

---

## Usage Guide

### 1. Creating a Project

When you first open the app, you'll see the **Projects** screen.

1. Click **New Project**
2. Enter a project name (e.g., "Corporate Network Assessment") and optional description
3. Click **Create** — this takes you to the **Tree Editor**

You can also load a **starter template** by clicking the template icon next to "New Project". Templates provide fully populated attack trees for common scenarios.

### 2. Building an Attack Tree

The **Tree Editor** is the main workspace with a drag-and-drop canvas.

- **Add a root node:** Click the **+ Add Node** button in the toolbar
- **Add child nodes:** Right-click a node and select **Add Child**, or select a node and press **Ctrl+Enter**
- **Move nodes:** Drag nodes to reposition them on the canvas
- **Select a node:** Click on it — the **Inspector Panel** opens on the right
- **Delete a node:** Select it and press **Delete**, or right-click and choose **Delete**
- **Duplicate a node:** Right-click a node and select **Duplicate** to clone it with all metadata

**Node types:**
| Type | Purpose |
|------|---------|
| Goal | The attacker's high-level objective |
| Sub-goal | Intermediate objective |
| Attack Step | A concrete action the attacker takes |
| Precondition | Something that must be true before proceeding |
| Pivot Point | A lateral movement or privilege escalation point |

**Gate types (AND/OR/SEQUENCE):**
- **OR** — attacker needs to succeed at any one child path
- **AND** — attacker must succeed at all child paths
- **SEQUENCE** — same as AND, but in a specific order

### 3. Scoring Nodes

Select a node to open the **Inspector**, then go to the **Scoring** tab.

**Simple mode (default)** — six sliders, each 1–10:
| Metric | What it measures |
|--------|-----------------|
| Likelihood | How probable is this step? |
| Impact | Business damage if successful |
| Effort | Resources the attacker needs |
| Exploitability | How easy to exploit |
| Detectability | How likely defenders detect it |
| Confidence | Analyst certainty in the scores |

**Advanced mode** — toggle at the top of the Scoring tab:
- Probability (0–1)
- Impact (0–10)
- Cost to Attacker (1–10)
- Computed risk displayed automatically

Scores are saved automatically. The tree canvas updates node colours based on risk level:
- **Green** — low risk (0–3)
- **Yellow/Orange** — medium risk (3–7)
- **Red** — high risk (7–10)

### 4. Adding Mitigations

In the **Mitigations** tab of the Inspector:

1. Click **Add Mitigation**
2. Enter a title (e.g., "Deploy WAF"), description, effectiveness (0–100%), status, and optional control reference (e.g., "NIST AC-3")
3. Click **Save**

Mitigations automatically reduce the node's **residual risk** based on the highest effectiveness value among all mitigations on that node.

### 5. Adding Detections

In the **Detections** tab:

1. Click **Add Detection**
2. Enter a title (e.g., "SIEM correlation rule"), description, coverage (0–100%), and data source
3. Click **Save**

Detection coverage feeds into the dashboard analytics.

### 6. Reference Mappings (ATT&CK, CAPEC, CWE, OWASP)

In the **Mappings** tab:

1. Click **Add Mapping**
2. Choose a framework (MITRE ATT&CK, CAPEC, CWE, or OWASP)
3. Browse or search the bundled reference data
4. Select the relevant technique/pattern/weakness
5. The mapping is linked to the node

You can also use the **References** view (sidebar navigation) to browse all reference frameworks independently.

### 7. Tags

Tags let you categorize and filter nodes. In the **Details** tab of the Inspector:

1. Scroll to the **Tags** section
2. Type a tag name or select an existing one from the dropdown
3. Press Enter or click to add it
4. Remove tags by clicking the **x** on any tag chip

Use the **filter toolbar** above the canvas to filter nodes by tags, node type, or free-text search.

### 8. Comments

In the **Comments** tab of the Inspector:

1. Type your comment in the text area
2. Click **Post**
3. Comments show author name, timestamp, and text
4. Delete comments with the trash icon

### 9. AI Assistant (Optional)

If you have an OpenAI-compatible LLM endpoint (Ollama, LM Studio, etc.):

1. Go to **Settings** (gear icon in the sidebar)
2. Enter your LLM endpoint URL (e.g., `http://localhost:11434/v1`)
3. Select a model name
4. Optionally enter an API key (encrypted at rest)
5. Click **Save**

Then, select any node and click the **AI** button to get suggestions for:
- Child attack branches
- Mitigations and detections
- Framework mappings (ATT&CK, CAPEC, CWE, OWASP)
- Report drafts

All suggestions are presented for review — nothing is auto-applied.

### 10. Dashboard

Click the **Dashboard** icon in the sidebar to see analytics for the current project:

- **Top Risks** — highest-risk nodes in the tree
- **Unmitigated Nodes** — nodes with no mitigations applied
- **Detection Coverage** — percentage of nodes with detection strategies
- **Attacker Effort Analysis** — effort distribution across the tree
- **Recent Activity** — audit trail of all changes (node edits, mitigations added, comments posted, etc.)

### 11. Exporting Reports

From the tree editor toolbar, click the **Export** button:

| Format | Description |
|--------|-------------|
| JSON | Full tree data for integration with other tools |
| CSV | Flat table of all nodes and scores |
| Markdown | Human-readable report |
| PDF (Technical) | Detailed report with all scoring data |
| PDF (Executive) | High-level summary for management |
| PNG / SVG | Visual image of the tree canvas |

### 12. Version Snapshots

Save the current state of your tree as a named snapshot:

1. Click the **Snapshot** button in the toolbar
2. Give it a name (e.g., "Before mitigation review")
3. Restore any previous snapshot from the snapshots list

---

## Project Structure

```
AttackTree/
├── backend/
│   ├── app/
│   │   ├── api/              # FastAPI route handlers
│   │   ├── models/           # SQLAlchemy database models
│   │   ├── schemas/          # Pydantic request/response schemas
│   │   ├── services/         # Business logic (risk engine, LLM, export, audit)
│   │   ├── reference_data/   # Bundled ATT&CK, CAPEC, CWE, OWASP JSON
│   │   ├── templates_data/   # Starter attack tree templates
│   │   ├── config.py         # Application configuration
│   │   ├── database.py       # Database engine and session
│   │   └── main.py           # FastAPI application entry point
│   ├── tests/                # Backend test suite (pytest)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/       # React components (tree node, inspector, AI panel, audit log)
│   │   ├── views/            # Page-level views (projects, tree editor, dashboard, references)
│   │   ├── stores/           # Zustand state management
│   │   ├── types/            # TypeScript type definitions
│   │   └── utils/            # API client, utilities
│   ├── package.json
│   └── vite.config.ts
├── Dockerfile                # Multi-stage build (Node + Python)
├── docker-compose.yml        # Single-command deployment
├── .gitignore
└── README.md
```

## Scoring Model

### Simple Mode (default)
Scales of 1–10 for: Likelihood, Impact, Effort, Exploitability, Detectability, Confidence.

**Risk formula:**
```
inherent_risk = (Likelihood × Impact × Exploitability) / (Effort × Detectability)
→ normalised to 0–10
```

**Residual risk:**
```
residual_risk = inherent_risk × (1 - max_mitigation_effectiveness)
```

### Advanced Mode
Uses probability (0–1), impact (0–10), and cost to attacker (1–10):
```
risk = probability × impact × (10 / max(cost, 1))
→ normalised to 0–10
```

### Roll-up Logic
- **OR node:** Risk = max(child risks) — any path suffices for attacker
- **AND node:** Risk = average(child risks) — all required
- **SEQUENCE:** Same as AND with ordering constraint displayed

All formulas are visible and inspectable in the UI.

## LLM Integration

The backend acts as a secure proxy to any OpenAI API-compatible endpoint.

**Supported endpoints:** Ollama, LM Studio, vLLM, text-generation-webui, LocalAI, or any service implementing `/v1/chat/completions`.

**Security model:**
- API keys encrypted at rest (Fernet symmetric encryption)
- Keys never sent to the browser
- Custom CA bundles supported for internal PKI
- Optional mutual TLS (client cert + key)
- TLS verification enabled by default
- All LLM requests made server-side

**The application remains fully functional without an LLM endpoint.**

## API Documentation

When the backend is running, visit **http://localhost:8000/api/docs** for interactive Swagger/OpenAPI documentation of all endpoints.

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| Ctrl+Z | Undo |
| Ctrl+Y | Redo |
| Ctrl+Enter | Add child node to selected |
| Delete | Delete selected node |

## Environment Variables

All variables use the `ATB_` prefix.

| Variable | Default | Description |
|----------|---------|-------------|
| `ATB_DATABASE_URL` | `sqlite+aiosqlite:///./attacktree.db` | Database connection string |
| `ATB_SECRET_KEY` | `change-me-in-production` | Secret key for API key encryption |
| `ATB_CORS_ORIGINS` | `["http://localhost:5173"]` | Allowed CORS origins (JSON array) |
| `ATB_LOG_LEVEL` | `INFO` | Logging level |

For Docker, set these in `docker-compose.yml` or pass via environment.

## Offline / Air-Gapped Deployment

This application is designed for restricted environments:

- **No runtime CDN dependencies** — all frontend assets bundled at build time
- **No external fonts, scripts, or analytics**
- **No telemetry**
- **Local reference data** — ATT&CK, CAPEC, CWE, OWASP shipped as JSON
- **Local PDF generation** — ReportLab, no cloud services
- **Local storage** — SQLite, no cloud database required
- **LLM optional** — all features work without an LLM endpoint

**For air-gapped builds:**
1. On a connected machine, run `npm ci` and `pip download -r requirements.txt -d ./wheels`
2. Transfer the project (with `node_modules` and `wheels`) to the air-gapped system
3. Install Python deps: `pip install --no-index --find-links ./wheels -r requirements.txt`
4. Build frontend: `cd frontend && npx vite build`
5. Run: `python -m uvicorn backend.app.main:app --port 8000`

## Templates Included

| Template | Context |
|----------|---------|
| Web Application Compromise to Data Exfiltration | Web app |
| API Authentication Abuse and Backend Pivot | API |
| Android App Reverse Engineering to API Abuse | Android |
| Thick Client Tampering and Backend Abuse | Desktop |
| Enterprise Phishing to Domain Compromise | Enterprise |
| Cloud IAM Abuse | Cloud |
| Data Centre Disruption | Data centre |
| OT Process Manipulation | OT/ICS |
| Ransomware Intrusion Chain | Enterprise |
| AI/LLM Pipeline Compromise | AI |
| Supply Chain Compromise | Supply chain |

## Running Tests

```bash
# Backend tests
cd AttackTree
python -m pytest backend/tests --tb=short

# Frontend type check
cd frontend
npx tsc --noEmit
```

## Trade-offs and Future Work

### Current trade-offs
- **SQLite** is the default database — simple, zero-config, good for single-user. Schema is PostgreSQL-compatible for future multi-user deployment.
- **No authentication** in MVP — designed for single-user local mode. The architecture supports adding auth later.
- **Reference data is a curated subset** — not the full ATT&CK/CAPEC/CWE databases. Import from full datasets supported.
- **PNG/SVG export** uses html-to-image — quality depends on the browser renderer.

### Future work
- Version comparison/diffing between snapshots
- Attachment/evidence repository per node
- Reference pack import from full STIX/ATT&CK bundles
- Monte Carlo simulation for probabilistic risk analysis
- Multi-user mode with PostgreSQL and role-based access
- Real-time collaboration
- Integration API for vulnerability management platforms

## License

MIT
