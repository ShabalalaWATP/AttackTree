# OCP — Offensive Cyber Planner

A comprehensive, offline-first cyber security platform for modelling, analysing, and documenting attack trees with AI-powered offensive planning tools.

---

## What Is OCP?

OCP lets cyber security analysts decompose an attacker's objective into a hierarchy of sub-goals, attack steps, preconditions, and pivot points connected by AND/OR/SEQUENCE logic. Each node carries rich security metadata — likelihood, impact, effort, exploitability, detectability, ATT&CK/CAPEC/CWE/OWASP mappings, mitigations, detections, tags, and analyst comments.

Beyond tree building, OCP provides a full suite of AI-powered offensive analysis modules — scenario simulation, kill chain analysis, threat modelling, brainstorming, red team advisory, and risk score validation.

---

## Features

### Core Platform
- **Visual Tree Editor** — drag-and-drop canvas with AND/OR/SEQUENCE indicators, risk colour coding, minimap, zoom/pan
- **Rich Node Inspector** — scoring (simple + advanced), mitigations, detections, reference mappings, comments, tags
- **Risk Engine** — transparent formula-based scoring with automatic roll-up through AND/OR logic
- **Project Home** — dedicated landing page when opening a project with tool launcher cards and a saved work table (scenarios, kill chains, threat models, snapshots) sorted newest-first
- **Project Toolbar** — in-project sub-navigation bar for quick switching between Home, Attack Tree, Brainstorm, Scenarios, Kill Chain, Threat Model, and Dashboard
- **Standalone Tools** — all AI modules (Brainstorm, Scenarios, Kill Chain, Threat Model, Dashboard) are fully accessible without an active project for exploratory use
- **Dashboard** — risk posture grade (A–F), defence coverage bars, risk distribution histogram, top risks, unmitigated gaps, attacker effort analysis, node type/status breakdown, audit trail
- **Reference Browser** — bundled MITRE ATT&CK, CAPEC, CWE, OWASP databases for offline lookup
- **Reporting** — JSON, Markdown, PDF (technical + executive), PNG, SVG export
- **Templates** — 11 pre-built attack trees (web apps, APIs, Android, enterprise, cloud, data centres, OT/ICS, AI, supply chain, and more)
- **Version Snapshots** — save and restore tree states
- **Undo/Redo** — full undo history during editing sessions
- **Audit Trail** — full activity log tracking all changes
- **Tags & Filtering** — custom tags, node type filters, and free-text search

### AI-Powered Modules (require an LLM provider)
- **AI Assist** — node-level suggestions for child branches, mitigations, detections, reference mappings, and report drafts
- **AI Agent** — auto-generates an entire attack tree from a high-level objective with fully populated risk scores and metadata
- **AI Brainstorming Session** — free-form conversational AI for exploring attack ideas and offensive scenarios
- **Scenario Simulation** — model attacker profiles (Script Kiddie → Nation State), disable security controls, and simulate impact with AI-generated narrative analysis
- **Kill Chain Analysis** — AI maps your tree's nodes to MITRE ATT&CK or Lockheed Martin kill chain phases with campaign summaries, detection windows, and recommendations
- **Threat Modelling** — STRIDE/PASTA/LINDDUN methodology with AI-generated data flow diagrams, threat identification, and one-click link-to-tree conversion
- **Red Team Advisor** — persistent AI advisor panel with full tree context for offensive tradecraft questions
- **Risk Score Challenger** — AI that critically evaluates your risk scores per node and identifies scoring biases

---

## Target Analysis Domains

- Web applications
- APIs / microservices
- Android applications
- Thick client / desktop applications
- Enterprise / Active Directory
- Cloud / IAM / Kubernetes
- Data centres / facilities
- OT / ICS / SCADA
- Hybrid IT/OT
- AI / LLM / agentic systems
- Supply chain / third party

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│              React SPA (Vite + TypeScript)                │
│  React Flow canvas │ Zustand │ TanStack Query │ Radix UI │
└────────────────────────┬─────────────────────────────────┘
                         │ REST API (90 endpoints)
┌────────────────────────┴─────────────────────────────────┐
│                FastAPI (Python 3.12+)                     │
│  16 API Routers │ Risk Engine │ LLM Proxy │ PDF Export   │
└────────────────────────┬─────────────────────────────────┘
                         │
                    SQLite (async)
```

### Frontend Stack
| Technology | Purpose |
|-----------|---------|
| React 18 + TypeScript | UI framework |
| Vite 6 | Build tool with HMR |
| React Flow (@xyflow/react) | Interactive tree canvas |
| Zustand | State management |
| TanStack Query | Server state & caching |
| Radix UI | Accessible UI primitives |
| Tailwind CSS | Utility-first styling |
| Lucide React | Icons |

### Backend Stack
| Technology | Purpose |
|-----------|---------|
| FastAPI | Async REST API framework |
| Pydantic v2 | Request/response validation |
| SQLAlchemy (async) | ORM with async support |
| aiosqlite | Async SQLite driver |
| httpx | Async HTTP client (LLM proxy) |
| cryptography (Fernet) | API key encryption at rest |
| ReportLab | PDF report generation |

### Key Design Decisions
- **No CDN dependencies at runtime** — all assets bundled locally for air-gapped/offline use
- **Server-side LLM proxy** — API keys and secrets never reach the browser
- **Single-container Docker deployment** — frontend built and served by the backend
- **90 REST API endpoints** across 16 routers covering all platform features
- **14 SQLAlchemy models** with full relationship mapping

---

## Project Structure

```
OCP/
├── backend/
│   ├── app/
│   │   ├── api/                # 16 FastAPI routers
│   │   │   ├── projects.py     # Project CRUD
│   │   │   ├── nodes.py        # Node CRUD + tree operations
│   │   │   ├── mitigations.py  # Mitigation management
│   │   │   ├── detections.py   # Detection management
│   │   │   ├── references.py   # Reference mapping CRUD
│   │   │   ├── snapshots.py    # Version snapshot management
│   │   │   ├── comments.py     # Per-node comments
│   │   │   ├── tags.py         # Tag management
│   │   │   ├── audit.py        # Audit trail queries
│   │   │   ├── llm.py          # LLM provider configuration
│   │   │   ├── export.py       # JSON/PDF/Markdown/PNG/SVG export
│   │   │   ├── templates.py    # Starter template loading
│   │   │   ├── scenarios.py    # Scenario simulation
│   │   │   ├── kill_chains.py  # Kill chain analysis
│   │   │   ├── threat_models.py# Threat modelling (STRIDE/PASTA/LINDDUN)
│   │   │   └── ai_chat.py      # AI Brainstorm, Red Team Advisor, Risk Challenger
│   │   ├── models/             # 14 SQLAlchemy ORM models
│   │   ├── schemas/            # Pydantic request/response schemas
│   │   ├── services/           # Business logic
│   │   │   ├── risk_engine.py  # Risk scoring formulas and roll-up
│   │   │   ├── llm_service.py  # LLM proxy (OpenAI-compatible)
│   │   │   ├── export_service.py # Report generation (PDF, Markdown)
│   │   │   ├── crypto.py       # Fernet encryption for API keys
│   │   │   └── audit.py        # Audit event logging
│   │   ├── reference_data/     # Bundled ATT&CK, CAPEC, CWE, OWASP JSON
│   │   ├── templates_data/     # 11 starter attack tree templates
│   │   ├── config.py           # Application configuration
│   │   ├── database.py         # Async database engine and sessions
│   │   └── main.py             # FastAPI app entry point (mounts all routers)
│   ├── tests/                  # Backend test suite (pytest)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/         # React components
│   │   │   ├── AttackTreeNode.tsx        # Custom React Flow node
│   │   │   ├── NodeInspector.tsx         # Right-panel node editor
│   │   │   ├── TopBar.tsx               # Main navigation bar
│   │   │   ├── ProjectToolBar.tsx        # In-project tool switcher
│   │   │   ├── MarkdownContent.tsx       # Shared markdown renderer
│   │   │   ├── AISuggestionsPanel.tsx    # AI Assist panel
│   │   │   ├── AIAgentDialog.tsx         # AI Agent dialog
│   │   │   ├── RedTeamAdvisorPanel.tsx   # Red Team Advisor slide-out
│   │   │   ├── RiskChallengerPanel.tsx   # Risk Score Challenger
│   │   │   ├── AuditLogPanel.tsx         # Audit trail viewer
│   │   │   ├── HelpDialog.tsx            # Comprehensive help guide
│   │   │   ├── KeyboardShortcutsDialog.tsx
│   │   │   ├── ConfirmDialog.tsx
│   │   │   └── ErrorBoundary.tsx
│   │   ├── views/              # Page-level views
│   │   │   ├── ProjectsView.tsx          # Project listing and creation
│   │   │   ├── ProjectHomeView.tsx       # Project landing page (tool cards + saved work)
│   │   │   ├── TreeEditorView.tsx        # Main tree canvas
│   │   │   ├── DashboardView.tsx         # Risk analytics dashboard
│   │   │   ├── ReferencesView.tsx        # Framework browser
│   │   │   ├── SettingsView.tsx          # LLM provider configuration
│   │   │   ├── ScenarioSimulationView.tsx# Scenario simulation
│   │   │   ├── KillChainView.tsx         # Kill chain analysis
│   │   │   ├── ThreatModelView.tsx       # Threat modelling
│   │   │   └── BrainstormView.tsx        # AI brainstorming chat
│   │   ├── stores/useStore.ts  # Zustand state management
│   │   ├── types/index.ts      # TypeScript type definitions
│   │   └── utils/
│   │       ├── api.ts          # REST API client (all 90 endpoints)
│   │       └── cn.ts           # Tailwind class merge utility
│   ├── package.json
│   └── vite.config.ts
├── Dockerfile                  # Multi-stage build (Node + Python)
├── docker-compose.yml          # Single-command deployment
└── README.md
```

---

## Getting Started

### Prerequisites
- **Python 3.12+**
- **Node.js 20+** and npm
- **Git**

### Download from GitHub

```bash
git clone https://github.com/ShabalalaWATP/AttackTree.git
cd AttackTree
```

### Option 1: Local Development (two terminals)

```bash
# Terminal 1 — Backend
cd backend
pip install -r requirements.txt
cd ..
python -m uvicorn backend.app.main:app --reload --port 8001

# Terminal 2 — Frontend
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173** in your browser.

> The frontend dev server proxies API calls to `localhost:8001`. Both must be running.

### Option 2: Docker (single command)

```bash
git clone https://github.com/ShabalalaWATP/AttackTree.git
cd AttackTree
docker compose up --build
```

Open **http://localhost:8001**. The Docker build bundles the frontend into the backend, so only one container is needed.

#### Docker Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ATB_DATABASE_URL` | `sqlite+aiosqlite:///./data/attacktree.db` | Database connection string |
| `ATB_SECRET_KEY` | `change-me-in-production` | Secret key for Fernet encryption |
| `ATB_LOG_LEVEL` | `INFO` | Logging level |

Data is persisted to `./data/` and uploads to `./uploads/` via Docker volumes.

---

## Usage Guide

### 1. Creating a Project

1. Click **+ New Project** on the Projects page
2. Enter a project name (e.g. "Corporate Network Assessment"), description, and root objective
3. Choose a context preset (Web Application, Cloud, Enterprise Network, etc.)
4. Click **Create** — this takes you to the **Project Home** page

You can also load a **starter template** by clicking the template button. 11 templates are available covering: Web App Compromise, API Auth Abuse, Ransomware Intrusion, Supply Chain Compromise, Cloud IAM Abuse, Enterprise Phishing, Android Reverse Engineering, OT Process Manipulation, Data Centre Disruption, Thick Client Tampering, and AI Pipeline Compromise.

### 2. Project Home

After opening a project, the **Project Home** page provides:

- **Project overview** — name, root objective, and node count
- **Tool launcher** — cards for each module (Attack Tree, Brainstorm, Scenarios, Kill Chain, Threat Model, Dashboard) with one-click navigation
- **Saved work table** — all scenarios, kill chains, threat models, and snapshots sorted newest-first with relative timestamps

The **Project Toolbar** appears below the main navigation whenever a project is open, providing tabs for Home, Attack Tree, Brainstorm, Scenarios, Kill Chain, Threat Model, and Dashboard.

### 3. Building an Attack Tree

The **Tree Editor** is the main workspace with a drag-and-drop canvas.

- **Add a root node:** Click the **+ Add Root Goal** button in the toolbar
- **Add child nodes:** Select a node and press **Ctrl+Enter**, or click **Add Child**
- **Move nodes:** Drag nodes to reposition them on the canvas
- **Re-parent nodes:** Drag from one node's handle to another
- **Select a node:** Click on it — the **Node Inspector** opens on the right
- **Delete a node:** Select it and press **Delete**

**Node types:**
| Type | Purpose |
|------|---------|
| Goal | The attacker's high-level objective |
| Sub-Goal | Intermediate objective |
| Attack Step | A concrete action the attacker takes |
| Precondition | Something that must be true before proceeding |
| Weakness | A vulnerability or weakness exploited |
| Pivot Point | A lateral movement or privilege escalation point |

**Gate types:**
| Gate | Logic |
|------|-------|
| OR | Attacker needs to succeed at any one child path |
| AND | Attacker must succeed at all child paths |
| SEQUENCE | Same as AND, but in a specific order |

### 4. Node Inspector

Click any node to open the six-tab inspector on the right:

| Tab | Function |
|-----|----------|
| **Details** | Title, type, description, platform, access requirements, skill level, threat category |
| **Scoring** | Likelihood, impact, effort, exploitability, detectability (1–10). Advanced mode: probability (0–1), impact (0–10), cost to attacker (1–10). **AI Challenge My Scores** button for AI validation. |
| **Mitigations** | Security controls with effectiveness (0–100%), status, and control references |
| **Detections** | Detection strategies with coverage (0–100%) and data sources |
| **Mappings** | Link to MITRE ATT&CK techniques, CAPEC patterns, CWE weaknesses, OWASP categories |
| **Comments** | Per-node discussion with author tracking and timestamps |

### 5. AI Assist

Select a node in the tree, then click the **AI Assist** sparkles icon in the toolbar:

- **Branches** — suggests 3–6 child attack steps
- **Mitigations** — suggests security controls and defences
- **Detections** — suggests detection opportunities and data sources
- **Mappings** — suggests framework references (ATT&CK, CAPEC, CWE, OWASP)
- **Technical/Executive Summary** — generates report drafts

Click the checkmark on any suggestion to accept it.

### 6. AI Agent Mode

Auto-generate an **entire attack tree** from a high-level objective:

1. Open a project and click the **AI Agent** button (robot icon) in the tree toolbar
2. Pick a **Quick Preset** or write a custom objective
3. Describe the target scope and adjust depth/breadth sliders
4. Click **Generate Attack Tree**
5. The agent creates all nodes with populated risk scores, platforms, access requirements, skill levels, and threat categories

### 7. AI Brainstorming Session

Navigate to **Brainstorm** in the top bar for a free-form conversational AI session:

- Ask about attack vectors, TTPs, real-world breach patterns, or gap analysis
- The AI has context of your current project and root objective
- Use insights to inform what branches to add to your tree

### 8. Scenario Simulation

Navigate to **Scenarios** to model what-if attacker scenarios:

1. Create a scenario with an attacker profile (type, skill, resources, motivation)
2. Toggle off specific security controls (mitigations) to simulate control failure
3. Click **Simulate** to recalculate risk scores
4. Click **AI Analyze** for a narrative impact assessment with recommendations
5. Use **AI Generate Scenarios** to auto-create realistic scenarios from your tree

### 9. Kill Chain Analysis

Navigate to **Kill Chain** to map your tree to campaign phases:

1. Create or AI-generate a kill chain (MITRE ATT&CK or Lockheed Martin framework)
2. AI maps each tree node to the appropriate phase
3. View detection windows, dwell times, and break opportunities per phase
4. Review campaign summary, weakest links, and prioritised recommendations

### 10. Threat Modelling

Navigate to **Threat Model** for formal threat analysis:

1. Create a threat model with a system description and methodology (STRIDE, PASTA, or LINDDUN)
2. **AI Generate DFD** — creates a Data Flow Diagram showing processes, data stores, external entities, and trust boundaries
3. **AI Generate Threats** — identifies threats using the chosen methodology
4. **Link to Tree** — converts threats into attack tree nodes
5. **AI Full Analysis** — one-click end-to-end: DFD generation + threat identification

### 11. Red Team Advisor

Click the **Swords** icon in the top-right toolbar (available when a project is open):

- A slide-out AI panel with full context of your project and tree
- Ask questions about offensive tradecraft, missing attack paths, detection gaps, or real-world breach parallels
- Persistent conversation within the session

### 12. Risk Score Challenger

In the **Scoring** tab of the Node Inspector, click **AI Challenge My Scores**:

- The AI analyses your likelihood, impact, effort, exploitability, and detectability scores
- Provides a critique with justifications for why scores might be too high or too low
- Considers node type, mitigations, and tree context

### 13. Dashboard

Click **Dashboard** in the top bar to see project-level analytics:

- **Risk Posture Grade** (A–F) with colour-coded badge
- **Quick Stats** — total nodes, average risk, mitigation %, detection %, mapping %, exposed count
- **Defence Coverage** — progress bars for mitigation, detection, and framework mapping
- **Risk Distribution** — 5-band histogram (Low → Critical)
- **Top 10 Risks** — highest-risk nodes with visual bars
- **Unmitigated Risks** — nodes with no mitigations applied
- **Lowest Attacker Effort** — cheapest attack paths
- **Node Types & Status** — breakdowns with bar charts
- **Highest Likelihood Vectors** — most probable attack paths
- **Audit Log** — complete change history

### 14. References Browser

Browse and search the four bundled security frameworks:

| Framework | Content | Filters |
|-----------|---------|---------|
| MITRE ATT&CK | Tactics, techniques, procedures | By tactic |
| CAPEC | Attack patterns | By severity |
| CWE | Weaknesses | By severity |
| OWASP | Web/API/mobile security categories | By category |

Click any reference to expand full details. Use "Add to Node" to map it to a selected node.

### 15. Exporting Reports

From the tree editor toolbar:

| Format | Description |
|--------|-------------|
| JSON | Full tree data for integration with other tools |
| Markdown | Human-readable report |
| PDF | Detailed report with all scoring data |
| PNG / SVG | Visual image of the tree canvas |

Use the **Import** button (upload icon) to load a previously exported JSON file.

### 16. Version Snapshots

Save the current state of your tree:

1. Click the **Save** icon in the toolbar while in the tree editor
2. Snapshots are timestamped automatically
3. Restore any previous snapshot to roll back changes

---

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
- **OR node:** Risk = max(child risks) — any path suffices for the attacker
- **AND node:** Risk = average(child risks) — all paths required
- **SEQUENCE:** Same as AND with ordering constraint

Node colours on the canvas reflect risk level: **green** (0–3), **amber** (3–7), **red** (7–10).

---

## LLM Integration

The backend acts as a secure proxy to any OpenAI API-compatible endpoint.

### Compatible Providers
Any endpoint implementing `/v1/chat/completions`:
- OpenAI (GPT-4o, GPT-4, etc.)
- Ollama (local models)
- LM Studio
- vLLM, text-generation-webui, LocalAI
- Azure OpenAI Service

### Configuration

1. Navigate to **Settings** in the top bar
2. Click **Add Provider**
3. Enter the **Base URL** (e.g. `https://api.openai.com/v1` or `http://localhost:11434/v1`)
4. Paste your **API Key** (optional for local models)
5. Set the **Model** name (e.g. `gpt-4o`, `llama3`, `mistral`)
6. Click **Test** to verify the connection

### Security Model
- API keys encrypted at rest using Fernet symmetric encryption
- Keys never sent to the browser — all LLM calls are server-side
- TLS certificate verification enabled by default
- Custom CA bundles and client certificates supported for internal PKI
- The application is **fully functional without an LLM provider** — AI features are optional

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + Z` | Undo |
| `Ctrl + Y` | Redo |
| `Ctrl + Enter` | Add child node |
| `Delete` | Delete selected node |
| `?` | Show keyboard shortcuts |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## License

This project is provided as-is for security research and education purposes.

## API Documentation

When the backend is running, visit **http://localhost:8001/api/docs** for interactive Swagger/OpenAPI documentation of all endpoints.

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
