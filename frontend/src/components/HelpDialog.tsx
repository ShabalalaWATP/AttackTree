import * as Dialog from '@radix-ui/react-dialog';
import { X, Bot, Sparkles, GitBranch, FolderOpen, LayoutDashboard, BookOpen, Settings, Shield, Keyboard, FlaskConical, Route, ShieldCheck, Brain, Swords, Scale } from 'lucide-react';
import { useState } from 'react';
import { cn } from '@/utils/cn';

const SECTIONS = [
  { id: 'overview', label: 'Overview', icon: <Shield size={14} /> },
  { id: 'projects', label: 'Workspaces', icon: <FolderOpen size={14} /> },
  { id: 'tree-editor', label: 'Tree Editor', icon: <GitBranch size={14} /> },
  { id: 'ai-assist', label: 'AI Assist', icon: <Sparkles size={14} /> },
  { id: 'ai-agent', label: 'AI Agent', icon: <Bot size={14} /> },
  { id: 'brainstorm', label: 'AI Brainstorm', icon: <Brain size={14} /> },
  { id: 'scenarios', label: 'Scenarios', icon: <FlaskConical size={14} /> },
  { id: 'kill-chain', label: 'Kill Chain', icon: <Route size={14} /> },
  { id: 'threat-model', label: 'Threat Model', icon: <ShieldCheck size={14} /> },
  { id: 'red-team', label: 'Red Team Advisor', icon: <Swords size={14} /> },
  { id: 'risk-challenger', label: 'Risk Challenger', icon: <Scale size={14} /> },
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={14} /> },
  { id: 'references', label: 'References', icon: <BookOpen size={14} /> },
  { id: 'settings', label: 'Settings', icon: <Settings size={14} /> },
  { id: 'shortcuts', label: 'Shortcuts', icon: <Keyboard size={14} /> },
] as const;

type SectionId = typeof SECTIONS[number]['id'];

const CONTENT: Record<SectionId, { title: string; content: React.ReactNode }> = {
  overview: {
    title: 'Welcome to Offensive Cyber Planner',
    content: (
      <div className="space-y-3 text-sm">
        <p><strong>OCP (Offensive Cyber Planner)</strong> is a comprehensive cyber security platform for modelling, analysing, and documenting attack trees — structured representations of how an attacker could compromise a target.</p>
        <h4 className="font-semibold mt-4">Key Capabilities</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>Visual Tree Editor</strong> — drag-and-drop canvas to build and organise attack trees with AND/OR/SEQUENCE logic</li>
          <li><strong>Risk Scoring</strong> — likelihood, impact, effort, exploitability, detectability scoring with automatic risk computation and roll-up</li>
          <li><strong>AI Assist</strong> — get AI-powered suggestions for child nodes, mitigations, detections, and reference mappings</li>
          <li><strong>AI Agent</strong> — auto-generate an entire attack tree from a high-level objective</li>
          <li><strong>AI Brainstorm</strong> — free-form conversational AI for exploring attack ideas and scenarios</li>
          <li><strong>Scenario Simulation</strong> — model different attacker profiles and simulate the impact of disabling security controls</li>
          <li><strong>Kill Chain Analysis</strong> — AI-powered mapping of your attack tree to MITRE ATT&CK or Lockheed Martin kill chain phases</li>
          <li><strong>Threat Modelling</strong> — STRIDE/PASTA/LINDDUN methodology with AI-generated data flow diagrams and threat analysis</li>
          <li><strong>Red Team Advisor</strong> — a persistent AI assistant that advises on offensive tradecraft in the context of your project</li>
          <li><strong>Risk Score Challenger</strong> — AI that critiques and validates your risk scores per node</li>
          <li><strong>Reference Browser</strong> — built-in MITRE ATT&CK, CAPEC, CWE, and OWASP databases</li>
          <li><strong>Dashboard</strong> — risk grade, defence coverage, risk distribution, top risks, unmitigated gaps, and audit trail</li>
          <li><strong>Export</strong> — JSON, PDF, Markdown, PNG, SVG export formats</li>
          <li><strong>Templates</strong> — 11 pre-built attack tree templates covering web, cloud, OT, AI, and more</li>
        </ul>
        <h4 className="font-semibold mt-4">Typical Workflow</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Create a workspace (or use a template / AI Agent)</li>
          <li>Build the attack tree in the Tree Editor</li>
          <li>Score nodes and add mitigations/detections</li>
          <li>Use AI tools: Brainstorm, Scenarios, Kill Chain, Threat Model</li>
          <li>Map nodes to MITRE ATT&CK / CAPEC / CWE / OWASP</li>
          <li>Review the Dashboard for risk analysis</li>
          <li>Export reports for stakeholders</li>
        </ol>
      </div>
    ),
  },
  projects: {
    title: 'Workspaces',
    content: (
      <div className="space-y-3 text-sm">
        <p>Workspaces are the top-level containers for your attack trees and analysis runs. Each workspace can be either a standalone scan or a project scan.</p>
        <h4 className="font-semibold">Creating a Workspace</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Click <strong>+ New Workspace</strong> on the Workspaces page</li>
          <li>Enter a name, description, and root objective (attacker's goal)</li>
          <li>Choose a context preset (e.g. Web Application, Cloud, Enterprise Network)</li>
          <li>Select whether the workspace should run as a standalone scan or a project scan</li>
        </ul>
        <h4 className="font-semibold mt-3">Templates</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Click <strong>Templates</strong> to start from a pre-built attack tree</li>
          <li>11 templates available: Web App Compromise, Ransomware Intrusion, Supply Chain, Cloud IAM Abuse, API Auth Abuse, Android Reverse Engineering, Enterprise Phishing, OT Process Manipulation, Data Centre Disruption, Thick Client Tampering, AI Pipeline Compromise</li>
          <li>The template creates a full workspace with pre-populated nodes, scores, and references</li>
        </ul>
        <h4 className="font-semibold mt-3">Import / Export</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Use the <strong>Import</strong> button (upload icon in top bar) to load a JSON export</li>
          <li>Export options: JSON (data), PDF/Markdown (reports), PNG/SVG (images)</li>
        </ul>
      </div>
    ),
  },
  'tree-editor': {
    title: 'Tree Editor',
    content: (
      <div className="space-y-3 text-sm">
        <p>The Tree Editor is the main canvas for building and navigating your attack tree.</p>
        <h4 className="font-semibold">Building the Tree</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Click <strong>Add Root Goal</strong> for an empty tree to create the first node</li>
          <li>Select a node, then click <strong>Add Child</strong> (or press <kbd className="px-1.5 py-0.5 rounded bg-muted text-xs">Ctrl+Enter</kbd>)</li>
          <li><strong>Drag</strong> nodes to reposition them on the canvas</li>
          <li><strong>Connect nodes</strong> by dragging from one node's handle to another to re-parent</li>
          <li>Press <kbd className="px-1.5 py-0.5 rounded bg-muted text-xs">Delete</kbd> to remove the selected node</li>
        </ul>
        <h4 className="font-semibold mt-3">Node Inspector (Right Panel)</h4>
        <p>Click any node to open the inspector with tabs:</p>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>Details</strong> — title, type, description, platform, access requirements, threat category</li>
          <li><strong>Scoring</strong> — likelihood, impact, effort, exploitability, detectability (auto-computes risk). Includes <strong>AI Challenge My Scores</strong> button to get a second opinion.</li>
          <li><strong>Mitigations</strong> — add security controls with effectiveness ratings</li>
          <li><strong>Detections</strong> — add detection strategies with coverage percentage and data sources</li>
          <li><strong>Mappings</strong> — link to MITRE ATT&CK, CAPEC, CWE, OWASP references</li>
          <li><strong>Comments</strong> — discussion and notes per node</li>
        </ul>
        <h4 className="font-semibold mt-3">Node Types</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>Goal</strong> — the attacker's ultimate objective (root node)</li>
          <li><strong>Sub-Goal</strong> — intermediate objectives</li>
          <li><strong>Attack Step</strong> — specific actions the attacker takes</li>
          <li><strong>Precondition</strong> — requirements that must be true</li>
          <li><strong>Weakness</strong> — vulnerabilities or weaknesses exploited</li>
          <li><strong>Pivot Point</strong> — stepping stones for lateral movement</li>
        </ul>
        <h4 className="font-semibold mt-3">Logic Types</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>OR</strong> — any one child path succeeds = parent succeeds</li>
          <li><strong>AND</strong> — all children must succeed for parent to succeed</li>
          <li><strong>SEQUENCE</strong> — children must succeed in order</li>
        </ul>
        <h4 className="font-semibold mt-3">Toolbar</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>Search</strong> — filter visible nodes by text</li>
          <li><strong>Type filter</strong> — show only specific node types</li>
          <li><strong>Tag filter</strong> — filter by tags</li>
          <li><strong>Recalc</strong> — recalculate all risk scores</li>
          <li><strong>PNG / SVG</strong> — export the canvas as an image</li>
        </ul>
      </div>
    ),
  },
  'ai-assist': {
    title: 'AI Assist',
    content: (
      <div className="space-y-3 text-sm">
        <p>AI Assist provides intelligent suggestions for individual nodes. It requires an LLM provider configured in Settings.</p>
        <h4 className="font-semibold">How to Use</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Select a node in the Tree Editor</li>
          <li>Click the <strong>AI Assist</strong> button (sparkles icon) in the toolbar</li>
          <li>Choose a suggestion type from the dropdown</li>
          <li>Click <strong>Suggest</strong> to generate ideas</li>
          <li>Click the <strong>checkmark</strong> on any suggestion to accept it (adds as a child node)</li>
        </ol>
        <h4 className="font-semibold mt-3">Suggestion Types</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>Branches</strong> — suggests 3-6 child attack steps for the selected node</li>
          <li><strong>Mitigations</strong> — suggests security controls and defences</li>
          <li><strong>Detections</strong> — suggests detection opportunities and data sources</li>
          <li><strong>Mappings</strong> — suggests MITRE ATT&CK, CAPEC, CWE, OWASP references</li>
        </ul>
        <h4 className="font-semibold mt-3">Summaries</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>Technical Summary</strong> — generates a detailed analyst report of the tree</li>
          <li><strong>Executive Summary</strong> — generates a management-friendly overview</li>
        </ul>
      </div>
    ),
  },
  'ai-agent': {
    title: 'AI Agent Mode',
    content: (
      <div className="space-y-3 text-sm">
        <p>AI Agent auto-generates an <strong>entire attack tree</strong> from a high-level objective — no manual node creation needed.</p>
        <h4 className="font-semibold">How to Use</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Open a standalone scan or project scan workspace in the Tree Editor</li>
          <li>Click the <strong>AI Agent</strong> button (robot icon) in the toolbar</li>
          <li>Either pick a <strong>Quick Preset</strong> or write your own objective</li>
          <li>Optionally describe the target scope and adjust depth/breadth sliders</li>
          <li>Click <strong>Generate Attack Tree</strong></li>
          <li>The agent generates all nodes with fully populated fields (risk scores, platform, access requirements, skill levels, threat categories)</li>
          <li>For large trees, the agent makes multiple API calls to enrich all fields</li>
          <li>Click <strong>View Tree</strong> to see the result</li>
        </ol>
        <h4 className="font-semibold mt-3">Tips</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Be specific in your objective for more targeted results (e.g. "Compromise the HVAC system of a data centre to cause thermal shutdown" vs "Attack a data centre")</li>
          <li>Use the scope field to describe the target environment in detail</li>
          <li>Depth 3-5 with breadth 4-6 gives good results without excessive token usage</li>
          <li>After generation, use AI Assist on individual nodes to drill deeper</li>
          <li>Review and adjust the AI-generated scores — they're starting estimates, not gospel</li>
        </ul>
      </div>
    ),
  },
  brainstorm: {
    title: 'AI Brainstorming Session',
    content: (
      <div className="space-y-3 text-sm">
        <p>An interactive, conversational AI session for <strong>free-form attack ideation</strong>. Think of it as a brainstorming partner with offensive security expertise.</p>
        <h4 className="font-semibold">How to Use</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Navigate to <strong>Brainstorm</strong> in the top bar</li>
          <li>Select an LLM provider from the dropdown</li>
          <li>Type a question or idea — e.g. "What are the most overlooked attack vectors against Kubernetes clusters?"</li>
          <li>The AI responds with structured attack ideas, techniques, and considerations</li>
          <li>Continue the conversation to explore ideas deeper</li>
        </ol>
        <h4 className="font-semibold mt-3">Context Awareness</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>If you have a project open, the AI automatically knows the <strong>project name</strong> and <strong>root objective</strong></li>
          <li>Use this to brainstorm ideas specifically relevant to your current project</li>
          <li>Click the <strong>trash</strong> icon to clear the conversation and start fresh</li>
        </ul>
        <h4 className="font-semibold mt-3">Conversation Tips</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Ask about attack vectors, TTPs, real-world breach patterns, or defence gap analysis</li>
          <li>Follow up on responses to drill into specific techniques</li>
          <li>Use the output to inform what nodes/branches to add to your tree</li>
        </ul>
      </div>
    ),
  },
  scenarios: {
    title: 'Scenario Simulation',
    content: (
      <div className="space-y-3 text-sm">
        <p>Model <strong>what-if scenarios</strong> by defining attacker profiles and simulating the impact of disabling specific security controls.</p>
        <h4 className="font-semibold">How to Use</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Navigate to <strong>Scenarios</strong> in the top bar</li>
          <li>Click <strong>+ New Scenario</strong> to create one</li>
          <li>Define the <strong>attacker profile</strong>: type (Script Kiddie → Nation State), skill level, resources, and motivation</li>
          <li>Toggle off <strong>security controls</strong> (mitigations) to model a "what if this fails?" scenario</li>
          <li>Add <strong>assumptions</strong> describing the scenario context</li>
          <li>Click <strong>Simulate</strong> to recalculate risk scores with the modified controls</li>
          <li>Click <strong>AI Analyze</strong> for an AI-generated narrative, impact summary, and recommendations</li>
        </ol>
        <h4 className="font-semibold mt-3">AI Auto-Generate</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Click <strong>AI Generate Scenarios</strong> to have the AI automatically create realistic attacker scenarios based on your tree</li>
          <li>Each generated scenario includes a full attacker profile and relevant control toggle settings</li>
        </ul>
        <h4 className="font-semibold mt-3">Use Cases</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Model the impact of a specific security control failing</li>
          <li>Compare attack surfaces for different attacker capability levels</li>
          <li>Justify security investment by showing risk delta with/without controls</li>
          <li>Prepare tabletop exercises with realistic scenarios</li>
        </ul>
      </div>
    ),
  },
  'kill-chain': {
    title: 'Kill Chain Analysis',
    content: (
      <div className="space-y-3 text-sm">
        <p>Map your attack tree nodes to <strong>kill chain phases</strong> to understand the full campaign timeline from initial access to objective completion.</p>
        <h4 className="font-semibold">How to Use</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Navigate to <strong>Kill Chain</strong> in the top bar</li>
          <li>Click <strong>+ New Kill Chain</strong> to create one manually, or use <strong>AI Generate</strong></li>
          <li>Choose a framework: <strong>MITRE ATT&CK</strong> or <strong>Lockheed Martin Kill Chain</strong></li>
          <li>Once created, click <strong>AI Map</strong> to have the AI assign your tree's nodes to kill chain phases</li>
        </ol>
        <h4 className="font-semibold mt-3">AI Features</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>AI Generate</strong> — creates a complete kill chain and maps all nodes in one step</li>
          <li><strong>AI Map</strong> — maps nodes to phases on an existing kill chain</li>
          <li>Each phase shows mapped nodes, detection windows, dwell time estimates, and break opportunities</li>
          <li>The AI produces a campaign summary and prioritised recommendations</li>
        </ul>
        <h4 className="font-semibold mt-3">What You Get</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Phase-by-phase breakdown with descriptions and difficulty ratings</li>
          <li>Total estimated campaign time</li>
          <li>Weakest defensive links</li>
          <li>Prioritised security recommendations (critical / high / medium / low)</li>
        </ul>
      </div>
    ),
  },
  'threat-model': {
    title: 'Threat Modelling',
    content: (
      <div className="space-y-3 text-sm">
        <p>Formal threat modelling using established methodologies (STRIDE, PASTA, LINDDUN) with optional AI automation for data flow diagrams and threat identification.</p>
        <h4 className="font-semibold">How to Use</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Navigate to <strong>Threat Model</strong> in the top bar</li>
          <li>Click <strong>+ New Threat Model</strong> to create one manually</li>
          <li>Enter a name, system description, and choose a <strong>methodology</strong> (STRIDE, PASTA, or LINDDUN)</li>
        </ol>
        <h4 className="font-semibold mt-3">AI Features</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>AI Generate DFD</strong> — generates a Data Flow Diagram (rendered on a canvas) showing processes, data stores, external entities, and trust boundaries</li>
          <li><strong>AI Generate Threats</strong> — identifies threats based on your tree's attack paths and applies the chosen methodology</li>
          <li><strong>Link to Tree</strong> — converts identified threats into new attack tree nodes so they appear in your main tree</li>
          <li><strong>AI Full Analysis</strong> — one-click: creates a threat model, generates the DFD, and identifies all threats in a single operation</li>
        </ul>
        <h4 className="font-semibold mt-3">Threat Details</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Each threat includes: category, description, severity, affected component, and recommended countermeasures</li>
          <li>Threats are organised by the selected methodology's taxonomy (e.g. STRIDE: Spoofing, Tampering, Repudiation, etc.)</li>
          <li>Use the tabs to switch between the <strong>DFD canvas</strong> and the <strong>threats list</strong></li>
        </ul>
      </div>
    ),
  },
  'red-team': {
    title: 'Red Team Advisor',
    content: (
      <div className="space-y-3 text-sm">
        <p>A persistent <strong>AI assistant panel</strong> that acts as a red team operator, providing tactical offensive advice in the context of your current project and tree.</p>
        <h4 className="font-semibold">How to Use</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Click the <strong>Swords</strong> icon in the top-right toolbar (available when a project is open)</li>
          <li>The advisor panel slides in from the right</li>
          <li>Ask questions about offensive tradecraft, attack techniques, or how to improve your tree</li>
          <li>The AI has full context of your project name, root objective, and all nodes in your tree</li>
        </ol>
        <h4 className="font-semibold mt-3">What to Ask</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>"What attack paths am I missing?"</li>
          <li>"How would an APT approach this differently from a script kiddie?"</li>
          <li>"What are the most critical gaps in my tree's coverage?"</li>
          <li>"Suggest detection opportunities for this attack path"</li>
          <li>"What real-world breaches used a similar attack pattern?"</li>
        </ul>
        <h4 className="font-semibold mt-3">Features</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Context-aware: automatically ingests your full tree structure</li>
          <li>Persistent conversation within the session</li>
          <li>Clear conversation with the trash icon to start a new topic</li>
        </ul>
      </div>
    ),
  },
  'risk-challenger': {
    title: 'Risk Score Challenger',
    content: (
      <div className="space-y-3 text-sm">
        <p>An AI tool that <strong>critically evaluates</strong> the risk scores you've assigned to a node, providing a second opinion and identifying potential biases or gaps.</p>
        <h4 className="font-semibold">How to Use</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Select a node in the Tree Editor</li>
          <li>Open the <strong>Scoring</strong> tab in the Node Inspector</li>
          <li>Click the <strong>AI Challenge My Scores</strong> button</li>
          <li>The AI analyses your likelihood, impact, effort, exploitability, and detectability scores</li>
          <li>It provides a critique with justifications for why scores might be too high or too low</li>
        </ol>
        <h4 className="font-semibold mt-3">What the AI Considers</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Node title, description, and type</li>
          <li>Current score values and computed inherent risk</li>
          <li>Mitigations applied to the node</li>
          <li>Context of the broader tree structure</li>
        </ul>
        <h4 className="font-semibold mt-3">Best Practices</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Use the challenger after you've scored a node to validate your judgement</li>
          <li>Pay attention to scores the AI flagged as significantly off — these often reveal blind spots</li>
          <li>The challenger provides reasoning, not just numbers — read the rationale</li>
          <li>Run the challenger again after adjusting scores to see if the new values are more defensible</li>
        </ul>
      </div>
    ),
  },
  dashboard: {
    title: 'Dashboard',
    content: (
      <div className="space-y-3 text-sm">
        <p>The Dashboard provides a comprehensive, at-a-glance risk analysis of your attack tree with glassmorphism-styled cards.</p>
        <h4 className="font-semibold">Risk Posture Grade</h4>
        <p>A letter grade (A–F) based on the average risk score across all nodes — from <strong>A (Minimal)</strong> to <strong>F (Critical)</strong>.</p>
        <h4 className="font-semibold mt-3">Quick Stats</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>Total Nodes</strong> — count of all nodes with how many are scored</li>
          <li><strong>Average Risk</strong> — mean inherent risk with max risk shown</li>
          <li><strong>Mitigated</strong> — percentage of nodes with at least one mitigation</li>
          <li><strong>Detection</strong> — percentage of nodes with detection strategies</li>
          <li><strong>Mapped</strong> — percentage of nodes with framework reference mappings</li>
          <li><strong>Exposed</strong> — count of nodes with no mitigations at all</li>
        </ul>
        <h4 className="font-semibold mt-3">Defence Coverage</h4>
        <p>Progress bars showing mitigation, detection, and framework mapping coverage as percentages.</p>
        <h4 className="font-semibold mt-3">Analytical Panels</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>Risk Distribution</strong> — histogram of risk scores across 5 severity buckets (Low → Critical)</li>
          <li><strong>Top Risks</strong> — the 10 highest-risk nodes with visual risk bars</li>
          <li><strong>Unmitigated Risks</strong> — high-risk nodes with zero mitigations</li>
          <li><strong>Lowest Attacker Effort</strong> — nodes that are cheapest/easiest for an attacker</li>
          <li><strong>Node Types</strong> — breakdown by goal, sub-goal, attack step, precondition, etc.</li>
          <li><strong>Status</strong> — breakdown by draft, validated, mitigated, accepted, archived</li>
          <li><strong>Highest Likelihood Vectors</strong> — the most probable attack paths</li>
        </ul>
        <h4 className="font-semibold mt-3">Audit Log</h4>
        <p>Tracks all changes made to the project — node creation, updates, deletions, scoring changes, mitigation additions, and more.</p>
      </div>
    ),
  },
  references: {
    title: 'References Browser',
    content: (
      <div className="space-y-3 text-sm">
        <p>Browse built-in security reference databases. All data is bundled locally for offline use.</p>
        <h4 className="font-semibold">Frameworks</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li><strong>MITRE ATT&CK</strong> — adversary tactics, techniques, and procedures (filter by tactic)</li>
          <li><strong>CAPEC</strong> — common attack pattern enumeration (filter by severity)</li>
          <li><strong>CWE</strong> — common weakness enumeration (filter by severity)</li>
          <li><strong>OWASP</strong> — web/API/mobile security categories (filter by category)</li>
        </ul>
        <h4 className="font-semibold mt-3">Using References</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>Search by ID, name, or keyword</li>
          <li>Filter by tactic, severity, or category using the dropdown</li>
          <li>Click any reference to expand its full details</li>
          <li>Use "Add to Node" to directly map a reference to a selected node in the tree</li>
          <li>References can also be added from the Node Inspector's Mappings tab</li>
        </ul>
      </div>
    ),
  },
  settings: {
    title: 'Settings',
    content: (
      <div className="space-y-3 text-sm">
        <p>Configure LLM providers for all AI features (Assist, Agent, Brainstorm, Scenarios, Kill Chain, Threat Model, Red Team Advisor, Risk Challenger).</p>
        <h4 className="font-semibold">Adding an LLM Provider</h4>
        <ol className="list-decimal pl-5 space-y-1.5">
          <li>Click <strong>Add Provider</strong></li>
          <li>Set the <strong>Base URL</strong> — for OpenAI: <code className="px-1.5 py-0.5 rounded bg-muted text-xs">https://api.openai.com/v1</code></li>
          <li>Paste your <strong>API Key</strong> (encrypted at rest, never sent to the browser)</li>
          <li>Set the <strong>Model</strong> name (e.g. <code className="px-1.5 py-0.5 rounded bg-muted text-xs">gpt-4o</code>)</li>
          <li>Click the <strong>Test</strong> button to verify the connection</li>
        </ol>
        <h4 className="font-semibold mt-3">Compatible Providers</h4>
        <p>Any endpoint that supports the OpenAI chat completions API format:</p>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>OpenAI (GPT-4o, GPT-4, etc.)</li>
          <li>Ollama (local models)</li>
          <li>LM Studio</li>
          <li>vLLM, text-generation-webui</li>
          <li>Azure OpenAI Service</li>
        </ul>
        <h4 className="font-semibold mt-3">Security</h4>
        <ul className="list-disc pl-5 space-y-1.5">
          <li>API keys are Fernet-encrypted at rest</li>
          <li>All LLM requests are made server-side — secrets never reach the browser</li>
          <li>TLS certificate verification enabled by default</li>
          <li>Custom CA bundles and client certificates supported</li>
        </ul>
      </div>
    ),
  },
  shortcuts: {
    title: 'Keyboard Shortcuts',
    content: (
      <div className="space-y-3 text-sm">
        <div className="grid grid-cols-2 gap-2">
          {[
            ['Ctrl + Z', 'Undo'],
            ['Ctrl + Y', 'Redo'],
            ['Ctrl + Enter', 'Add child node'],
            ['Delete', 'Delete selected node'],
            ['?', 'Show keyboard shortcuts'],
            ['Click node', 'Select & open inspector'],
            ['Click canvas', 'Deselect node'],
            ['Drag node', 'Move node on canvas'],
            ['Drag handle → node', 'Re-parent node'],
            ['Scroll wheel', 'Zoom in / out'],
          ].map(([key, desc]) => (
            <div key={key} className="flex items-center justify-between py-1 px-2 rounded bg-muted/50">
              <span className="text-xs">{desc}</span>
              <kbd className="px-1.5 py-0.5 rounded bg-background border text-[11px] font-mono">{key}</kbd>
            </div>
          ))}
        </div>
      </div>
    ),
  },
};

interface HelpDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function HelpDialog({ open, onOpenChange }: HelpDialogProps) {
  const [section, setSection] = useState<SectionId>('overview');

  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/50 z-50 animate-fade-in" />
        <Dialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 bg-card border rounded-xl shadow-xl z-50 w-[820px] max-w-[calc(100%-2rem)] h-[650px] max-h-[calc(100%-2rem)] flex animate-scale-in">
          {/* Sidebar */}
          <div className="w-48 border-r p-3 space-y-0.5 shrink-0 overflow-auto">
            <Dialog.Title className="font-semibold text-sm px-2 py-2 mb-1">
              Help & Guide
            </Dialog.Title>
            {SECTIONS.map((s) => (
              <button
                key={s.id}
                onClick={() => setSection(s.id)}
                className={cn(
                  'w-full flex items-center gap-2 px-2 py-1.5 rounded text-xs font-medium transition-colors text-left',
                  section === s.id
                    ? 'bg-primary text-primary-foreground'
                    : 'hover:bg-accent text-muted-foreground hover:text-foreground'
                )}
              >
                {s.icon}
                {s.label}
              </button>
            ))}
          </div>

          {/* Content */}
          <div className="flex-1 flex flex-col min-w-0">
            <div className="flex items-center justify-between px-5 py-3 border-b">
              <h2 className="font-semibold">{CONTENT[section].title}</h2>
              <Dialog.Close className="p-1 rounded hover:bg-accent transition-colors">
                <X size={16} />
              </Dialog.Close>
            </div>
            <div className="flex-1 overflow-auto px-5 py-4">
              {CONTENT[section].content}
            </div>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
