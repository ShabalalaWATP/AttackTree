import { useEffect, useMemo, useState } from 'react';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import {
  NODE_TYPE_CONFIG,
  type AnalysisRunData,
  type ArtifactCountsData,
  type DashboardAnalysisData,
  type DashboardNodeSummaryData,
  type DashboardPortfolioData,
  type DashboardProjectData,
  type DashboardWorkspaceSummaryData,
  type NodeType,
  type ProjectData,
} from '@/types';
import { cn } from '@/utils/cn';
import { formatContextPreset } from '@/utils/contextPresets';
import {
  Activity, AlertTriangle, BarChart3, Clock, Crosshair, Eye, FlaskConical,
  FolderOpen, Layers, Network, RefreshCw, Route, Shield, ShieldCheck, Target, TrendingUp,
} from 'lucide-react';
import { AuditLogPanel } from '@/components/AuditLogPanel';
import { useAdvisorPageContext } from '@/hooks/useAdvisorPageContext';

interface ArtifactCounts {
  scenarios: number;
  killChains: number;
  threatModels: number;
  infraMaps: number;
  snapshots: number;
}

interface DashboardNodeCard {
  id: string;
  title: string;
  node_type: string;
  inherent_risk: number | null;
  residual_risk: number | null;
  mitigation_count: number;
  detection_count: number;
  mapping_count: number;
  status: string;
  platform: string;
  attack_surface: string;
  required_access: string;
  created_at: string;
  updated_at: string;
}

interface WorkspaceBundle {
  project: ProjectData;
  artifacts: ArtifactCounts;
  analysis: NodeAnalysis;
  totalArtifacts: number;
}

interface NodeAnalysis {
  totalNodes: number;
  scored: number;
  avgRisk: number;
  maxRisk: number;
  residualScored: number;
  avgResidualRisk: number;
  residualReductionPct: number;
  criticalCount: number;
  reviewBacklog: number;
  gapCount: number;
  noMitigationCount: number;
  noDetectionCount: number;
  noMappingCount: number;
  mitigationPct: number;
  detectionPct: number;
  mappingPct: number;
  topRisks: DashboardNodeCard[];
  unmitigated: DashboardNodeCard[];
  gapQueue: DashboardNodeCard[];
  recentUpdates: DashboardNodeCard[];
  byType: Record<string, number>;
  byStatus: Record<string, number>;
  bySurface: Record<string, number>;
  byPlatform: Record<string, number>;
  byAccess: Record<string, number>;
  riskBuckets: Array<{ label: string; count: number; color: string }>;
}

interface CriticalPathDetail {
  id: string;
  title: string;
  node_type: string;
  inherent_risk: number | null;
  residual_risk: number | null;
  mitigation_count: number;
  max_mitigation_effectiveness: number;
}

interface DashboardCriticalPath {
  path: string[];
  cumulativeRisk: number;
  pathDetails: CriticalPathDetail[];
}

interface ProjectRunSummary {
  total: number;
  completed: number;
  partial: number;
  failed: number;
  avgDurationMs: number;
  byTool: Record<string, number>;
  recent: AnalysisRunData[];
}

interface PortfolioSummary {
  metrics: WorkspaceBundle[];
  aggregate: NodeAnalysis;
  totalArtifacts: ArtifactCounts;
  workspaceCount: number;
  projectScans: number;
  standaloneScans: number;
  contexts: Record<string, number>;
}

const EMPTY_ARTIFACTS: ArtifactCounts = { scenarios: 0, killChains: 0, threatModels: 0, infraMaps: 0, snapshots: 0 };
const EMPTY_ANALYSIS: NodeAnalysis = {
  totalNodes: 0,
  scored: 0,
  avgRisk: 0,
  maxRisk: 0,
  residualScored: 0,
  avgResidualRisk: 0,
  residualReductionPct: 0,
  criticalCount: 0,
  reviewBacklog: 0,
  gapCount: 0,
  noMitigationCount: 0,
  noDetectionCount: 0,
  noMappingCount: 0,
  mitigationPct: 0,
  detectionPct: 0,
  mappingPct: 0,
  topRisks: [],
  unmitigated: [],
  gapQueue: [],
  recentUpdates: [],
  byType: {},
  byStatus: {},
  bySurface: {},
  byPlatform: {},
  byAccess: {},
  riskBuckets: [
    { label: 'Low', count: 0, color: 'bg-emerald-500' },
    { label: 'Guarded', count: 0, color: 'bg-blue-500' },
    { label: 'Medium', count: 0, color: 'bg-amber-500' },
    { label: 'High', count: 0, color: 'bg-orange-500' },
    { label: 'Critical', count: 0, color: 'bg-red-500' },
  ],
};
const EMPTY_PORTFOLIO: PortfolioSummary = {
  metrics: [],
  aggregate: EMPTY_ANALYSIS,
  totalArtifacts: EMPTY_ARTIFACTS,
  workspaceCount: 0,
  projectScans: 0,
  standaloneScans: 0,
  contexts: {},
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function normalizeWorkspaceMode(mode: unknown): ProjectData['workspace_mode'] {
  return mode === 'standalone_scan' ? 'standalone_scan' : 'project_scan';
}

function normalizeProject(value: ProjectData | Record<string, unknown> | undefined): ProjectData {
  if (!isRecord(value) || typeof value.id !== 'string') {
    return {
      id: '',
      name: 'Untitled Workspace',
      description: '',
      context_preset: 'general',
      root_objective: '',
      owner: '',
      workspace_mode: 'project_scan',
      created_at: '',
      updated_at: '',
      node_count: 0,
    };
  }
  return {
    id: String(value.id),
    name: typeof value.name === 'string' && value.name.trim() ? value.name : 'Untitled Workspace',
    description: typeof value.description === 'string' ? value.description : '',
    context_preset: typeof value.context_preset === 'string' && value.context_preset.trim() ? value.context_preset : 'general',
    root_objective: typeof value.root_objective === 'string' ? value.root_objective : '',
    owner: typeof value.owner === 'string' ? value.owner : '',
    workspace_mode: normalizeWorkspaceMode(value.workspace_mode),
    created_at: typeof value.created_at === 'string' ? value.created_at : '',
    updated_at: typeof value.updated_at === 'string' ? value.updated_at : '',
    node_count: typeof value.node_count === 'number' && Number.isFinite(value.node_count) ? value.node_count : 0,
  };
}

function normalizeArtifactCounts(value: ArtifactCountsData | null | undefined): ArtifactCounts {
  return {
    scenarios: typeof value?.scenarios === 'number' ? value.scenarios : 0,
    killChains: typeof value?.kill_chains === 'number' ? value.kill_chains : 0,
    threatModels: typeof value?.threat_models === 'number' ? value.threat_models : 0,
    infraMaps: typeof value?.infra_maps === 'number' ? value.infra_maps : 0,
    snapshots: typeof value?.snapshots === 'number' ? value.snapshots : 0,
  };
}

function normalizeDashboardNode(value: DashboardNodeSummaryData | null | undefined): DashboardNodeCard {
  return {
    id: typeof value?.id === 'string' ? value.id : '',
    title: typeof value?.title === 'string' && value.title.trim() ? value.title : 'Unnamed node',
    node_type: typeof value?.node_type === 'string' ? value.node_type : 'note',
    inherent_risk: typeof value?.inherent_risk === 'number' ? value.inherent_risk : null,
    residual_risk: typeof value?.residual_risk === 'number' ? value.residual_risk : null,
    mitigation_count: typeof value?.mitigation_count === 'number' ? value.mitigation_count : 0,
    detection_count: typeof value?.detection_count === 'number' ? value.detection_count : 0,
    mapping_count: typeof value?.mapping_count === 'number' ? value.mapping_count : 0,
    status: typeof value?.status === 'string' ? value.status : '',
    platform: typeof value?.platform === 'string' ? value.platform : '',
    attack_surface: typeof value?.attack_surface === 'string' ? value.attack_surface : '',
    required_access: typeof value?.required_access === 'string' ? value.required_access : '',
    created_at: typeof value?.created_at === 'string' ? value.created_at : '',
    updated_at: typeof value?.updated_at === 'string' ? value.updated_at : '',
  };
}

function normalizeAnalysis(value: DashboardAnalysisData | null | undefined): NodeAnalysis {
  if (!value) return EMPTY_ANALYSIS;
  return {
    totalNodes: typeof value.total_nodes === 'number' ? value.total_nodes : 0,
    scored: typeof value.scored === 'number' ? value.scored : 0,
    avgRisk: typeof value.avg_risk === 'number' ? value.avg_risk : 0,
    maxRisk: typeof value.max_risk === 'number' ? value.max_risk : 0,
    residualScored: typeof value.residual_scored === 'number' ? value.residual_scored : 0,
    avgResidualRisk: typeof value.avg_residual_risk === 'number' ? value.avg_residual_risk : 0,
    residualReductionPct: typeof value.residual_reduction_pct === 'number' ? value.residual_reduction_pct : 0,
    criticalCount: typeof value.critical_count === 'number' ? value.critical_count : 0,
    reviewBacklog: typeof value.review_backlog === 'number' ? value.review_backlog : 0,
    gapCount: typeof value.gap_count === 'number' ? value.gap_count : 0,
    noMitigationCount: typeof value.no_mitigation_count === 'number' ? value.no_mitigation_count : 0,
    noDetectionCount: typeof value.no_detection_count === 'number' ? value.no_detection_count : 0,
    noMappingCount: typeof value.no_mapping_count === 'number' ? value.no_mapping_count : 0,
    mitigationPct: typeof value.mitigation_pct === 'number' ? value.mitigation_pct : 0,
    detectionPct: typeof value.detection_pct === 'number' ? value.detection_pct : 0,
    mappingPct: typeof value.mapping_pct === 'number' ? value.mapping_pct : 0,
    topRisks: Array.isArray(value.top_risks) ? value.top_risks.map(normalizeDashboardNode).filter((node) => node.id) : [],
    unmitigated: Array.isArray(value.unmitigated) ? value.unmitigated.map(normalizeDashboardNode).filter((node) => node.id) : [],
    gapQueue: Array.isArray(value.gap_queue) ? value.gap_queue.map(normalizeDashboardNode).filter((node) => node.id) : [],
    recentUpdates: Array.isArray(value.recent_updates) ? value.recent_updates.map(normalizeDashboardNode).filter((node) => node.id) : [],
    byType: isRecord(value.by_type) ? Object.fromEntries(Object.entries(value.by_type).filter(([, count]) => typeof count === 'number')) : {},
    byStatus: isRecord(value.by_status) ? Object.fromEntries(Object.entries(value.by_status).filter(([, count]) => typeof count === 'number')) : {},
    bySurface: isRecord(value.by_surface) ? Object.fromEntries(Object.entries(value.by_surface).filter(([, count]) => typeof count === 'number')) : {},
    byPlatform: isRecord(value.by_platform) ? Object.fromEntries(Object.entries(value.by_platform).filter(([, count]) => typeof count === 'number')) : {},
    byAccess: isRecord(value.by_access) ? Object.fromEntries(Object.entries(value.by_access).filter(([, count]) => typeof count === 'number')) : {},
    riskBuckets: Array.isArray(value.risk_buckets)
      ? value.risk_buckets
        .filter((bucket): bucket is { label: string; count: number; color: string } => (
          isRecord(bucket)
          && typeof bucket.label === 'string'
          && typeof bucket.count === 'number'
          && typeof bucket.color === 'string'
        ))
      : EMPTY_ANALYSIS.riskBuckets,
  };
}

function normalizeWorkspaceSummary(value: DashboardWorkspaceSummaryData | null | undefined): WorkspaceBundle {
  const project = normalizeProject(value?.project);
  const artifacts = normalizeArtifactCounts(value?.artifacts);
  return {
    project,
    artifacts,
    analysis: normalizeAnalysis(value?.analysis),
    totalArtifacts: typeof value?.total_artifacts === 'number' ? value.total_artifacts : artifactTotal(artifacts),
  };
}

function normalizePortfolio(value: DashboardPortfolioData | null | undefined): PortfolioSummary {
  if (!value) return EMPTY_PORTFOLIO;
  const metrics = Array.isArray(value.workspaces) ? value.workspaces.map(normalizeWorkspaceSummary).filter((bundle) => bundle.project.id) : [];
  return {
    metrics,
    aggregate: normalizeAnalysis(value.aggregate),
    totalArtifacts: normalizeArtifactCounts(value.artifact_totals),
    workspaceCount: metrics.length,
    projectScans: typeof value.project_scans === 'number' ? value.project_scans : 0,
    standaloneScans: typeof value.standalone_scans === 'number' ? value.standalone_scans : 0,
    contexts: isRecord(value.contexts) ? Object.fromEntries(Object.entries(value.contexts).filter(([, count]) => typeof count === 'number')) : {},
  };
}

function formatEnumLabel(value: string) {
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function safeTimestamp(iso: string | undefined): number {
  const ms = Date.parse(iso || '');
  return Number.isFinite(ms) ? ms : 0;
}

function formatContext(context: string) {
  return formatContextPreset(context.trim() || 'unspecified');
}

function riskText(risk: number) {
  if (risk >= 7) return 'text-risk-critical';
  if (risk >= 4) return 'text-risk-medium';
  return 'text-risk-low';
}

function riskBar(risk: number) {
  if (risk >= 7) return 'bg-[hsl(var(--risk-critical-text))]';
  if (risk >= 4) return 'bg-[hsl(var(--risk-medium-text))]';
  return 'bg-[hsl(var(--risk-low-text))]';
}

function riskGrade(avg: number) {
  if (avg >= 8) return { letter: 'F', label: 'Critical', gradient: 'from-red-500 to-rose-600' };
  if (avg >= 6) return { letter: 'D', label: 'High Risk', gradient: 'from-orange-500 to-red-500' };
  if (avg >= 4) return { letter: 'C', label: 'Moderate', gradient: 'from-amber-400 to-orange-500' };
  if (avg >= 2) return { letter: 'B', label: 'Low Risk', gradient: 'from-blue-400 to-cyan-400' };
  return { letter: 'A', label: 'Minimal', gradient: 'from-emerald-400 to-green-500' };
}

function artifactTotal(artifacts: ArtifactCounts) {
  return artifacts.scenarios + artifacts.killChains + artifacts.threatModels + artifacts.infraMaps + artifacts.snapshots;
}

function formatMode(mode: ProjectData['workspace_mode']) {
  return mode === 'standalone_scan' ? 'Standalone Scan' : 'Project Scan';
}

function formatDate(iso: string) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

function formatDateTime(iso: string) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  return date.toLocaleString('en-GB', {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function formatRunLabel(run: AnalysisRunData) {
  return `${formatEnumLabel(run.tool)} · ${formatEnumLabel(run.run_type)}`;
}

function formatRunStatus(status: string) {
  if (status === 'completed') return 'Completed';
  if (status === 'partial') return 'Partial';
  if (status === 'running') return 'Running';
  if (status === 'queued') return 'Queued';
  if (status === 'failed') return 'Failed';
  return 'Unknown';
}

function formatRunDuration(durationMs: number) {
  if (!durationMs) return 'No timing';
  if (durationMs < 60_000) return `${Math.round(durationMs / 1000)}s`;
  return `${(durationMs / 60_000).toFixed(1)}m`;
}

function runStatusTone(status: string) {
  if (status === 'completed') return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300';
  if (status === 'partial') return 'border-amber-500/20 bg-amber-500/10 text-amber-300';
  if (status === 'running' || status === 'queued') return 'border-blue-500/20 bg-blue-500/10 text-blue-300';
  if (status === 'failed') return 'border-red-500/20 bg-red-500/10 text-red-300';
  return 'border-border/40 bg-background/40 text-muted-foreground';
}

function normalizeCriticalPath(value: unknown): DashboardCriticalPath | null {
  if (!isRecord(value)) return null;
  const path = Array.isArray(value.path)
    ? value.path.filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
    : [];
  const pathDetails = Array.isArray(value.path_details)
    ? value.path_details
      .filter(isRecord)
      .map((item) => ({
        id: typeof item.id === 'string' ? item.id : '',
        title: typeof item.title === 'string' && item.title.trim() ? item.title : 'Unnamed node',
        node_type: typeof item.node_type === 'string' ? item.node_type : 'note',
        inherent_risk: typeof item.inherent_risk === 'number' ? item.inherent_risk : null,
        residual_risk: typeof item.residual_risk === 'number' ? item.residual_risk : null,
        mitigation_count: typeof item.mitigation_count === 'number' ? item.mitigation_count : 0,
        max_mitigation_effectiveness: typeof item.max_mitigation_effectiveness === 'number' ? item.max_mitigation_effectiveness : 0,
      }))
      .filter((item) => item.id)
    : [];

  return {
    path,
    cumulativeRisk: typeof value.cumulative_risk === 'number' ? value.cumulative_risk : 0,
    pathDetails,
  };
}

function coverageGapReasons(node: DashboardNodeCard) {
  const reasons: string[] = [];
  if (node.mitigation_count <= 0) reasons.push('No controls');
  if (node.detection_count <= 0) reasons.push('No detections');
  if (node.mapping_count <= 0) reasons.push('No references');
  return reasons;
}

export function DashboardView() {
  const { currentProject } = useStore();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshTick, setRefreshTick] = useState(0);
  const [projectArtifacts, setProjectArtifacts] = useState<ArtifactCounts>(EMPTY_ARTIFACTS);
  const [projectRuns, setProjectRuns] = useState<AnalysisRunData[]>([]);
  const [projectAnalysis, setProjectAnalysis] = useState<NodeAnalysis>(EMPTY_ANALYSIS);
  const [portfolio, setPortfolio] = useState<PortfolioSummary>(EMPTY_PORTFOLIO);
  const [criticalPath, setCriticalPath] = useState<DashboardCriticalPath | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError('');
      try {
        if (currentProject) {
          if (!cancelled) setPortfolio(EMPTY_PORTFOLIO);
          const [dashboardData, criticalPathData] = await Promise.all([
            api.getProjectDashboard(currentProject.id),
            api.getCriticalPath(currentProject.id).catch(() => null),
          ]);
          if (!cancelled) {
            setProjectArtifacts(normalizeArtifactCounts((dashboardData as DashboardProjectData | null)?.artifacts));
            setProjectAnalysis(normalizeAnalysis((dashboardData as DashboardProjectData | null)?.analysis));
            setProjectRuns(Array.isArray((dashboardData as DashboardProjectData | null)?.analysis_runs) ? dashboardData.analysis_runs : []);
            setCriticalPath(normalizeCriticalPath(criticalPathData));
          }
        } else {
          if (!cancelled) setProjectArtifacts({ ...EMPTY_ARTIFACTS });
          if (!cancelled) setProjectRuns([]);
          if (!cancelled) setProjectAnalysis(EMPTY_ANALYSIS);
          if (!cancelled) setCriticalPath(null);
          const portfolioData = await api.getDashboardPortfolio();
          if (!cancelled) setPortfolio(normalizePortfolio(portfolioData as DashboardPortfolioData | null));
        }
      } catch (e: any) {
        if (!cancelled) setError(e.message || 'Failed to load dashboard');
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    load();
    return () => { cancelled = true; };
  }, [currentProject?.id, refreshTick]);
  const runSummary = useMemo<ProjectRunSummary>(() => {
    const byTool: Record<string, number> = {};
    let completed = 0;
    let partial = 0;
    let failed = 0;

    projectRuns.forEach((run) => {
      byTool[run.tool] = (byTool[run.tool] || 0) + 1;
      if (run.status === 'completed') completed += 1;
      else if (run.status === 'partial') partial += 1;
      else if (run.status === 'failed') failed += 1;
    });

    return {
      total: projectRuns.length,
      completed,
      partial,
      failed,
      avgDurationMs: projectRuns.length ? projectRuns.reduce((sum, run) => sum + (run.duration_ms || 0), 0) / projectRuns.length : 0,
      byTool,
      recent: projectRuns.slice(0, 6),
    };
  }, [projectRuns]);

  const active = currentProject ? projectAnalysis : portfolio.aggregate;
  const artifacts = currentProject ? projectArtifacts : portfolio.totalArtifacts;
  const grade = riskGrade(active.avgRisk);
  const topRiskEntries = currentProject
    ? projectAnalysis.topRisks.map(node => ({ ...node, projectName: currentProject.name }))
    : portfolio.metrics
      .flatMap(bundle => bundle.analysis.topRisks.map(node => ({ ...node, projectName: bundle.project.name })))
      .sort((a, b) => (b.inherent_risk || 0) - (a.inherent_risk || 0))
      .slice(0, 10);
  const highRiskWorkspaces = [...portfolio.metrics]
    .sort((a, b) => (b.analysis.avgRisk - a.analysis.avgRisk) || (b.analysis.maxRisk - a.analysis.maxRisk))
    .slice(0, 6);
  const recentWorkspaces = [...portfolio.metrics]
    .sort((a, b) => safeTimestamp(b.project.updated_at) - safeTimestamp(a.project.updated_at))
    .slice(0, 6);
  const artifactEntries = [
    { label: 'Scenarios', value: artifacts.scenarios, icon: <FlaskConical size={12} className="text-violet-400" /> },
    { label: 'Kill Chains', value: artifacts.killChains, icon: <Route size={12} className="text-cyan-400" /> },
    { label: 'Threat Models', value: artifacts.threatModels, icon: <ShieldCheck size={12} className="text-emerald-400" /> },
    { label: 'Infra Maps', value: artifacts.infraMaps, icon: <Network size={12} className="text-sky-400" /> },
    { label: 'Snapshots', value: artifacts.snapshots, icon: <Layers size={12} className="text-amber-400" /> },
  ];
  const coverageAverage = Math.round((active.mitigationPct + active.detectionPct + active.mappingPct) / 3);
  const latestWorkspace = recentWorkspaces[0];
  const heroTimestamp = currentProject
    ? (currentProject.updated_at ? formatDateTime(currentProject.updated_at) : 'No recent update')
    : latestWorkspace?.project.updated_at
      ? formatDateTime(latestWorkspace.project.updated_at)
      : 'No recent workspace updates';
  const heroMetrics = currentProject
    ? [
        { label: 'Coverage Avg', value: `${coverageAverage}%`, tone: 'text-cyan-300' },
        { label: 'Run Success', value: runSummary.total ? `${Math.round((runSummary.completed / runSummary.total) * 100)}%` : 'NA', tone: 'text-emerald-300' },
        { label: 'Assets', value: artifactTotal(artifacts), tone: 'text-violet-300' },
      ]
    : [
        { label: 'Coverage Avg', value: `${coverageAverage}%`, tone: 'text-cyan-300' },
        { label: 'Contexts', value: Object.keys(portfolio.contexts).length, tone: 'text-emerald-300' },
        { label: 'Analyses', value: artifactTotal(artifacts), tone: 'text-violet-300' },
      ];
  const heroSummary = currentProject
    ? currentProject.root_objective || 'Workspace command view for attack-tree posture, control gaps, and operational analysis outputs.'
    : 'Portfolio-wide command view for workspace posture, coverage pressure, and the highest-risk analysis areas.';
  const heroLabel = currentProject ? 'Workspace Command View' : 'Portfolio Command View';
  const postureSummary = currentProject
    ? 'Core posture indicators for the active workspace.'
    : 'Portfolio-wide indicators across every loaded workspace.';
  const pressureSummary = currentProject
    ? 'Priority items, workflow pressure, and immediate action demand.'
    : 'Where the portfolio is carrying the most operational risk.';
  const compositionSummary = currentProject
    ? 'How the current workspace is distributed by type, surface, and access.'
    : 'How the portfolio is spread across workspace contexts and attack surfaces.';
  const advisorContext = useMemo(() => ({
    view: 'dashboard' as const,
    title: currentProject ? `${currentProject.name} Dashboard` : 'Portfolio Dashboard',
    summary: heroSummary,
    packets: [
      `Average inherent risk: ${active.avgRisk.toFixed(1)}`,
      `Critical nodes: ${active.criticalCount}`,
      `Review backlog: ${active.reviewBacklog}`,
      `Coverage average: ${coverageAverage}%`,
      currentProject ? `Recent analysis runs: ${runSummary.total}` : `Workspaces in scope: ${portfolio.workspaceCount}`,
      currentProject && criticalPath ? `Critical path cumulative risk: ${criticalPath.cumulativeRisk.toFixed(1)}` : '',
    ],
  }), [
    active.avgRisk,
    active.criticalCount,
    active.reviewBacklog,
    coverageAverage,
    criticalPath,
    currentProject,
    heroSummary,
    portfolio.workspaceCount,
    runSummary.total,
  ]);
  useAdvisorPageContext(advisorContext);

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        <div className="flex items-center gap-2 text-sm"><RefreshCw size={14} className="animate-spin" /> Loading dashboard…</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="h-full flex items-center justify-center">
        <Card className="max-w-md text-center">
          <div className="text-sm font-semibold mb-1">Dashboard data could not be loaded</div>
          <div className="text-xs text-muted-foreground mb-4">{error}</div>
          <button onClick={() => setRefreshTick(value => value + 1)} className="px-3 py-2 rounded-lg bg-primary text-primary-foreground text-sm">Retry</button>
        </Card>
      </div>
    );
  }

  if (!currentProject && portfolio.workspaceCount === 0) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        <div className="text-center">
          <p className="mb-2">No workspaces available yet.</p>
          <button onClick={() => useStore.getState().setViewMode('projects')} className="text-primary text-sm hover:underline">Open Workspaces</button>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto bg-[radial-gradient(circle_at_top_left,_rgba(34,211,238,0.09),_transparent_28%),radial-gradient(circle_at_top_right,_rgba(99,102,241,0.10),_transparent_24%),linear-gradient(180deg,rgba(15,23,42,0.32),transparent_18%)]">
      <div className="px-6 pt-6 pb-6">
        <div className="max-w-7xl mx-auto space-y-5">
          <div className="relative overflow-hidden rounded-[30px] border border-white/10 bg-[linear-gradient(135deg,rgba(8,15,40,0.92),rgba(15,23,42,0.88))] px-6 py-6 shadow-[0_28px_100px_-40px_rgba(8,15,40,0.95)] lg:px-8 lg:py-8">
            <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(34,211,238,0.16),transparent_34%),radial-gradient(circle_at_bottom_right,rgba(168,85,247,0.12),transparent_30%)]" />
            <div className="pointer-events-none absolute -right-20 top-0 h-56 w-56 rounded-full bg-cyan-500/10 blur-3xl" />
            <div className="pointer-events-none absolute bottom-0 left-1/3 h-48 w-48 rounded-full bg-indigo-500/10 blur-3xl" />

            <div className="relative grid gap-6 xl:grid-cols-[1.2fr_0.8fr]">
              <div>
                <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.24em] text-cyan-200">
                  <Activity size={11} />
                  {heroLabel}
                </div>
                <h1 className="mt-4 text-3xl font-semibold tracking-tight text-foreground sm:text-[2.5rem]">
                  {currentProject?.name ?? 'Portfolio Dashboard'}
                </h1>
                <p className="mt-3 max-w-3xl text-sm leading-7 text-muted-foreground">
                  {heroSummary}
                </p>

                <div className="mt-5 flex flex-wrap gap-2">
                  <HeroPill icon={<FolderOpen size={12} className="text-cyan-300" />}>
                    {currentProject ? formatMode(currentProject.workspace_mode) : `${portfolio.workspaceCount} workspaces`}
                  </HeroPill>
                  <HeroPill icon={<Network size={12} className="text-emerald-300" />}>
                    {currentProject ? formatContext(currentProject.context_preset) : `${Object.keys(portfolio.contexts).length} context profiles`}
                  </HeroPill>
                  <HeroPill icon={<Layers size={12} className="text-violet-300" />}>
                    {artifactTotal(artifacts)} analysis assets
                  </HeroPill>
                  <HeroPill icon={<Clock size={12} className="text-amber-300" />}>
                    Updated {heroTimestamp}
                  </HeroPill>
                </div>
              </div>

              <div className="grid gap-4">
                <div className="rounded-[26px] border border-white/10 bg-slate-950/40 p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.06)]">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="text-[10px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Risk Posture</div>
                      <div className="mt-2 text-2xl font-black tracking-tight text-foreground">{grade.label}</div>
                      <div className="mt-1 text-xs leading-6 text-muted-foreground">
                        Average inherent risk {active.avgRisk.toFixed(1)} across {active.scored} scored node{active.scored === 1 ? '' : 's'}
                      </div>
                    </div>
                    <div className={cn('flex h-16 w-16 items-center justify-center rounded-[22px] bg-gradient-to-br text-white shadow-xl', grade.gradient)}>
                      <span className="text-3xl font-black">{grade.letter}</span>
                    </div>
                  </div>

                  <div className="mt-5 grid gap-3 sm:grid-cols-3">
                    {heroMetrics.map((item) => (
                      <HeroMetric key={item.label} label={item.label} value={item.value} tone={item.tone} />
                    ))}
                  </div>

                  <div className="mt-5 flex items-center justify-between gap-3 rounded-2xl border border-white/10 bg-white/[0.03] px-3 py-2.5 text-xs">
                    <div className="min-w-0">
                      <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground">Operator Readout</div>
                      <div className="mt-1 truncate text-muted-foreground">
                        {currentProject
                          ? `${runSummary.total} run${runSummary.total === 1 ? '' : 's'} recorded for this workspace`
                          : `${portfolio.projectScans} project scans and ${portfolio.standaloneScans} standalone scans active`}
                      </div>
                    </div>
                    <button
                      onClick={() => setRefreshTick(value => value + 1)}
                      className="inline-flex shrink-0 items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-3 py-2 text-foreground transition-colors hover:bg-white/[0.08]"
                      title="Refresh dashboard"
                    >
                      <RefreshCw size={13} />
                      Refresh
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <SectionHeading title="Operational Snapshot" description={postureSummary} />
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-6">
            {currentProject ? (
              <>
                <StatCard icon={<Target size={14} className="text-cyan-400" />} label="Total Nodes" value={active.totalNodes} subtext={`${active.scored} scored`} accent="from-cyan-500/20 to-blue-500/20" />
                <StatCard icon={<BarChart3 size={14} className="text-amber-400" />} label="Avg Risk" value={active.avgRisk.toFixed(1)} subtext={`max: ${active.maxRisk.toFixed(1)}`} accent="from-amber-500/20 to-red-500/20" valueClass={riskText(active.avgRisk)} />
                <StatCard icon={<ShieldCheck size={14} className="text-emerald-400" />} label="Residual Avg" value={active.residualScored ? active.avgResidualRisk.toFixed(1) : 'NA'} subtext={`${active.residualReductionPct.toFixed(0)}% risk reduction`} accent="from-emerald-500/20 to-green-500/20" valueClass="text-emerald-400" />
                <StatCard icon={<AlertTriangle size={14} className="text-red-400" />} label="Critical" value={active.criticalCount} subtext="risk >= 8.0" accent="from-red-500/20 to-rose-500/20" valueClass="text-red-400" />
                <StatCard icon={<Clock size={14} className="text-blue-400" />} label="Review Backlog" value={active.reviewBacklog} subtext="draft or unscored nodes" accent="from-blue-500/20 to-indigo-500/20" valueClass="text-blue-400" />
                <StatCard icon={<Shield size={14} className="text-purple-400" />} label="Gap Queue" value={active.gapCount} subtext="high-risk nodes missing coverage" accent="from-purple-500/20 to-fuchsia-500/20" valueClass="text-purple-400" />
              </>
            ) : (
              <>
                <StatCard icon={<FolderOpen size={14} className="text-cyan-400" />} label="Workspaces" value={portfolio.workspaceCount} subtext={`${portfolio.projectScans} project · ${portfolio.standaloneScans} standalone`} accent="from-cyan-500/20 to-blue-500/20" />
                <StatCard icon={<Target size={14} className="text-emerald-400" />} label="Total Nodes" value={active.totalNodes} subtext={`${active.scored} scored`} accent="from-emerald-500/20 to-green-500/20" />
                <StatCard icon={<BarChart3 size={14} className="text-amber-400" />} label="Avg Risk" value={active.avgRisk.toFixed(1)} subtext={`max: ${active.maxRisk.toFixed(1)}`} accent="from-amber-500/20 to-red-500/20" valueClass={riskText(active.avgRisk)} />
                <StatCard icon={<AlertTriangle size={14} className="text-red-400" />} label="Critical" value={active.criticalCount} subtext="risk >= 8.0" accent="from-red-500/20 to-rose-500/20" valueClass="text-red-400" />
                <StatCard icon={<Clock size={14} className="text-blue-400" />} label="Review Backlog" value={active.reviewBacklog} subtext="draft or unscored nodes" accent="from-blue-500/20 to-indigo-500/20" valueClass="text-blue-400" />
                <StatCard icon={<Layers size={14} className="text-purple-400" />} label="Analyses" value={artifactTotal(artifacts)} subtext={`${artifacts.threatModels} threat models · ${artifacts.infraMaps} maps`} accent="from-purple-500/20 to-fuchsia-500/20" valueClass="text-purple-400" />
              </>
            )}
          </div>

          <Card>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4">Defence Coverage</h3>
            <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
              <CoverageBar label="Mitigation" pct={active.mitigationPct} gradient="from-green-500 to-emerald-400" />
              <CoverageBar label="Detection" pct={active.detectionPct} gradient="from-blue-500 to-cyan-400" />
              <CoverageBar label="Framework Mapping" pct={active.mappingPct} gradient="from-purple-500 to-fuchsia-400" />
            </div>
          </Card>

          <SectionHeading title="Exposure Map" description="Risk concentration, ranked threats, and distribution of immediate pressure." />
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
            <Card className="xl:col-span-1">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4 flex items-center gap-1.5">
                <Activity size={13} className="text-primary" /> Risk Distribution
              </h3>
              <div className="space-y-2">
                {active.riskBuckets.map(bucket => {
                  const pct = active.scored ? (bucket.count / active.scored) * 100 : 0;
                  return (
                    <div key={bucket.label}>
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-[10px] font-medium text-muted-foreground">{bucket.label}</span>
                        <span className="text-[10px] font-bold">{bucket.count} <span className="text-muted-foreground font-normal">({pct.toFixed(0)}%)</span></span>
                      </div>
                      <div className="h-3 bg-muted/50 rounded-full overflow-hidden">
                        <div className={cn('h-full rounded-full', bucket.color)} style={{ width: `${pct}%`, minWidth: bucket.count > 0 ? '6px' : '0' }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>

            <Card className="xl:col-span-2">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Crosshair size={13} className="text-red-400" /> Top Risks
              </h3>
              <div className="space-y-0.5">
                {topRiskEntries.map((node, index) => (
                  <div key={`${node.projectName}-${node.id}`} className="flex items-center gap-2 py-1.5 px-2 rounded-lg hover:bg-white/5 text-xs">
                    <span className="w-4 text-[10px] text-muted-foreground font-mono">{index + 1}</span>
                    <span className="shrink-0 opacity-70">{NODE_TYPE_CONFIG[node.node_type as NodeType]?.icon}</span>
                    <div className="truncate flex-1">
                      <div className="truncate">{node.title}</div>
                      {!currentProject && <div className="text-[10px] text-muted-foreground truncate">{node.projectName}</div>}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <div className="w-20 h-2 bg-muted/50 rounded-full overflow-hidden">
                        <div className={cn('h-full rounded-full', riskBar(node.inherent_risk || 0))} style={{ width: `${((node.inherent_risk || 0) / 10) * 100}%` }} />
                      </div>
                      <span className={cn('font-bold w-6 text-right tabular-nums text-xs', riskText(node.inherent_risk || 0))}>{(node.inherent_risk || 0).toFixed(1)}</span>
                    </div>
                  </div>
                ))}
                {!topRiskEntries.length && <Empty message="No ranked risks available yet" />}
              </div>
            </Card>
          </div>

          <SectionHeading title={currentProject ? 'Immediate Focus' : 'Workspace Watchlist'} description={pressureSummary} />
          <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
            {currentProject ? (
              <>
                <Card className="xl:col-span-2">
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4 flex items-center gap-1.5">
                    <Shield size={13} className="text-amber-400" /> Immediate Action Queue
                  </h3>
                  <div className="space-y-2">
                    {projectAnalysis.gapQueue.map(node => (
                      <div key={node.id} className="rounded-lg border border-border/30 bg-background/30 px-3 py-2.5">
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="text-sm font-medium truncate">{node.title}</div>
                            <div className="text-[11px] text-muted-foreground mt-0.5 truncate">
                              {formatEnumLabel(node.required_access || 'unspecified')} access
                              {' · '}
                              {node.platform || 'Platform not set'}
                            </div>
                            <div className="mt-2 flex flex-wrap gap-1.5">
                              {coverageGapReasons(node).map(reason => (
                                <span key={reason} className="rounded-full border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[10px] text-amber-300">
                                  {reason}
                                </span>
                              ))}
                            </div>
                          </div>
                          <div className="shrink-0 text-right">
                            <div className={cn('text-lg font-black tabular-nums', riskText(node.inherent_risk || 0))}>
                              {(node.inherent_risk || 0).toFixed(1)}
                            </div>
                            <div className="text-[10px] text-muted-foreground">inherent risk</div>
                          </div>
                        </div>
                      </div>
                    ))}
                    {!projectAnalysis.gapQueue.length && <Empty message="No high-risk control gaps are currently queued" positive />}
                  </div>
                </Card>

                <Card>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4 flex items-center gap-1.5">
                    <Activity size={13} className="text-primary" /> Workflow Status
                  </h3>
                  <div className="grid grid-cols-1 gap-2 mb-4 sm:grid-cols-3">
                    <MiniStat icon={<Shield size={12} className="text-amber-400" />} label="No Controls" value={projectAnalysis.noMitigationCount} />
                    <MiniStat icon={<Eye size={12} className="text-blue-400" />} label="No Detection" value={projectAnalysis.noDetectionCount} />
                    <MiniStat icon={<Route size={12} className="text-purple-400" />} label="No Refs" value={projectAnalysis.noMappingCount} />
                  </div>
                  <div className="rounded-lg border border-border/30 bg-background/30 px-3 py-2.5 mb-4">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Residual Reduction</div>
                    <div className="mt-1 text-lg font-black text-emerald-400">{projectAnalysis.residualReductionPct.toFixed(0)}%</div>
                    <div className="text-[10px] text-muted-foreground">Across nodes with both inherent and residual scores</div>
                  </div>
                  <div className="grid grid-cols-2 gap-2 mb-4">
                    <MiniStat icon={<Activity size={12} className="text-cyan-400" />} label="Runs" value={runSummary.total} />
                    <MiniStat icon={<ShieldCheck size={12} className="text-emerald-400" />} label="Completed" value={runSummary.completed} />
                    <MiniStat icon={<AlertTriangle size={12} className="text-amber-400" />} label="Partial" value={runSummary.partial} />
                    <MiniStat icon={<Clock size={12} className="text-blue-400" />} label="Avg Mins" value={Number((runSummary.avgDurationMs / 60000).toFixed(1))} />
                  </div>
                  <MetricBars entries={projectAnalysis.byStatus} total={projectAnalysis.totalNodes} formatter={formatEnumLabel} />
                </Card>
              </>
            ) : (
              <>
                <Card>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4 flex items-center gap-1.5">
                    <TrendingUp size={13} className="text-red-400" /> Highest-Risk Workspaces
                  </h3>
                  <div className="space-y-1">
                    {highRiskWorkspaces.map(bundle => (
                      <div key={bundle.project.id} className="rounded-lg border border-border/30 p-3 bg-background/30">
                        <div className="flex items-center justify-between gap-3">
                          <div>
                            <div className="text-sm font-semibold">{bundle.project.name}</div>
                            <div className="text-[11px] text-muted-foreground">{formatMode(bundle.project.workspace_mode)} · {bundle.project.node_count} nodes · {bundle.totalArtifacts} analyses</div>
                          </div>
                          <div className={cn('text-lg font-black', riskText(bundle.analysis.avgRisk))}>{bundle.analysis.avgRisk.toFixed(1)}</div>
                        </div>
                      </div>
                    ))}
                    {!highRiskWorkspaces.length && <Empty message="No workspace risk data available yet" />}
                  </div>
                </Card>

                <Card>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4 flex items-center gap-1.5">
                    <Clock size={13} className="text-primary" /> Recent Workspaces
                  </h3>
                  <div className="space-y-1">
                    {recentWorkspaces.map(bundle => (
                      <div key={bundle.project.id} className="flex items-center justify-between gap-3 py-2 px-2 rounded-lg hover:bg-white/5 text-xs">
                        <div className="min-w-0">
                          <div className="truncate font-medium">{bundle.project.name}</div>
                          <div className="text-muted-foreground truncate">{formatMode(bundle.project.workspace_mode)} · {formatContextPreset(bundle.project.context_preset)}</div>
                        </div>
                        <div className="text-right shrink-0">
                          <div>{formatDate(bundle.project.updated_at)}</div>
                          <div className="text-[10px] text-muted-foreground">{bundle.project.node_count} nodes</div>
                        </div>
                      </div>
                    ))}
                    {!recentWorkspaces.length && <Empty message="No workspaces loaded yet" />}
                  </div>
                </Card>

                <Card>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4">Analysis Assets</h3>
                  <div className="grid grid-cols-2 gap-3">
                    {artifactEntries.map((item) => (
                      <MiniStat key={item.label} icon={item.icon} label={item.label} value={item.value} />
                    ))}
                  </div>
                  <div className="mt-4 rounded-lg border border-border/30 bg-background/30 px-3 py-2.5">
                    <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Portfolio Totals</div>
                    <div className="mt-1 text-lg font-black">{artifactTotal(artifacts)}</div>
                    <div className="text-[10px] text-muted-foreground">
                      {portfolio.workspaceCount ? (artifactTotal(artifacts) / portfolio.workspaceCount).toFixed(1) : '0.0'} analyses per workspace
                    </div>
                  </div>
                </Card>
              </>
            )}
          </div>

          {currentProject && (
            <div className="grid grid-cols-1 gap-5 xl:grid-cols-3">
              <Card className="xl:col-span-2">
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4 flex items-center gap-1.5">
                  <Route size={13} className="text-red-400" /> Critical Path
                </h3>
                {criticalPath?.pathDetails.length ? (
                  <div className="space-y-2">
                    <div className="rounded-lg border border-border/30 bg-background/30 px-3 py-2.5">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Path Strength</div>
                          <div className="text-lg font-black text-red-400">{criticalPath.cumulativeRisk.toFixed(1)}</div>
                        </div>
                        <div className="text-right">
                          <div className="text-sm font-semibold">{criticalPath.pathDetails.length} nodes</div>
                          <div className="text-[10px] text-muted-foreground">highest cumulative route</div>
                        </div>
                      </div>
                    </div>
                    {criticalPath.pathDetails.slice(0, 6).map((item, index) => (
                      <div key={item.id} className="flex items-center gap-3 rounded-lg border border-border/30 bg-background/30 px-3 py-2 text-xs">
                        <span className="w-5 text-[10px] font-mono text-muted-foreground">{index + 1}</span>
                        <div className="min-w-0 flex-1">
                          <div className="truncate font-medium">{item.title}</div>
                          <div className="text-[10px] text-muted-foreground">
                            {NODE_TYPE_CONFIG[item.node_type as NodeType]?.label || formatEnumLabel(item.node_type)}
                            {' · '}
                            {item.mitigation_count} control{item.mitigation_count === 1 ? '' : 's'}
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          <div className={cn('font-bold tabular-nums', riskText(item.inherent_risk || 0))}>
                            {(item.inherent_risk || 0).toFixed(1)}
                          </div>
                          <div className="text-[10px] text-muted-foreground">
                            residual {item.residual_risk != null ? item.residual_risk.toFixed(1) : 'NA'}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty message="Critical path data is not available yet" />
                )}
              </Card>

              <Card>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4 flex items-center gap-1.5">
                  <Activity size={13} className="text-cyan-400" /> Analysis Run Ledger
                </h3>
                <div className="space-y-2">
                  {runSummary.recent.map((run) => (
                    <div key={run.id} className="rounded-lg border border-border/30 bg-background/30 px-3 py-2.5">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <div className="text-sm font-medium truncate">{formatRunLabel(run)}</div>
                          <div className="text-[10px] text-muted-foreground mt-0.5 truncate">
                            {run.artifact_name || currentProject.name}
                            {' · '}
                            {formatDateTime(run.created_at)}
                          </div>
                          <div className="mt-2 text-[11px] text-muted-foreground line-clamp-2">{run.summary || 'No run summary available yet'}</div>
                        </div>
                        <div className="shrink-0 text-right">
                          <div className={cn('inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium border', runStatusTone(run.status))}>
                            {formatRunStatus(run.status)}
                          </div>
                          <div className="text-[10px] text-muted-foreground mt-1">{formatRunDuration(run.duration_ms)}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                  {!runSummary.recent.length && <Empty message="No workspace analysis runs recorded yet" />}
                </div>
                <div className="mt-4 rounded-lg border border-border/30 bg-background/30 px-3 py-2.5">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Run Mix</div>
                  {Object.keys(runSummary.byTool).length ? (
                    <div className="mt-2 space-y-1.5">
                      {Object.entries(runSummary.byTool).sort((a, b) => b[1] - a[1]).map(([tool, count]) => (
                        <div key={tool} className="flex items-center justify-between text-xs">
                          <span>{formatEnumLabel(tool)}</span>
                          <span className="font-semibold tabular-nums">{count}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="mt-2 text-[11px] text-muted-foreground">No run activity yet</div>
                  )}
                </div>
              </Card>

              <Card>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4 flex items-center gap-1.5">
                  <Clock size={13} className="text-primary" /> Recent Node Changes
                </h3>
                <div className="space-y-1">
                  {projectAnalysis.recentUpdates.map((node) => (
                    <div key={node.id} className="flex items-center justify-between gap-3 rounded-lg px-2 py-2 hover:bg-white/5 text-xs">
                      <div className="min-w-0">
                        <div className="truncate font-medium">{node.title}</div>
                        <div className="text-[10px] text-muted-foreground">
                          {formatEnumLabel(node.status)}
                          {' · '}
                          {formatDateTime(node.updated_at || node.created_at)}
                        </div>
                      </div>
                      <div className="text-right shrink-0">
                        <div className={cn('font-bold tabular-nums', riskText(node.inherent_risk || 0))}>
                          {node.inherent_risk != null ? node.inherent_risk.toFixed(1) : 'NA'}
                        </div>
                        <div className="text-[10px] text-muted-foreground">{node.platform || 'No platform'}</div>
                      </div>
                    </div>
                  ))}
                  {!projectAnalysis.recentUpdates.length && <Empty message="No recent node changes yet" />}
                </div>
              </Card>
            </div>
          )}

          <SectionHeading title="Composition & Coverage" description={compositionSummary} />
          <div className={cn('grid grid-cols-1 gap-5', currentProject ? 'xl:grid-cols-4' : 'xl:grid-cols-3')}>
            {currentProject && (
              <Card>
                <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4">Analysis Assets</h3>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  {artifactEntries.map((item) => (
                    <MiniStat key={item.label} icon={item.icon} label={item.label} value={item.value} />
                  ))}
                </div>
                <div className="mt-4 rounded-lg border border-border/30 bg-background/30 px-3 py-2.5">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Analysis Assets</div>
                  <div className="mt-1 text-lg font-black">{artifactTotal(artifacts)}</div>
                  <div className="text-[10px] text-muted-foreground">
                    {artifacts.snapshots} snapshot{artifacts.snapshots === 1 ? '' : 's'} captured for rollback and reporting
                  </div>
                </div>
              </Card>
            )}

            <Card>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4">Node Types</h3>
              <MetricBars entries={active.byType} total={active.totalNodes} formatter={(key) => NODE_TYPE_CONFIG[key as NodeType]?.label || key} iconFormatter={(key) => NODE_TYPE_CONFIG[key as NodeType]?.icon || ''} />
            </Card>
            <Card>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4">Top Attack Surfaces</h3>
              <MetricBars entries={active.bySurface} total={active.totalNodes} formatter={(key) => key} />
            </Card>
            <Card>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4">Required Access</h3>
              <MetricBars entries={active.byAccess} total={active.totalNodes} formatter={formatEnumLabel} />
            </Card>
          </div>

          {currentProject ? (
            <Card>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4 flex items-center gap-1.5">
                <Clock size={13} className="text-primary" /> Recent Activity
              </h3>
              <AuditLogPanel projectId={currentProject.id} />
            </Card>
          ) : (
            <Card>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-[0.22em] mb-4">Workspaces by Context</h3>
              {Object.keys(portfolio.contexts).length ? (
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2 xl:grid-cols-3">
                  {Object.entries(portfolio.contexts).sort((a, b) => b[1] - a[1]).slice(0, 9).map(([context, count]) => (
                    <div key={context} className="rounded-lg border border-border/30 bg-background/30 px-3 py-2">
                      <div className="text-xs font-medium truncate">{formatContextPreset(context)}</div>
                      <div className="text-[11px] text-muted-foreground mt-0.5">{count} workspace{count === 1 ? '' : 's'}</div>
                    </div>
                  ))}
                </div>
              ) : (
                <Empty message="No workspace context data available yet" />
              )}
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}

function Card({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={cn(
      'relative overflow-hidden rounded-[24px] border border-white/10 bg-[linear-gradient(180deg,rgba(15,23,42,0.72),rgba(8,15,40,0.58))] shadow-[0_24px_70px_-36px_rgba(8,15,40,0.95)]',
      className,
    )}>
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top_left,rgba(56,189,248,0.12),transparent_32%),radial-gradient(circle_at_bottom_right,rgba(99,102,241,0.10),transparent_30%)]" />
      <div className="relative p-4 sm:p-5">{children}</div>
    </div>
  );
}

function StatCard({ icon, label, value, subtext, accent, valueClass }: { icon: React.ReactNode; label: string; value: string | number; subtext: string; accent: string; valueClass?: string }) {
  return (
    <Card className="min-h-[148px]">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="text-[10px] font-semibold uppercase tracking-[0.22em] text-muted-foreground">{label}</div>
          <div className={cn('mt-3 text-3xl font-black tracking-tight', valueClass)}>{value}</div>
        </div>
        <div className={cn('flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br shadow-lg ring-1 ring-white/10', accent)}>
          {icon}
        </div>
      </div>
      <div className="mt-5 flex items-end justify-between gap-3">
        <div className="max-w-[14rem] text-[11px] leading-5 text-muted-foreground">{subtext}</div>
        <div className="w-16 shrink-0 overflow-hidden rounded-full bg-white/5">
          <div className={cn('h-1.5 rounded-full bg-gradient-to-r', accent)} />
        </div>
      </div>
    </Card>
  );
}

function CoverageBar({ label, pct, gradient }: { label: string; pct: number; gradient: string }) {
  return (
    <div className="rounded-[20px] border border-white/10 bg-white/[0.03] p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold uppercase tracking-[0.18em] text-muted-foreground">{label}</span>
        <span className="text-base font-black tabular-nums text-foreground">{pct.toFixed(0)}%</span>
      </div>
      <div className="h-2.5 bg-white/5 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full bg-gradient-to-r', gradient)} style={{ width: `${pct}%` }} />
      </div>
      <div className="mt-2 text-[11px] text-muted-foreground">
        {pct >= 75 ? 'Strong' : pct >= 45 ? 'Partial' : 'Thin'} coverage across the current set.
      </div>
    </div>
  );
}

function MiniStat({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return (
    <div className="rounded-[18px] border border-white/10 bg-white/[0.03] px-3 py-3">
      <div className="flex items-center gap-2 text-[11px] text-muted-foreground">{icon}{label}</div>
      <div className="mt-2 text-xl font-semibold tracking-tight">{value}</div>
    </div>
  );
}

function MetricBars({ entries, total, formatter, iconFormatter }: { entries: Record<string, number>; total: number; formatter: (key: string) => string; iconFormatter?: (key: string) => string }) {
  const sorted = Object.entries(entries).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (!sorted.length) return <Empty message="No metrics available yet" />;
  return (
    <div className="space-y-2">
      {sorted.map(([key, count]) => {
        const pct = total ? (count / total) * 100 : 0;
        return (
          <div key={key} className="flex items-center gap-3 rounded-[18px] border border-white/10 bg-white/[0.03] px-3 py-2.5">
            <span className="flex items-center gap-1.5 w-32 shrink-0 text-[11px]">
              {iconFormatter && <span className="opacity-70">{iconFormatter(key)}</span>}
              <span className="truncate">{formatter(key)}</span>
            </span>
            <div className="flex-1 h-2.5 bg-white/5 rounded-full overflow-hidden">
              <div className="h-full rounded-full bg-gradient-to-r from-cyan-400/75 to-blue-500/80" style={{ width: `${pct}%`, minWidth: count > 0 ? '6px' : '0' }} />
            </div>
            <div className="w-12 shrink-0 text-right">
              <div className="text-[11px] font-bold tabular-nums">{count}</div>
              <div className="text-[10px] text-muted-foreground">{pct.toFixed(0)}%</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Empty({ message, positive = false }: { message: string; positive?: boolean }) {
  return <div className={cn('text-xs text-center py-3', positive ? 'text-green-400' : 'text-muted-foreground')}>{message}</div>;
}

function SectionHeading({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">Dashboard Section</div>
        <h2 className="mt-1 text-lg font-semibold tracking-tight text-foreground">{title}</h2>
      </div>
      <p className="max-w-2xl text-sm text-muted-foreground">{description}</p>
    </div>
  );
}

function HeroPill({ icon, children }: { icon: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] px-3 py-1.5 text-xs text-muted-foreground backdrop-blur">
      {icon}
      <span>{children}</span>
    </div>
  );
}

function HeroMetric({ label, value, tone }: { label: string; value: string | number; tone: string }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-white/[0.04] px-3 py-3">
      <div className="text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">{label}</div>
      <div className={cn('mt-2 text-xl font-black tracking-tight', tone)}>{value}</div>
    </div>
  );
}
