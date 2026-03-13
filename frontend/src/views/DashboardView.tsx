import { useEffect, useMemo, useState } from 'react';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import {
  NODE_TYPE_CONFIG,
  type ArtifactCountsData,
  type AttackNodeData,
  type DashboardAnalysisData,
  type DashboardNodeSummaryData,
  type DashboardPortfolioData,
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

interface ArtifactCounts {
  scenarios: number;
  killChains: number;
  threatModels: number;
  infraMaps: number;
  snapshots: number;
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
  criticalCount: number;
  mitigationPct: number;
  detectionPct: number;
  mappingPct: number;
  topRisks: AttackNodeData[];
  unmitigated: AttackNodeData[];
  byType: Record<string, number>;
  byStatus: Record<string, number>;
  bySurface: Record<string, number>;
  riskBuckets: Array<{ label: string; count: number; color: string }>;
}

const EMPTY_ARTIFACTS: ArtifactCounts = { scenarios: 0, killChains: 0, threatModels: 0, infraMaps: 0, snapshots: 0 };
const EMPTY_ANALYSIS: NodeAnalysis = {
  totalNodes: 0,
  scored: 0,
  avgRisk: 0,
  maxRisk: 0,
  criticalCount: 0,
  mitigationPct: 0,
  detectionPct: 0,
  mappingPct: 0,
  topRisks: [],
  unmitigated: [],
  byType: {},
  byStatus: {},
  bySurface: {},
  riskBuckets: [
    { label: 'Low', count: 0, color: 'bg-emerald-500' },
    { label: 'Guarded', count: 0, color: 'bg-blue-500' },
    { label: 'Medium', count: 0, color: 'bg-amber-500' },
    { label: 'High', count: 0, color: 'bg-orange-500' },
    { label: 'Critical', count: 0, color: 'bg-red-500' },
  ],
};
const EMPTY_PORTFOLIO = {
  metrics: [] as WorkspaceBundle[],
  aggregate: EMPTY_ANALYSIS,
  totalArtifacts: { ...EMPTY_ARTIFACTS },
  workspaceCount: 0,
  projectScans: 0,
  standaloneScans: 0,
  contexts: {} as Record<string, number>,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object';
}

function normalizeNodeList(value: unknown): AttackNodeData[] {
  if (!Array.isArray(value)) return [];
  return value.filter((node): node is AttackNodeData => (
    isRecord(node)
    && typeof node.id === 'string'
    && typeof node.title === 'string'
    && typeof node.node_type === 'string'
  ));
}

function normalizeArtifactCounts(value: ArtifactCountsData | null | undefined): ArtifactCounts {
  return {
    scenarios: value?.scenarios ?? 0,
    killChains: value?.kill_chains ?? 0,
    threatModels: value?.threat_models ?? 0,
    infraMaps: value?.infra_maps ?? 0,
    snapshots: value?.snapshots ?? 0,
  };
}

function normalizeDashboardNode(value: DashboardNodeSummaryData): AttackNodeData {
  return {
    id: value.id,
    project_id: '',
    parent_id: null,
    node_type: (value.node_type as NodeType) || 'attack_step',
    title: value.title,
    description: '',
    notes: '',
    logic_type: 'OR',
    status: (value.status as AttackNodeData['status']) || 'draft',
    sort_order: 0,
    position_x: 0,
    position_y: 0,
    threat_category: '',
    attack_surface: value.attack_surface || '',
    platform: value.platform || '',
    required_access: value.required_access || '',
    required_privileges: '',
    required_tools: '',
    required_skill: '',
    likelihood: null,
    impact: null,
    effort: null,
    exploitability: null,
    detectability: null,
    confidence: null,
    inherent_risk: value.inherent_risk,
    residual_risk: value.residual_risk,
    probability: null,
    cost_to_attacker: null,
    time_estimate: '',
    rolled_up_risk: null,
    rolled_up_likelihood: null,
    assumptions: '',
    analyst: '',
    cve_references: '',
    extended_metadata: {},
    created_at: '',
    updated_at: '',
    mitigations: [],
    detections: [],
    reference_mappings: [],
    tags: [],
  };
}

function normalizeDashboardAnalysis(value: DashboardAnalysisData | null | undefined): NodeAnalysis {
  if (!value) return EMPTY_ANALYSIS;
  return {
    totalNodes: value.total_nodes ?? 0,
    scored: value.scored ?? 0,
    avgRisk: value.avg_risk ?? 0,
    maxRisk: value.max_risk ?? 0,
    criticalCount: value.critical_count ?? 0,
    mitigationPct: value.mitigation_pct ?? 0,
    detectionPct: value.detection_pct ?? 0,
    mappingPct: value.mapping_pct ?? 0,
    topRisks: Array.isArray(value.top_risks) ? value.top_risks.map(normalizeDashboardNode) : [],
    unmitigated: Array.isArray(value.unmitigated) ? value.unmitigated.map(normalizeDashboardNode) : [],
    byType: value.by_type ?? {},
    byStatus: value.by_status ?? {},
    bySurface: value.by_surface ?? {},
    riskBuckets: Array.isArray(value.risk_buckets)
      ? value.risk_buckets.map(bucket => ({ label: bucket.label, count: bucket.count, color: bucket.color }))
      : EMPTY_ANALYSIS.riskBuckets,
  };
}

function normalizeWorkspaceSummary(value: DashboardWorkspaceSummaryData): WorkspaceBundle {
  return {
    project: value.project,
    artifacts: normalizeArtifactCounts(value.artifacts),
    analysis: normalizeDashboardAnalysis(value.analysis),
    totalArtifacts: value.total_artifacts ?? 0,
  };
}

function normalizePortfolio(value: DashboardPortfolioData | null | undefined) {
  if (!value) return EMPTY_PORTFOLIO;
  const metrics = Array.isArray(value.workspaces) ? value.workspaces.map(normalizeWorkspaceSummary) : [];
  return {
    metrics,
    aggregate: normalizeDashboardAnalysis(value.aggregate),
    totalArtifacts: normalizeArtifactCounts(value.artifact_totals),
    workspaceCount: metrics.length,
    projectScans: value.project_scans ?? 0,
    standaloneScans: value.standalone_scans ?? 0,
    contexts: Object.fromEntries(
      Object.entries(value.contexts ?? {}).map(([context, count]) => [formatContext(context), count])
    ),
  };
}

function countItems(value: unknown): number {
  return Array.isArray(value) ? value.length : 0;
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

function analyze(nodes: AttackNodeData[]): NodeAnalysis {
  const scored = nodes.filter(node => node.inherent_risk != null);
  const topRisks = [...scored].sort((a, b) => (b.inherent_risk || 0) - (a.inherent_risk || 0)).slice(0, 10);
  const unmitigated = scored.filter(node => !node.mitigations?.length).sort((a, b) => (b.inherent_risk || 0) - (a.inherent_risk || 0));
  const byType: Record<string, number> = {};
  const byStatus: Record<string, number> = {};
  const bySurface: Record<string, number> = {};
  const mitigated = nodes.filter(node => node.mitigations?.length).length;
  const withDetections = nodes.filter(node => node.detections?.length).length;
  const withMappings = nodes.filter(node => node.reference_mappings?.length).length;

  nodes.forEach(node => {
    byType[node.node_type] = (byType[node.node_type] || 0) + 1;
    byStatus[node.status] = (byStatus[node.status] || 0) + 1;
    bySurface[node.attack_surface || 'Unknown'] = (bySurface[node.attack_surface || 'Unknown'] || 0) + 1;
  });

  const avgRisk = scored.length ? scored.reduce((sum, node) => sum + (node.inherent_risk || 0), 0) / scored.length : 0;
  const maxRisk = scored.length ? Math.max(...scored.map(node => node.inherent_risk || 0)) : 0;
  const criticalCount = scored.filter(node => (node.inherent_risk || 0) >= 8).length;
  const riskBuckets = [
    { label: 'Low', min: 0, max: 2, count: 0, color: 'bg-emerald-500' },
    { label: 'Guarded', min: 2, max: 4, count: 0, color: 'bg-blue-500' },
    { label: 'Medium', min: 4, max: 6, count: 0, color: 'bg-amber-500' },
    { label: 'High', min: 6, max: 8, count: 0, color: 'bg-orange-500' },
    { label: 'Critical', min: 8, max: 10.1, count: 0, color: 'bg-red-500' },
  ];
  scored.forEach(node => {
    const bucket = riskBuckets.find(item => (node.inherent_risk || 0) >= item.min && (node.inherent_risk || 0) < item.max);
    if (bucket) bucket.count += 1;
  });

  return {
    totalNodes: nodes.length,
    scored: scored.length,
    avgRisk,
    maxRisk,
    criticalCount,
    mitigationPct: nodes.length ? (mitigated / nodes.length) * 100 : 0,
    detectionPct: nodes.length ? (withDetections / nodes.length) * 100 : 0,
    mappingPct: nodes.length ? (withMappings / nodes.length) * 100 : 0,
    topRisks,
    unmitigated,
    byType,
    byStatus,
    bySurface,
    riskBuckets: riskBuckets.map(({ label, count, color }) => ({ label, count, color })),
  };
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

export function DashboardView() {
  const { currentProject, nodes } = useStore();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [refreshTick, setRefreshTick] = useState(0);
  const [projectArtifacts, setProjectArtifacts] = useState<ArtifactCounts>(EMPTY_ARTIFACTS);
  const [portfolio, setPortfolio] = useState(EMPTY_PORTFOLIO);
  const safeProjectNodes = useMemo(() => normalizeNodeList(nodes), [nodes]);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setError('');
      try {
        if (currentProject) {
          if (!cancelled) setPortfolio(EMPTY_PORTFOLIO);
          const [scenarios, killChains, threatModels, infraMaps, snapshots] = await Promise.all([
            api.listScenarios(currentProject.id).catch(() => []),
            api.listKillChains(currentProject.id).catch(() => []),
            api.listThreatModels(currentProject.id).catch(() => []),
            api.listInfraMaps(currentProject.id).catch(() => []),
            api.listSnapshots(currentProject.id).catch(() => []),
          ]);
          if (!cancelled) {
            setProjectArtifacts({
              scenarios: countItems(scenarios),
              killChains: countItems(killChains),
              threatModels: countItems(threatModels),
              infraMaps: countItems(infraMaps),
              snapshots: countItems(snapshots),
            });
          }
        } else {
          if (!cancelled) setProjectArtifacts({ ...EMPTY_ARTIFACTS });
          const dashboard = await api.getDashboardPortfolio();
          if (!cancelled) setPortfolio(normalizePortfolio(dashboard));
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

  const projectAnalysis = useMemo(() => analyze(safeProjectNodes), [safeProjectNodes]);

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

  return (
    <div className="h-full overflow-auto">
      <div className="relative px-6 pt-6 pb-4 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan-500/5 via-blue-500/5 to-purple-500/5" />
        <div className="relative max-w-7xl mx-auto">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div>
              <h1 className="text-xl font-bold">{currentProject?.name ?? 'Portfolio Dashboard'}</h1>
              <p className="text-sm text-muted-foreground mt-0.5">
                {currentProject?.root_objective || 'Cross-workspace statistics, risk posture, and analysis coverage across all scans'}
              </p>
              {!currentProject && (
                <div className="flex items-center gap-3 mt-2 text-xs text-muted-foreground">
                  <span>{portfolio.workspaceCount} workspaces</span>
                  <span>{portfolio.projectScans} project scans</span>
                  <span>{portfolio.standaloneScans} standalone scans</span>
                </div>
              )}
            </div>
            <div className="flex items-center gap-3">
              <button onClick={() => setRefreshTick(value => value + 1)} className="p-2 rounded-lg border border-border/40 hover:bg-white/5" title="Refresh dashboard">
                <RefreshCw size={14} />
              </button>
              <div className="text-right">
                <div className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Risk Posture</div>
                <div className="text-xs text-muted-foreground">{grade.label}</div>
              </div>
              <div className={cn('w-12 h-12 rounded-xl bg-gradient-to-br flex items-center justify-center shadow-lg', grade.gradient)}>
                <span className="text-white text-xl font-black">{grade.letter}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="px-6 pb-6">
        <div className="max-w-7xl mx-auto space-y-5">
          <div className="grid grid-cols-6 gap-3">
            {currentProject ? (
              <>
                <StatCard icon={<Target size={14} className="text-cyan-400" />} label="Total Nodes" value={active.totalNodes} subtext={`${active.scored} scored`} accent="from-cyan-500/20 to-blue-500/20" />
                <StatCard icon={<BarChart3 size={14} className="text-amber-400" />} label="Avg Risk" value={active.avgRisk.toFixed(1)} subtext={`max: ${active.maxRisk.toFixed(1)}`} accent="from-amber-500/20 to-red-500/20" valueClass={riskText(active.avgRisk)} />
                <StatCard icon={<AlertTriangle size={14} className="text-red-400" />} label="Critical" value={active.criticalCount} subtext="risk >= 8.0" accent="from-red-500/20 to-rose-500/20" valueClass="text-red-400" />
                <StatCard icon={<Shield size={14} className="text-green-400" />} label="Mitigated" value={`${active.mitigationPct.toFixed(0)}%`} subtext="nodes with controls" accent="from-green-500/20 to-emerald-500/20" valueClass="text-green-400" />
                <StatCard icon={<Eye size={14} className="text-blue-400" />} label="Detection" value={`${active.detectionPct.toFixed(0)}%`} subtext="nodes with detections" accent="from-blue-500/20 to-indigo-500/20" valueClass="text-blue-400" />
                <StatCard icon={<Layers size={14} className="text-purple-400" />} label="Analyses" value={artifactTotal(artifacts)} subtext={`${artifacts.infraMaps} maps · ${artifacts.scenarios} scenarios`} accent="from-purple-500/20 to-fuchsia-500/20" valueClass="text-purple-400" />
              </>
            ) : (
              <>
                <StatCard icon={<FolderOpen size={14} className="text-cyan-400" />} label="Workspaces" value={portfolio.workspaceCount} subtext={`${portfolio.projectScans} project · ${portfolio.standaloneScans} standalone`} accent="from-cyan-500/20 to-blue-500/20" />
                <StatCard icon={<Target size={14} className="text-emerald-400" />} label="Total Nodes" value={active.totalNodes} subtext={`${active.scored} scored`} accent="from-emerald-500/20 to-green-500/20" />
                <StatCard icon={<BarChart3 size={14} className="text-amber-400" />} label="Avg Risk" value={active.avgRisk.toFixed(1)} subtext={`max: ${active.maxRisk.toFixed(1)}`} accent="from-amber-500/20 to-red-500/20" valueClass={riskText(active.avgRisk)} />
                <StatCard icon={<AlertTriangle size={14} className="text-red-400" />} label="Critical" value={active.criticalCount} subtext="risk >= 8.0" accent="from-red-500/20 to-rose-500/20" valueClass="text-red-400" />
                <StatCard icon={<Layers size={14} className="text-purple-400" />} label="Analyses" value={artifactTotal(artifacts)} subtext={`${artifacts.threatModels} threat models · ${artifacts.infraMaps} maps`} accent="from-purple-500/20 to-fuchsia-500/20" valueClass="text-purple-400" />
                <StatCard icon={<Shield size={14} className="text-blue-400" />} label="Coverage" value={`${active.mitigationPct.toFixed(0)}%`} subtext={`${active.detectionPct.toFixed(0)}% detection`} accent="from-blue-500/20 to-indigo-500/20" valueClass="text-blue-400" />
              </>
            )}
          </div>

          <Card>
            <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Defence Coverage</h3>
            <div className="grid grid-cols-3 gap-6">
              <CoverageBar label="Mitigation" pct={active.mitigationPct} gradient="from-green-500 to-emerald-400" />
              <CoverageBar label="Detection" pct={active.detectionPct} gradient="from-blue-500 to-cyan-400" />
              <CoverageBar label="Framework Mapping" pct={active.mappingPct} gradient="from-purple-500 to-fuchsia-400" />
            </div>
          </Card>

          <div className="grid grid-cols-3 gap-5">
            <Card className="col-span-1">
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
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

            <Card className="col-span-2">
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

          <div className="grid grid-cols-2 gap-5">
            {currentProject ? (
              <>
                <Card>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Unmitigated Risks</h3>
                  <div className="space-y-0.5">
                    {projectAnalysis.unmitigated.slice(0, 8).map(node => (
                      <div key={node.id} className="flex items-center justify-between py-1.5 px-2 rounded-lg hover:bg-white/5 text-xs">
                        <span className="truncate mr-2">{node.title}</span>
                        <span className={cn('font-bold tabular-nums', riskText(node.inherent_risk || 0))}>{(node.inherent_risk || 0).toFixed(1)}</span>
                      </div>
                    ))}
                    {!projectAnalysis.unmitigated.length && <Empty message="All scored nodes have mitigations attached" positive />}
                  </div>
                </Card>

                <Card>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Analysis Coverage</h3>
                  <div className="grid grid-cols-2 gap-3">
                    <MiniStat icon={<FlaskConical size={12} className="text-violet-400" />} label="Scenarios" value={artifacts.scenarios} />
                    <MiniStat icon={<Route size={12} className="text-cyan-400" />} label="Kill Chains" value={artifacts.killChains} />
                    <MiniStat icon={<ShieldCheck size={12} className="text-emerald-400" />} label="Threat Models" value={artifacts.threatModels} />
                    <MiniStat icon={<Network size={12} className="text-sky-400" />} label="Infra Maps" value={artifacts.infraMaps} />
                  </div>
                </Card>
              </>
            ) : (
              <>
                <Card>
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
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
                  <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
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
              </>
            )}
          </div>

          <div className="grid grid-cols-2 gap-5">
            <Card>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Node Types</h3>
              <MetricBars entries={active.byType} total={active.totalNodes} formatter={(key) => NODE_TYPE_CONFIG[key as NodeType]?.label || key} iconFormatter={(key) => NODE_TYPE_CONFIG[key as NodeType]?.icon || ''} />
            </Card>
            <Card>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Top Attack Surfaces</h3>
              <MetricBars entries={active.bySurface} total={active.totalNodes} formatter={(key) => key} />
            </Card>
          </div>

          {currentProject ? (
            <Card>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-1.5">
                <Clock size={13} className="text-primary" /> Recent Activity
              </h3>
              <AuditLogPanel projectId={currentProject.id} />
            </Card>
          ) : (
            <Card>
              <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">Workspaces by Context</h3>
              {Object.keys(portfolio.contexts).length ? (
                <div className="grid grid-cols-3 gap-3">
                  {Object.entries(portfolio.contexts).sort((a, b) => b[1] - a[1]).slice(0, 9).map(([context, count]) => (
                    <div key={context} className="rounded-lg border border-border/30 bg-background/30 px-3 py-2">
                      <div className="text-xs font-medium truncate">{context}</div>
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
  return <div className={cn('rounded-xl border border-border/40 bg-card/60 backdrop-blur-sm p-4', className)}>{children}</div>;
}

function StatCard({ icon, label, value, subtext, accent, valueClass }: { icon: React.ReactNode; label: string; value: string | number; subtext: string; accent: string; valueClass?: string }) {
  return (
    <Card>
      <div className="flex items-center gap-2 mb-2">
        <div className={cn('w-7 h-7 rounded-lg bg-gradient-to-br flex items-center justify-center', accent)}>{icon}</div>
        <span className="text-[11px] text-muted-foreground font-medium">{label}</span>
      </div>
      <div className={cn('text-2xl font-black', valueClass)}>{value}</div>
      <div className="text-[10px] text-muted-foreground">{subtext}</div>
    </Card>
  );
}

function CoverageBar({ label, pct, gradient }: { label: string; pct: number; gradient: string }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-medium">{label}</span>
        <span className="text-sm font-bold tabular-nums">{pct.toFixed(0)}%</span>
      </div>
      <div className="h-2.5 bg-muted/50 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full bg-gradient-to-r', gradient)} style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

function MiniStat({ icon, label, value }: { icon: React.ReactNode; label: string; value: number }) {
  return <div className="rounded-lg border border-border/30 bg-background/30 px-3 py-2"><div className="flex items-center gap-2 text-[11px] text-muted-foreground">{icon}{label}</div><div className="text-lg font-semibold mt-1">{value}</div></div>;
}

function MetricBars({ entries, total, formatter, iconFormatter }: { entries: Record<string, number>; total: number; formatter: (key: string) => string; iconFormatter?: (key: string) => string }) {
  const sorted = Object.entries(entries).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (!sorted.length) return <Empty message="No metrics available yet" />;
  return (
    <div className="space-y-1.5">
      {sorted.map(([key, count]) => {
        const pct = total ? (count / total) * 100 : 0;
        return (
          <div key={key} className="flex items-center gap-2">
            <span className="flex items-center gap-1.5 w-32 shrink-0 text-[11px]">
              {iconFormatter && <span className="opacity-70">{iconFormatter(key)}</span>}
              <span className="truncate">{formatter(key)}</span>
            </span>
            <div className="flex-1 h-4 bg-muted/50 rounded-full overflow-hidden">
              <div className="h-full rounded-full bg-primary/50" style={{ width: `${pct}%`, minWidth: count > 0 ? '6px' : '0' }} />
            </div>
            <span className="text-[11px] font-bold w-8 text-right tabular-nums">{count}</span>
          </div>
        );
      })}
    </div>
  );
}

function Empty({ message, positive = false }: { message: string; positive?: boolean }) {
  return <div className={cn('text-xs text-center py-3', positive ? 'text-green-400' : 'text-muted-foreground')}>{message}</div>;
}
