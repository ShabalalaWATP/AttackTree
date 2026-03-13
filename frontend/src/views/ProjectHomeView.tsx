import { useState, useEffect, useMemo } from 'react';
import { useStore, type ViewMode } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import type { AnalysisRunData } from '@/types';
import {
  Activity, GitBranch, Brain, FlaskConical, Route, ShieldCheck, LayoutDashboard,
  Target, Clock, ChevronRight, Layers, Network
} from 'lucide-react';
import { useAdvisorPageContext } from '@/hooks/useAdvisorPageContext';

interface ToolCard {
  id: ViewMode;
  label: string;
  icon: React.ReactNode;
  description: string;
  gradient: string;
}

const TOOLS: ToolCard[] = [
  { id: 'tree', label: 'Attack Tree', icon: <GitBranch size={22} />, description: 'Build and visualise attack trees with risk scoring', gradient: 'from-cyan-500/20 to-blue-500/20' },
  { id: 'brainstorm', label: 'Brainstorm', icon: <Brain size={22} />, description: 'AI-powered offensive brainstorming chat', gradient: 'from-purple-500/20 to-fuchsia-500/20' },
  { id: 'scenarios', label: 'Scenarios', icon: <FlaskConical size={22} />, description: 'Plan cyber operations, stress controls, and build scenario libraries', gradient: 'from-violet-500/20 to-purple-500/20' },
  { id: 'kill_chain', label: 'Kill Chain', icon: <Route size={22} />, description: 'Map attacks to kill chain frameworks', gradient: 'from-cyan-500/20 to-teal-500/20' },
  { id: 'threat_model', label: 'Threat Model', icon: <ShieldCheck size={22} />, description: 'DFD generation, STRIDE analysis and threat matrices', gradient: 'from-emerald-500/20 to-green-500/20' },
  { id: 'infra_map', label: 'Infra Map', icon: <Network size={22} />, description: 'Map infrastructure, dependencies, and trust boundaries in depth', gradient: 'from-sky-500/20 to-cyan-500/20' },
  { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={22} />, description: 'Risk analytics, coverage metrics and audit trail', gradient: 'from-amber-500/20 to-orange-500/20' },
];

interface SavedItem {
  id: string;
  name: string;
  tool: string;
  toolView: ViewMode;
  icon: React.ReactNode;
  created_at: string;
  meta: string;
}

export function ProjectHomeView() {
  const { currentProject, nodes, openView } = useStore();
  const [savedItems, setSavedItems] = useState<SavedItem[]>([]);
  const [recentRuns, setRecentRuns] = useState<AnalysisRunData[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!currentProject) { setLoading(false); return; }
    let cancelled = false;

    const load = async () => {
      setLoading(true);
      const items: SavedItem[] = [];
      let runs: AnalysisRunData[] = [];

      try {
        const [scenarios, killChains, threatModels, infraMaps, snapshots, loadedRuns] = await Promise.all([
          api.listScenarios(currentProject.id).catch(() => []),
          api.listKillChains(currentProject.id).catch(() => []),
          api.listThreatModels(currentProject.id).catch(() => []),
          api.listInfraMaps(currentProject.id).catch(() => []),
          api.listSnapshots(currentProject.id).catch(() => []),
          api.listAnalysisRuns(currentProject.id, 12).catch(() => []),
        ]);
        runs = Array.isArray(loadedRuns) ? loadedRuns : [];

        for (const s of scenarios) {
          items.push({
            id: s.id, name: s.name, tool: 'Scenario', toolView: 'scenarios',
            icon: <FlaskConical size={13} className="text-purple-500" />,
            created_at: s.created_at,
            meta: [s.scenario_type, s.attacker_type, s.status].filter(Boolean).join(' · '),
          });
        }
        for (const kc of killChains) {
          items.push({
            id: kc.id, name: kc.name, tool: 'Kill Chain', toolView: 'kill_chain',
            icon: <Route size={13} className="text-cyan-500" />,
            created_at: kc.created_at,
            meta: kc.framework || '',
          });
        }
        for (const tm of threatModels) {
          items.push({
            id: tm.id, name: tm.name, tool: 'Threat Model', toolView: 'threat_model',
            icon: <ShieldCheck size={13} className="text-emerald-500" />,
            created_at: tm.created_at,
            meta: `${tm.methodology?.toUpperCase() || ''} · ${tm.threats?.length || 0} threats`,
          });
        }
        for (const im of infraMaps) {
          items.push({
            id: im.id, name: im.name, tool: 'Infra Map', toolView: 'infra_map',
            icon: <Network size={13} className="text-sky-500" />,
            created_at: im.updated_at || im.created_at,
            meta: `${im.nodes?.length || 0} nodes`,
          });
        }
        for (const snap of snapshots) {
          items.push({
            id: snap.id, name: snap.label || 'Snapshot', tool: 'Snapshot', toolView: 'tree',
            icon: <Clock size={13} className="text-muted-foreground" />,
            created_at: snap.created_at,
            meta: '',
          });
        }

        // Sort newest first
        items.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
      } catch { /* ignore */ }

      if (!cancelled) {
        setSavedItems(items);
        setRecentRuns(runs);
        setLoading(false);
      }
    };

    load();
    return () => { cancelled = true; };
  }, [currentProject?.id]);

  const nodeCount = nodes.length;
  const workspaceLabel = currentProject?.workspace_mode === 'standalone_scan' ? 'Standalone Scan' : 'Project Scan';
  const advisorContext = useMemo(() => ({
    view: 'project_home' as const,
    title: currentProject ? `${currentProject.name} Workspace Home` : 'Workspace Home',
    summary: currentProject?.root_objective || 'Workspace home view with launch shortcuts, saved analyses, and recent run activity.',
    packets: [
      `Workspace mode: ${workspaceLabel}`,
      `Attack tree nodes: ${nodeCount}`,
      `Saved analyses: ${savedItems.filter((item) => item.tool !== 'Snapshot').length}`,
      `Recent runs: ${recentRuns.length}`,
      currentProject?.context_preset ? `Context preset: ${currentProject.context_preset}` : '',
    ],
  }), [currentProject, nodeCount, recentRuns.length, savedItems, workspaceLabel]);
  useAdvisorPageContext(advisorContext);

  if (!currentProject) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
        No workspace open.
      </div>
    );
  }

  const openSavedItem = (item: SavedItem) => {
    if (item.toolView === 'tree') {
      openView('tree');
      return;
    }
    openView(item.toolView, { artifactId: item.id });
  };
  const openRecentRun = (run: AnalysisRunData) => {
    const targetView = toolViewForRun(run);
    const artifactView = runArtifactView(run);
    if (artifactView && run.artifact_id) {
      openView(artifactView, { artifactId: run.artifact_id });
      return;
    }
    if (targetView === 'tree' && run.artifact_kind === 'node' && run.artifact_id) {
      openView('tree', { nodeId: run.artifact_id });
      return;
    }
    openView(targetView);
  };

  return (
    <div className="h-full overflow-auto">
      <div className="max-w-5xl mx-auto px-6 py-8 space-y-8">

        {/* Project hero */}
        <div className="relative overflow-hidden rounded-xl border border-border/40 bg-card/60 backdrop-blur-sm p-6">
          <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-primary/5" />
          <div className="relative">
            <h1 className="text-2xl font-bold">{currentProject.name}</h1>
            {currentProject.root_objective && (
              <p className="text-sm text-muted-foreground mt-1">{currentProject.root_objective}</p>
            )}
            <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
              <span className="px-2 py-1 rounded-full bg-primary/10 text-primary font-medium">{workspaceLabel}</span>
              <span className="flex items-center gap-1"><Layers size={12} /> {nodeCount} nodes</span>
              <span className="flex items-center gap-1"><Target size={12} /> {savedItems.filter(i => i.tool !== 'Snapshot').length} saved analyses</span>
              <span className="flex items-center gap-1"><Activity size={12} /> {recentRuns.length} recent runs</span>
            </div>
          </div>
        </div>

        {/* Tool cards */}
        <div>
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">Launch Tool</h2>
          <div className="grid grid-cols-3 gap-3">
            {TOOLS.map(tool => (
              <button
                key={tool.id}
                onClick={() => openView(tool.id)}
                className="group text-left rounded-xl border border-border/40 bg-card/60 backdrop-blur-sm p-4 hover:border-primary/40 hover:bg-primary/5 transition-all duration-200"
              >
                <div className={cn('w-10 h-10 rounded-lg bg-gradient-to-br flex items-center justify-center mb-3', tool.gradient)}>
                  {tool.icon}
                </div>
                <div className="font-semibold text-sm mb-0.5 flex items-center gap-1.5">
                  {tool.label}
                  <ChevronRight size={12} className="text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed">{tool.description}</p>
              </button>
            ))}
          </div>
        </div>

        <div>
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">
            Recent Runs in This Workspace
          </h2>

          {loading ? (
            <div className="text-center py-8 text-sm text-muted-foreground">Loading…</div>
          ) : recentRuns.length === 0 ? (
            <div className="rounded-xl border border-border/40 bg-card/60 backdrop-blur-sm p-8 text-center">
              <p className="text-sm text-muted-foreground">No project analysis runs recorded yet.</p>
            </div>
          ) : (
            <div className="rounded-xl border border-border/40 bg-card/60 backdrop-blur-sm overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/40 text-[11px] text-muted-foreground uppercase tracking-wider">
                    <th className="text-left px-4 py-2.5 font-medium">Action</th>
                    <th className="text-left px-4 py-2.5 font-medium">Asset</th>
                    <th className="text-left px-4 py-2.5 font-medium">Summary</th>
                    <th className="text-left px-4 py-2.5 font-medium">Status</th>
                    <th className="text-left px-4 py-2.5 font-medium">When</th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {recentRuns.map((run) => (
                    <tr
                      key={run.id}
                      className="border-b border-border/20 hover:bg-white/5 cursor-pointer transition-colors"
                      onClick={() => openRecentRun(run)}
                    >
                      <td className="px-4 py-2.5 font-medium">{formatRunType(run.run_type)}</td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{run.artifact_name || currentProject.name}</td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground max-w-[320px] truncate">{run.summary || 'No summary available'}</td>
                      <td className="px-4 py-2.5">
                        <span className={cn('inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium border', runStatusClass(run.status))}>
                          {formatRunStatus(run.status)}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground tabular-nums">
                        {formatRunTimestamp(run.created_at, run.duration_ms)}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <ChevronRight size={13} className="text-muted-foreground" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Saved work table */}
        <div>
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">
            Saved Work in This Workspace
          </h2>

          {loading ? (
            <div className="text-center py-8 text-sm text-muted-foreground">Loading…</div>
          ) : savedItems.length === 0 ? (
            <div className="rounded-xl border border-border/40 bg-card/60 backdrop-blur-sm p-8 text-center">
              <p className="text-sm text-muted-foreground">No saved analyses yet. Launch a tool above to get started.</p>
            </div>
          ) : (
            <div className="rounded-xl border border-border/40 bg-card/60 backdrop-blur-sm overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border/40 text-[11px] text-muted-foreground uppercase tracking-wider">
                    <th className="text-left px-4 py-2.5 font-medium">Name</th>
                    <th className="text-left px-4 py-2.5 font-medium">Tool</th>
                    <th className="text-left px-4 py-2.5 font-medium">Details</th>
                    <th className="text-left px-4 py-2.5 font-medium">Created</th>
                    <th className="px-4 py-2.5" />
                  </tr>
                </thead>
                <tbody>
                  {savedItems.map(item => (
                    <tr
                      key={item.id}
                      className="border-b border-border/20 hover:bg-white/5 cursor-pointer transition-colors"
                      onClick={() => openSavedItem(item)}
                    >
                      <td className="px-4 py-2.5 font-medium truncate max-w-[220px]">{item.name}</td>
                      <td className="px-4 py-2.5">
                        <span className="flex items-center gap-1.5 text-xs">
                          {item.icon} {item.tool}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground">{item.meta}</td>
                      <td className="px-4 py-2.5 text-xs text-muted-foreground tabular-nums">
                        {formatDate(item.created_at)}
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <ChevronRight size={13} className="text-muted-foreground" />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function formatDate(iso: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return '';
  const now = new Date();
  const diff = now.getTime() - d.getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

function formatRunType(value: string): string {
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function formatRunStatus(value: string): string {
  if (value === 'completed') return 'Completed';
  if (value === 'partial') return 'Partial';
  if (value === 'running') return 'Running';
  if (value === 'queued') return 'Queued';
  if (value === 'failed') return 'Failed';
  return 'Unknown';
}

function formatRunTimestamp(iso: string, durationMs: number): string {
  const stamp = formatDate(iso);
  if (!durationMs) return stamp;
  const seconds = Math.round(durationMs / 1000);
  if (seconds < 60) return `${stamp} · ${seconds}s`;
  const minutes = Math.round(seconds / 60);
  return `${stamp} · ${minutes}m`;
}

function runStatusClass(status: string): string {
  if (status === 'completed') return 'border-emerald-500/20 bg-emerald-500/10 text-emerald-300';
  if (status === 'partial') return 'border-amber-500/20 bg-amber-500/10 text-amber-300';
  if (status === 'running' || status === 'queued') return 'border-blue-500/20 bg-blue-500/10 text-blue-300';
  if (status === 'failed') return 'border-red-500/20 bg-red-500/10 text-red-300';
  return 'border-border/40 bg-background/40 text-muted-foreground';
}

function toolViewForRun(run: AnalysisRunData): ViewMode {
  if (run.tool === 'attack_tree') return 'tree';
  if (run.tool === 'brainstorm') return 'brainstorm';
  if (run.tool === 'scenario') return 'scenarios';
  if (run.tool === 'kill_chain') return 'kill_chain';
  if (run.tool === 'threat_model') return 'threat_model';
  if (run.tool === 'infra_map') return 'infra_map';
  return 'dashboard';
}

function runArtifactView(run: AnalysisRunData): ViewMode | null {
  if (!run.artifact_id) return null;
  if (run.artifact_kind === 'scenario') return 'scenarios';
  if (run.artifact_kind === 'kill_chain') return 'kill_chain';
  if (run.artifact_kind === 'threat_model') return 'threat_model';
  if (run.artifact_kind === 'infra_map') return 'infra_map';
  return null;
}
