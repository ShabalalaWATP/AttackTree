import { useState, useEffect, useMemo, useCallback } from 'react';
import type { PlanningProfile } from '@/types';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import { StandaloneLanding } from '@/components/StandaloneLanding';
import { getPlanningProfileOption, PLANNING_PROFILE_OPTIONS } from '@/utils/planningProfiles';
import toast from 'react-hot-toast';
import {
  Route, Plus, Trash2, Brain, Loader2, Sparkles, Clock,
  Eye, ShieldAlert, ChevronDown, ChevronRight, Zap, X,
  Timer, AlertTriangle, Target, BarChart3,
  Crosshair, Shield, Terminal, FileSearch, ChevronsDown, ChevronsUp,
  ExternalLink, Wrench, Radio, BookOpen, Gauge
} from 'lucide-react';

import { MarkdownContent } from '@/components/MarkdownContent';
import { ConfirmDialog } from '@/components/ConfirmDialog';

/* ───── Types ───── */

interface MappedNode {
  node_id: string;
  node_title: string;
  technique_id?: string;
  technique_name?: string;
  technique?: string; // backward compat
  confidence: number;
}

interface KillChainPhase {
  phase: string;
  phase_index: number;
  description: string;
  mapped_nodes: MappedNode[];
  tools: string[];
  iocs: string[];
  log_sources: string[];
  detection_window: string;
  dwell_time: string;
  break_opportunities: string[];
  difficulty: string;
  defensive_coverage: string;
  coverage_notes: string;
}

interface Recommendation {
  priority: string;
  title: string;
  description: string;
  addresses_phases?: string[];
  effort?: string;
}

interface KillChainAnalysisMetadata {
  generation_warnings: string[];
  generation_strategy?: string;
  generation_status?: string;
  current_stage?: string;
  chunk_count?: number;
  pending_chunk_count?: number;
  pending_chunk_ids: string[];
  synthesis_status?: string;
}

interface KillChainData {
  id: string;
  project_id: string;
  name: string;
  description: string;
  framework: string;
  ai_summary: string;
  phases: KillChainPhase[];
  recommendations: Recommendation[];
  total_estimated_time?: string;
  weakest_links?: string[];
  overall_risk_rating?: string;
  attack_complexity?: string;
  coverage_score?: number;
  critical_path?: string;
  analysis_metadata: KillChainAnalysisMetadata;
  created_at: string;
}

/* ───── Helpers ───── */

function isRecord(value: unknown): value is Record<string, any> {
  return !!value && typeof value === 'object';
}

function stringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeMappedNodes(value: unknown, fallbackNodeIds?: unknown): MappedNode[] {
  if (Array.isArray(value)) {
    return value
      .filter(isRecord)
      .map((item) => ({
        node_id: typeof item.node_id === 'string' ? item.node_id : '',
        node_title: typeof item.node_title === 'string' && item.node_title.trim() ? item.node_title : (typeof item.node_id === 'string' ? item.node_id : 'Unknown node'),
        technique_id: typeof item.technique_id === 'string' ? item.technique_id : undefined,
        technique_name: typeof item.technique_name === 'string' ? item.technique_name : undefined,
        technique: typeof item.technique === 'string' ? item.technique : undefined,
        confidence: typeof item.confidence === 'number' ? item.confidence : 0,
      }))
      .filter((item) => item.node_id);
  }

  if (Array.isArray(fallbackNodeIds)) {
    return fallbackNodeIds
      .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
      .map((id) => ({ node_id: id, node_title: id, technique: '', confidence: 0.8 }));
  }

  return [];
}

function normalizePhases(phases: unknown): KillChainPhase[] {
  if (!Array.isArray(phases)) return [];
  return phases.filter(isRecord).map((p, i) => {
    return {
      phase: typeof p.phase === 'string' ? p.phase : '',
      phase_index: typeof p.phase_index === 'number' ? p.phase_index : (typeof p.order === 'number' ? p.order : i + 1),
      description: typeof p.description === 'string' ? p.description : '',
      mapped_nodes: normalizeMappedNodes(p.mapped_nodes, p.node_ids),
      tools: stringList(p.tools),
      iocs: stringList(p.iocs),
      log_sources: stringList(p.log_sources),
      detection_window: typeof p.detection_window === 'string' ? p.detection_window : '',
      dwell_time: typeof p.dwell_time === 'string' ? p.dwell_time : '',
      break_opportunities: stringList(p.break_opportunities),
      difficulty: typeof p.difficulty === 'string' && p.difficulty.trim() ? p.difficulty : 'moderate',
      defensive_coverage: typeof p.defensive_coverage === 'string' && p.defensive_coverage.trim() ? p.defensive_coverage : 'none',
      coverage_notes: typeof p.coverage_notes === 'string' ? p.coverage_notes : '',
    };
  });
}

function normalizeRecommendations(value: unknown): Recommendation[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter(isRecord)
    .map((item) => ({
      priority: typeof item.priority === 'string' && item.priority.trim() ? item.priority : 'medium',
      title: typeof item.title === 'string' ? item.title : 'Untitled recommendation',
      description: typeof item.description === 'string' ? item.description : '',
      addresses_phases: stringList(item.addresses_phases),
      effort: typeof item.effort === 'string' ? item.effort : undefined,
    }));
}

function normalizeKillChain(data: any): KillChainData {
  return {
    ...data,
    description: typeof data?.description === 'string' ? data.description : '',
    framework: typeof data?.framework === 'string' ? data.framework : 'mitre_attck',
    ai_summary: typeof data?.ai_summary === 'string' ? data.ai_summary : '',
    phases: normalizePhases(data?.phases),
    recommendations: normalizeRecommendations(data?.recommendations),
    total_estimated_time: typeof data?.total_estimated_time === 'string' ? data.total_estimated_time : undefined,
    weakest_links: stringList(data?.weakest_links),
    overall_risk_rating: typeof data?.overall_risk_rating === 'string' ? data.overall_risk_rating : undefined,
    attack_complexity: typeof data?.attack_complexity === 'string' ? data.attack_complexity : undefined,
    coverage_score: typeof data?.coverage_score === 'number' ? data.coverage_score : undefined,
    critical_path: typeof data?.critical_path === 'string' ? data.critical_path : undefined,
    analysis_metadata: isRecord(data?.analysis_metadata)
      ? {
          generation_warnings: stringList(data.analysis_metadata.generation_warnings),
          generation_strategy: typeof data.analysis_metadata.generation_strategy === 'string' ? data.analysis_metadata.generation_strategy : undefined,
          generation_status: typeof data.analysis_metadata.generation_status === 'string' ? data.analysis_metadata.generation_status : undefined,
          current_stage: typeof data.analysis_metadata.current_stage === 'string' ? data.analysis_metadata.current_stage : undefined,
          chunk_count: typeof data.analysis_metadata.chunk_count === 'number' ? data.analysis_metadata.chunk_count : undefined,
          pending_chunk_count: typeof data.analysis_metadata.pending_chunk_count === 'number' ? data.analysis_metadata.pending_chunk_count : undefined,
          pending_chunk_ids: stringList(data.analysis_metadata.pending_chunk_ids),
          synthesis_status: typeof data.analysis_metadata.synthesis_status === 'string' ? data.analysis_metadata.synthesis_status : undefined,
        }
      : {
          generation_warnings: [],
          pending_chunk_ids: [],
        },
  };
}

const FRAMEWORKS = [
  { id: 'mitre_attck', label: 'MITRE ATT&CK', phases: 14 },
  { id: 'cyber_kill_chain', label: 'Lockheed Martin Cyber Kill Chain', phases: 7 },
  { id: 'unified', label: 'Unified Kill Chain', phases: 18 },
];

const DIFFICULTY_COLORS: Record<string, string> = {
  trivial: 'bg-green-500',
  easy: 'bg-lime-500',
  moderate: 'bg-yellow-500',
  hard: 'bg-orange-500',
  very_hard: 'bg-red-500',
  'very hard': 'bg-red-500',
};

const DIFFICULTY_TEXT: Record<string, string> = {
  trivial: 'text-green-500',
  easy: 'text-lime-500',
  moderate: 'text-yellow-500',
  hard: 'text-orange-500',
  very_hard: 'text-red-500',
  'very hard': 'text-red-500',
};

const COVERAGE_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  none: { bg: 'bg-red-500/15', text: 'text-red-400', label: 'No Coverage' },
  minimal: { bg: 'bg-orange-500/15', text: 'text-orange-400', label: 'Minimal' },
  partial: { bg: 'bg-yellow-500/15', text: 'text-yellow-400', label: 'Partial' },
  good: { bg: 'bg-blue-500/15', text: 'text-blue-400', label: 'Good' },
  strong: { bg: 'bg-green-500/15', text: 'text-green-400', label: 'Strong' },
};

const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-500',
  high: 'text-orange-500',
  medium: 'text-yellow-500',
  low: 'text-green-500',
};

const PRIORITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-500 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-500 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-600 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-500 border-blue-500/30',
};

/* ───── Component ───── */

export function KillChainView() {
  const { currentProject, nodes, setNodes, setViewMode, setSelectedNodeId } = useStore();
  const [killChains, setKillChains] = useState<KillChainData[]>([]);
  const [selected, setSelected] = useState<KillChainData | null>(null);
  const [genLoading, setGenLoading] = useState(false);
  const [mapLoading, setMapLoading] = useState(false);
  const [createFramework, setCreateFramework] = useState('mitre_attck');
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState('');
  const [expandedPhases, setExpandedPhases] = useState<Set<number>>(new Set());
  const [nodesChecked, setNodesChecked] = useState(false);
  const [activeTab, setActiveTab] = useState<'timeline' | 'summary' | 'recommendations'>('timeline');
  const [userGuidance, setUserGuidance] = useState('');
  const [planningProfile, setPlanningProfile] = useState<PlanningProfile>('planning_first');
  const [showGuidance, setShowGuidance] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const selectedPlanningProfile = useMemo(() => getPlanningProfileOption(planningProfile), [planningProfile]);

  // Reset project-scoped state and always reload the current project's nodes.
  useEffect(() => {
    setSelected(null);
    setKillChains([]);
    setExpandedPhases(new Set());
    setActiveTab('timeline');
    setUserGuidance('');
    setNodesChecked(false);

    if (!currentProject) {
      setNodes([]);
      return;
    }
    let cancelled = false;

    api.listNodes(currentProject.id)
      .then((data) => {
        if (!cancelled) setNodes(Array.isArray(data) ? data : []);
      })
      .catch(() => {
        if (!cancelled) setNodes([]);
      })
      .finally(() => {
        if (!cancelled) setNodesChecked(true);
      });

    return () => { cancelled = true; };
  }, [currentProject?.id, setNodes]);

  useEffect(() => {
    if (!currentProject) return;

    let cancelled = false;
    api.listKillChains(currentProject.id)
      .then((data) => {
        if (cancelled) return;
        const normalized = Array.isArray(data) ? data.map((kc: any) => normalizeKillChain(kc)) : [];
        setKillChains(normalized);
      })
      .catch((e: any) => {
        if (!cancelled) toast.error(e.message);
      });

    return () => { cancelled = true; };
  }, [currentProject?.id]);

  const handleCreate = async () => {
    if (!currentProject) { toast('Open a workspace to create kill chains', { icon: '📂' }); return; }
    try {
      const kc = await api.createKillChain({
        project_id: currentProject.id,
        name: createName || `Kill Chain (${FRAMEWORKS.find(f => f.id === createFramework)?.label})`,
        framework: createFramework,
      });
      const normalized = normalizeKillChain(kc);
      setKillChains((prev) => [normalized, ...prev]);
      setSelected(normalized);
      setShowCreate(false);
      setCreateName('');
    } catch (e: any) { toast.error(e.message); }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.deleteKillChain(id);
      setKillChains((prev) => prev.filter((k) => k.id !== id));
      if (selected?.id === id) setSelected(null);
      toast.success('Kill chain deleted');
    } catch (e: any) { toast.error(e.message); }
  };

  const handleAiMap = async () => {
    if (!selected) return;
    setMapLoading(true);
    try {
      const result = await api.aiMapKillChain(selected.id, { user_guidance: userGuidance, planning_profile: planningProfile });
      const normalized = normalizeKillChain(result);
      setSelected(normalized);
      setKillChains((prev) => prev.map((k) => k.id === normalized.id ? normalized : k));
      setActiveTab('timeline');
      setShowGuidance(false);
      toast.success('Kill chain analysis complete');
    } catch (e: any) { toast.error(e.message); }
    finally { setMapLoading(false); }
  };

  const handleAiGenerate = async () => {
    if (!currentProject) { toast('Open a workspace to generate AI kill chains', { icon: '📂' }); return; }
    setGenLoading(true);
    try {
      const result = await api.aiGenerateKillChain(currentProject.id, {
        framework: createFramework,
        user_guidance: userGuidance,
        planning_profile: planningProfile,
      });
      const normalized = normalizeKillChain(result);
      setKillChains((prev) => [normalized, ...prev]);
      setSelected(normalized);
      setActiveTab('timeline');
      setShowGuidance(false);
      toast.success('Kill chain generated');
    } catch (e: any) { toast.error(e.message); }
    finally { setGenLoading(false); }
  };

  const togglePhase = useCallback((idx: number) => {
    setExpandedPhases(prev => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  }, []);

  const navigateToNode = (nodeId: string) => {
    setSelectedNodeId(nodeId);
    setViewMode('tree');
  };

  // Normalize phases
  const phases = useMemo(() => normalizePhases(selected?.phases || []), [selected?.phases]);
  const analysisMetadata = selected?.analysis_metadata || { generation_warnings: [], pending_chunk_ids: [] };
  const analysisInProgress = analysisMetadata.generation_status === 'running' || analysisMetadata.generation_status === 'partial';

  const expandAll = useCallback(() => {
    setExpandedPhases(new Set(phases.map((_, i) => i)));
  }, [phases]);

  const collapseAll = useCallback(() => {
    setExpandedPhases(new Set());
  }, []);

  // Stats
  const totalNodes = phases.reduce((s, p) => s + (p.mapped_nodes?.length || 0), 0);
  const totalBreaks = phases.reduce((s, p) => s + (p.break_opportunities?.length || 0), 0);
  const hardPhases = phases.filter(p => p.difficulty === 'hard' || p.difficulty === 'very hard' || p.difficulty === 'very_hard').length;
  const coveredPhases = phases.filter(p => p.mapped_nodes?.length > 0).length;
  const gapPhases = phases.filter(p => p.defensive_coverage === 'none' || p.defensive_coverage === 'minimal').length;
  const coveragePercent = selected?.coverage_score != null
    ? Math.round(selected.coverage_score * 100)
    : (phases.length > 0 ? Math.round((coveredPhases / phases.length) * 100) : 0);

  if (!currentProject) {
    return (
      <StandaloneLanding
        icon={<Route size={28} className="text-cyan-500" />}
        title="Kill Chain Planning"
        description="Run kill chain analysis from a workspace. AI generation works from the objective alone, and node mapping becomes available once the tree exists."
        features={[
          { icon: <Sparkles size={15} className="text-cyan-500" />, title: 'AI Generation', desc: 'Generate campaign phase structures from the active workspace objective.' },
          { icon: <Zap size={15} className="text-cyan-500" />, title: 'Node Mapping', desc: 'Map attack tree nodes into MITRE ATT&CK, Cyber Kill Chain, or Unified Kill Chain phases.' },
          { icon: <ShieldAlert size={15} className="text-cyan-500" />, title: 'Break Points', desc: 'Surface dwell time, detection windows, and defender interruption opportunities.' },
        ]}
      />
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* ──── Top Toolbar ──── */}
      <div className="border-b px-4 py-2 flex items-center gap-2 bg-card shrink-0 flex-wrap">
        <Route size={16} className="text-cyan-500" />
        <h2 className="font-semibold text-sm">Kill Chain</h2>
        <div className="border-l h-5 mx-1" />

        {/* Select kill chain */}
        <select
          value={selected?.id || ''}
          onChange={(e) => {
            const kc = killChains.find(k => k.id === e.target.value) || null;
            setSelected(kc);
            setExpandedPhases(new Set());
          }}
          className="select-field text-xs px-2 py-1 max-w-[200px]"
        >
          <option value="">Select kill chain...</option>
          {killChains.map(k => <option key={k.id} value={k.id}>{k.name}</option>)}
        </select>

        <select value={createFramework} onChange={(e) => setCreateFramework(e.target.value)}
          className="select-field text-xs px-2 py-1">
          {FRAMEWORKS.map(f => <option key={f.id} value={f.id}>{f.label}</option>)}
        </select>

        {showCreate ? (
          <div className="flex items-center gap-1">
            <input value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="Name (optional)..."
              className="text-xs bg-transparent border rounded px-2 py-1 w-32" onKeyDown={e => e.key === 'Enter' && handleCreate()} />
            <button onClick={handleCreate} className="text-xs px-2 py-1 rounded bg-cyan-600 text-white hover:bg-cyan-700">Create</button>
            <button onClick={() => setShowCreate(false)} className="p-0.5 hover:bg-accent rounded"><X size={12} /></button>
          </div>
        ) : (
          <button onClick={() => setShowCreate(true)} className="p-1 rounded hover:bg-accent" title="Create empty kill chain">
            <Plus size={14} />
          </button>
        )}

        <div className="flex-1" />

        <select
          value={planningProfile}
          onChange={(e) => setPlanningProfile(e.target.value as PlanningProfile)}
          className="select-field text-xs px-2 py-1"
        >
          {PLANNING_PROFILE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>

        {/* Guidance toggle */}
        <button
          onClick={() => setShowGuidance(!showGuidance)}
          className={cn(
            'flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors',
            showGuidance ? 'bg-amber-500/20 text-amber-500' : 'hover:bg-accent text-muted-foreground'
          )}
          title="Add operator guidance for the AI"
        >
          <BookOpen size={12} />
          Guidance
        </button>

        {selected && (
          <button onClick={handleAiMap} disabled={mapLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 text-white text-xs font-medium hover:bg-cyan-700 disabled:opacity-50">
            {mapLoading ? <Loader2 size={13} className="animate-spin" /> : <Brain size={13} />}
            {mapLoading ? 'Analysing...' : analysisInProgress ? 'Resume AI Analyse' : 'AI Analyse'}
          </button>
        )}

        <button onClick={handleAiGenerate} disabled={genLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-gradient-to-r from-indigo-600 to-cyan-600 text-white text-xs font-medium hover:opacity-90 disabled:opacity-50">
          {genLoading ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
          {genLoading ? 'Generating...' : 'AI Generate'}
        </button>

        {selected && (
          <button onClick={() => setDeleteConfirmId(selected.id)} className="p-1 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive">
            <Trash2 size={14} />
          </button>
        )}
      </div>

      {/* ──── Guidance Input Bar ──── */}
      {showGuidance && (
        <div className="border-b px-4 py-2 bg-amber-500/5 flex items-center gap-2">
          <BookOpen size={13} className="text-amber-500 shrink-0" />
          <input
            value={userGuidance}
            onChange={(e) => setUserGuidance(e.target.value)}
            placeholder="Guide the AI: e.g. 'Focus on cloud-based attack paths', 'Assume attacker has valid credentials', 'Target is a healthcare org with legacy systems'..."
            className="flex-1 text-xs bg-transparent border rounded px-3 py-1.5 placeholder:text-muted-foreground/50"
            onKeyDown={e => { if (e.key === 'Enter' && selected) handleAiMap(); else if (e.key === 'Enter') handleAiGenerate(); }}
          />
          <span className="text-[10px] text-muted-foreground hidden lg:inline">{selectedPlanningProfile.label}: {selectedPlanningProfile.description}</span>
          <span className="text-[10px] text-muted-foreground shrink-0">Press Enter to run</span>
        </div>
      )}

      {/* ──── No-Nodes Guidance Banner ──── */}
      {nodesChecked && nodes.length === 0 && (
        <div className="mx-4 mt-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
          <div className="flex items-start gap-2">
            <ShieldAlert size={14} className="text-amber-500 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-medium text-amber-600 dark:text-amber-400">No attack tree nodes in this workspace</p>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Kill chains work best with an existing attack tree to map nodes to phases.
                <strong> AI Generate</strong> will create a kill chain from the objective alone. Use the <strong>Tree Editor</strong> or <strong>AI Agent</strong> to build a tree first for richer analysis.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* ──── Content Area ──── */}
      {!selected ? (
        /* ── Empty state: no kill chain selected ── */
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center max-w-md">
            <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-cyan-500/20 to-indigo-500/20 flex items-center justify-center">
              <Route size={28} className="text-cyan-500" />
            </div>
            <p className="text-sm font-semibold mb-1">Kill Chain Analysis</p>
            <p className="text-xs mb-5 leading-relaxed">
              Maps your attack tree nodes to kill chain phases (MITRE ATT&CK, Lockheed Martin, or Unified Kill Chain).
              The AI identifies which phases your tree covers, estimates dwell times and detection windows,
              and highlights "break the chain" opportunities for defenders.
            </p>
            <div className="flex items-center justify-center gap-3">
              <button onClick={handleAiGenerate} disabled={genLoading}
                className="flex items-center gap-1.5 px-5 py-2.5 rounded-lg bg-gradient-to-r from-indigo-600 to-cyan-600 text-white text-sm font-medium hover:opacity-90 disabled:opacity-50 shadow-lg shadow-cyan-500/20">
                {genLoading ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />}
                Generate Kill Chain
              </button>
              <button onClick={() => setShowCreate(true)}
                className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg border text-sm hover:bg-accent">
                <Plus size={15} />
                Create Empty
              </button>
            </div>
          </div>
        </div>
      ) : phases.length === 0 ? (
        /* ── Empty state: no phases yet ── */
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center">
            <Brain size={36} className="mx-auto mb-3 text-cyan-500/40" />
            <p className="text-sm font-medium">{analysisInProgress ? 'Analysis is partially complete' : 'No phases mapped yet'}</p>
            <p className="text-xs mt-1 mb-4">
              {analysisInProgress
                ? 'Resume AI analysis to finish the remaining kill-chain phases.'
                : <>Click <strong>AI Analyse</strong> to map your attack tree nodes into kill chain phases</>}
            </p>
            <button onClick={handleAiMap} disabled={mapLoading}
              className="flex items-center gap-1.5 px-5 py-2 rounded-lg bg-cyan-600 text-white text-sm font-medium hover:bg-cyan-700 disabled:opacity-50 mx-auto">
              {mapLoading ? <Loader2 size={14} className="animate-spin" /> : <Brain size={14} />}
              {analysisInProgress ? 'Resume AI Analyse' : 'AI Analyse'}
            </button>
          </div>
        </div>
      ) : (
        /* ── Main content: phases populated ── */
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* ── Tabs + Stats Ribbon ── */}
          <div className="flex items-center border-b shrink-0">
            <button onClick={() => setActiveTab('timeline')}
              className={cn('px-4 py-2 text-xs font-medium border-b-2 transition-colors',
                activeTab === 'timeline' ? 'border-cyan-500 text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>
              Timeline ({phases.length})
            </button>
            <button onClick={() => setActiveTab('summary')}
              className={cn('px-4 py-2 text-xs font-medium border-b-2 transition-colors',
                activeTab === 'summary' ? 'border-cyan-500 text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>
              Campaign Intel
            </button>
            {selected.recommendations?.length > 0 && (
              <button onClick={() => setActiveTab('recommendations')}
                className={cn('px-4 py-2 text-xs font-medium border-b-2 transition-colors',
                  activeTab === 'recommendations' ? 'border-cyan-500 text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>
                Recommendations ({selected.recommendations.length})
              </button>
            )}
            <div className="flex-1" />
            <div className="flex items-center gap-3 pr-4 text-[10px] text-muted-foreground">
              {selected.overall_risk_rating && (
                <span className={cn('font-bold uppercase', RISK_COLORS[selected.overall_risk_rating] || 'text-foreground')}>
                  {selected.overall_risk_rating} risk
                </span>
              )}
              {selected.total_estimated_time && (
                <span className="flex items-center gap-1"><Timer size={10} /> {selected.total_estimated_time}</span>
              )}
              <span title={`${coveredPhases} of ${phases.length} phases have mapped nodes`}>
                <Gauge size={10} className="inline mr-0.5" />{coveragePercent}% coverage
              </span>
              {gapPhases > 0 && (
                <span className="text-red-400" title={`${gapPhases} phases have no or minimal defensive coverage`}>
                  <ShieldAlert size={10} className="inline mr-0.5" />{gapPhases} gaps
                </span>
              )}
            </div>
          </div>

          {/* ── Tab Content ── */}
          <div className="flex-1 overflow-auto">
            {(analysisMetadata.generation_strategy || analysisMetadata.generation_status || analysisMetadata.generation_warnings.length > 0) && (
              <div className="px-6 pt-4">
                <div className="rounded-lg border bg-muted/20 p-3 text-xs space-y-2">
                  <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">Generation Status</div>
                  <div className="text-[11px] text-muted-foreground">
                    Strategy: {analysisMetadata.generation_strategy || 'standard'}
                    {analysisMetadata.chunk_count ? `, passes: ${analysisMetadata.chunk_count}` : ''}
                    {analysisMetadata.generation_status ? `, status: ${analysisMetadata.generation_status}` : ''}
                    {analysisMetadata.current_stage ? `, stage: ${analysisMetadata.current_stage}` : ''}
                    {typeof analysisMetadata.pending_chunk_count === 'number' && analysisMetadata.pending_chunk_count > 0
                      ? `, pending: ${analysisMetadata.pending_chunk_count}`
                      : ''}
                    {analysisMetadata.synthesis_status ? `, synthesis: ${analysisMetadata.synthesis_status}` : ''}
                  </div>
                  {analysisMetadata.generation_warnings.length > 0 && (
                    <ul className="list-disc pl-4 space-y-1 text-[11px] text-amber-500">
                      {analysisMetadata.generation_warnings.map((warning, index) => <li key={index}>{warning}</li>)}
                    </ul>
                  )}
                </div>
              </div>
            )}

            {/* ═══════ TIMELINE TAB ═══════ */}
            {activeTab === 'timeline' && (
              <div className="p-6">
                {/* Coverage progress bar */}
                <div className="mb-5">
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-500 font-medium border border-cyan-500/20">
                        {FRAMEWORKS.find(f => f.id === selected.framework)?.label || selected.framework}
                      </span>
                      <span className="text-[10px] text-muted-foreground">{coveredPhases}/{phases.length} phases covered</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <button onClick={expandAll} className="p-1 rounded hover:bg-accent text-muted-foreground" title="Expand all">
                        <ChevronsDown size={13} />
                      </button>
                      <button onClick={collapseAll} className="p-1 rounded hover:bg-accent text-muted-foreground" title="Collapse all">
                        <ChevronsUp size={13} />
                      </button>
                    </div>
                  </div>
                  <div className="h-2 rounded-full bg-muted overflow-hidden flex">
                    {phases.map((p, i) => {
                      const cov = COVERAGE_COLORS[p.defensive_coverage] || COVERAGE_COLORS.none;
                      const hasNodes = (p.mapped_nodes?.length || 0) > 0;
                      return (
                        <div
                          key={i}
                          className={cn(
                            'h-full transition-all',
                            hasNodes ? cov.bg.replace('/15', '/60') : 'bg-muted-foreground/10'
                          )}
                          style={{ width: `${100 / phases.length}%` }}
                          title={`${p.phase}: ${cov.label}`}
                        />
                      );
                    })}
                  </div>
                  <div className="flex items-center gap-3 mt-1.5">
                    {Object.entries(COVERAGE_COLORS).map(([key, val]) => (
                      <span key={key} className="flex items-center gap-1 text-[9px] text-muted-foreground">
                        <span className={cn('w-2 h-2 rounded-full', val.bg.replace('/15', '/60'))} />
                        {val.label}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Vertical Timeline */}
                <div className="relative ml-4">
                  <div className="absolute top-0 bottom-0 left-3 w-0.5 bg-border" />

                  <div className="space-y-3">
                    {phases.map((phase, idx) => {
                      const hasNodes = (phase.mapped_nodes?.length || 0) > 0;
                      const isExpanded = expandedPhases.has(idx);
                      const diffColor = DIFFICULTY_COLORS[phase.difficulty] || 'bg-gray-400';
                      const covStyle = COVERAGE_COLORS[phase.defensive_coverage] || COVERAGE_COLORS.none;
                      const isGap = phase.defensive_coverage === 'none' || phase.defensive_coverage === 'minimal';

                      return (
                        <div key={idx} className="relative flex gap-4">
                          {/* Timeline dot */}
                          <div className={cn(
                            'w-7 h-7 rounded-full border-2 z-10 shrink-0 flex items-center justify-center text-[10px] font-bold',
                            hasNodes
                              ? 'bg-cyan-500 border-cyan-600 text-white'
                              : isGap
                                ? 'bg-red-500/20 border-red-500/40 text-red-400'
                                : 'bg-muted border-muted-foreground/30 text-muted-foreground'
                          )}>
                            {phase.phase_index}
                          </div>

                          {/* Phase card */}
                          <div className={cn(
                            'flex-1 rounded-lg border transition-all',
                            hasNodes ? 'border-cyan-500/30 bg-cyan-500/5' : isGap ? 'border-red-500/20 bg-red-500/5' : 'border-border bg-card',
                            isExpanded && 'ring-1 ring-cyan-500/30'
                          )}>
                            <button
                              onClick={() => togglePhase(idx)}
                              className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-accent/30"
                            >
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2 flex-wrap">
                                  <span className="text-sm font-semibold">{phase.phase}</span>
                                  {phase.difficulty && (
                                    <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
                                      <span className={cn('w-2 h-2 rounded-full', diffColor)} />
                                      {phase.difficulty}
                                    </span>
                                  )}
                                  {/* Coverage badge */}
                                  <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full font-medium', covStyle.bg, covStyle.text)}>
                                    {covStyle.label}
                                  </span>
                                  {(phase as any).technique_id && (
                                    <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 font-mono">
                                      {(phase as any).technique_id}
                                    </span>
                                  )}
                                </div>
                                {phase.description && (
                                  <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">{phase.description}</p>
                                )}
                              </div>
                              <div className="flex items-center gap-3 shrink-0 text-[10px] text-muted-foreground">
                                {phase.dwell_time && (
                                  <span className="flex items-center gap-1"><Clock size={10} /> {phase.dwell_time}</span>
                                )}
                                {phase.detection_window && (
                                  <span className="flex items-center gap-1"><Eye size={10} /> {phase.detection_window}</span>
                                )}
                                {hasNodes && (
                                  <span className="text-cyan-500 font-medium">{phase.mapped_nodes.length} node(s)</span>
                                )}
                              </div>
                              {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                            </button>

                            {/* ── Expanded Phase Details ── */}
                            {isExpanded && (
                              <div className="px-4 pb-4 border-t border-border/50 text-xs space-y-3">
                                {/* Description */}
                                {phase.description && (
                                  <div className="mt-3">
                                    <p className="leading-relaxed">{phase.description}</p>
                                  </div>
                                )}

                                {/* Metrics grid */}
                                <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                                  {phase.dwell_time && (
                                    <div className="p-2 rounded bg-muted/30 border">
                                      <div className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1"><Clock size={10} /> Dwell Time</div>
                                      <div className="font-medium mt-0.5">{phase.dwell_time}</div>
                                    </div>
                                  )}
                                  {phase.detection_window && (
                                    <div className="p-2 rounded bg-muted/30 border">
                                      <div className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1"><Eye size={10} /> Detection Window</div>
                                      <div className="font-medium mt-0.5">{phase.detection_window}</div>
                                    </div>
                                  )}
                                  {phase.difficulty && (
                                    <div className="p-2 rounded bg-muted/30 border">
                                      <div className="text-[10px] text-muted-foreground font-semibold">Difficulty</div>
                                      <div className="flex items-center gap-1.5 mt-0.5">
                                        <span className={cn('w-2.5 h-2.5 rounded-full', diffColor)} />
                                        <span className="font-medium capitalize">{phase.difficulty}</span>
                                      </div>
                                    </div>
                                  )}
                                  {phase.defensive_coverage && (
                                    <div className="p-2 rounded bg-muted/30 border">
                                      <div className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1"><Shield size={10} /> Defence Coverage</div>
                                      <div className={cn('font-medium mt-0.5 capitalize', covStyle.text)}>{phase.defensive_coverage}</div>
                                    </div>
                                  )}
                                </div>

                                {/* Coverage notes */}
                                {phase.coverage_notes && (
                                  <div className="p-2 rounded bg-muted/20 border text-[11px] leading-relaxed">
                                    <span className="font-semibold text-muted-foreground">Coverage Notes: </span>
                                    {phase.coverage_notes}
                                  </div>
                                )}

                                {/* Tools */}
                                {phase.tools?.length > 0 && (
                                  <div>
                                    <div className="text-[10px] text-muted-foreground font-semibold mb-1.5 flex items-center gap-1">
                                      <Wrench size={10} /> Attacker Tools
                                    </div>
                                    <div className="flex flex-wrap gap-1">
                                      {phase.tools.map((t, ti) => (
                                        <span key={ti} className="text-[10px] px-2 py-0.5 rounded-full bg-orange-500/10 text-orange-400 border border-orange-500/20">
                                          {t}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {/* Mapped nodes with navigate */}
                                {hasNodes && (
                                  <div>
                                    <div className="text-[10px] text-muted-foreground font-semibold mb-1.5 flex items-center gap-1">
                                      <Crosshair size={10} className="text-cyan-500" /> Mapped Attack Nodes
                                    </div>
                                    <div className="space-y-1">
                                      {phase.mapped_nodes.map((n, ni) => (
                                        <div key={ni} className="flex items-center gap-2 p-1.5 rounded bg-muted/20 group">
                                          <Zap size={10} className="text-amber-500 shrink-0" />
                                          <span className="font-medium flex-1 truncate">{n.node_title || n.node_id}</span>
                                          {(n.technique_id || n.technique) && (
                                            <span className="text-[10px] text-purple-400 font-mono">{n.technique_id || n.technique}</span>
                                          )}
                                          {n.technique_name && (
                                            <span className="text-[10px] text-muted-foreground truncate max-w-[150px]">{n.technique_name}</span>
                                          )}
                                          {n.confidence > 0 && (
                                            <span className="text-[10px] text-muted-foreground">{Math.round(n.confidence * 100)}%</span>
                                          )}
                                          <button
                                            onClick={() => navigateToNode(n.node_id)}
                                            className="opacity-0 group-hover:opacity-100 p-0.5 rounded hover:bg-accent text-cyan-500"
                                            title="Navigate to node in tree"
                                          >
                                            <ExternalLink size={10} />
                                          </button>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {/* IOCs */}
                                {phase.iocs?.length > 0 && (
                                  <div>
                                    <div className="text-[10px] text-muted-foreground font-semibold mb-1.5 flex items-center gap-1">
                                      <FileSearch size={10} /> Indicators of Compromise
                                    </div>
                                    <div className="space-y-0.5">
                                      {phase.iocs.map((ioc, ii) => (
                                        <div key={ii} className="text-[10px] font-mono text-red-400/80 pl-2 border-l-2 border-red-500/20">
                                          {ioc}
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {/* Log sources */}
                                {phase.log_sources?.length > 0 && (
                                  <div>
                                    <div className="text-[10px] text-muted-foreground font-semibold mb-1.5 flex items-center gap-1">
                                      <Radio size={10} /> Log Sources
                                    </div>
                                    <div className="flex flex-wrap gap-1">
                                      {phase.log_sources.map((ls, li) => (
                                        <span key={li} className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20">
                                          {ls}
                                        </span>
                                      ))}
                                    </div>
                                  </div>
                                )}

                                {/* Break opportunities */}
                                {phase.break_opportunities?.length > 0 && (
                                  <div>
                                    <div className="text-[10px] text-muted-foreground font-semibold mb-1.5 flex items-center gap-1">
                                      <ShieldAlert size={10} className="text-green-500" /> Break the Chain
                                    </div>
                                    <div className="space-y-1">
                                      {phase.break_opportunities.map((b, bi) => (
                                        <div key={bi} className="flex items-start gap-1.5 text-green-500/90">
                                          <ShieldAlert size={10} className="shrink-0 mt-0.5" />
                                          <span>{b}</span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}

            {/* ═══════ CAMPAIGN INTEL TAB ═══════ */}
            {activeTab === 'summary' && (
              <div className="p-6 max-w-4xl mx-auto space-y-6">
                {/* Risk Overview Cards */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {selected.overall_risk_rating && (
                    <div className="p-3 rounded-lg bg-muted/30 border text-center">
                      <div className="text-[10px] text-muted-foreground font-semibold mb-1">Overall Risk</div>
                      <div className={cn('text-lg font-bold uppercase', RISK_COLORS[selected.overall_risk_rating] || 'text-foreground')}>
                        {selected.overall_risk_rating}
                      </div>
                    </div>
                  )}
                  {selected.attack_complexity && (
                    <div className="p-3 rounded-lg bg-muted/30 border text-center">
                      <div className="text-[10px] text-muted-foreground font-semibold mb-1">Complexity</div>
                      <div className="text-lg font-bold capitalize">{selected.attack_complexity}</div>
                    </div>
                  )}
                  <div className="p-3 rounded-lg bg-muted/30 border text-center">
                    <div className="text-[10px] text-muted-foreground font-semibold mb-1">Coverage</div>
                    <div className={cn('text-lg font-bold', coveragePercent >= 70 ? 'text-green-500' : coveragePercent >= 40 ? 'text-yellow-500' : 'text-red-500')}>
                      {coveragePercent}%
                    </div>
                  </div>
                  {selected.total_estimated_time && (
                    <div className="p-3 rounded-lg bg-muted/30 border text-center">
                      <div className="text-[10px] text-muted-foreground font-semibold mb-1">Est. Duration</div>
                      <div className="text-sm font-bold text-cyan-400">{selected.total_estimated_time}</div>
                    </div>
                  )}
                </div>

                {/* Critical Path */}
                {selected.critical_path && (
                  <div className="p-4 rounded-lg bg-red-500/5 border border-red-500/20">
                    <div className="text-[10px] font-semibold text-red-400 mb-1 flex items-center gap-1">
                      <Target size={11} /> Critical Path
                    </div>
                    <p className="text-xs leading-relaxed">{selected.critical_path}</p>
                  </div>
                )}

                {/* AI Summary */}
                {selected.ai_summary ? (
                  <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-lg p-4">
                    <div className="text-[11px] font-semibold text-cyan-500 mb-2 flex items-center gap-1.5">
                      <Brain size={13} /> AI Campaign Report
                    </div>
                    <MarkdownContent content={selected.ai_summary} size="sm" />
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground italic">No campaign summary available yet. Run AI Analyse to generate.</p>
                )}

                {/* Phase Difficulty & Coverage Breakdown */}
                <div>
                  <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5"><BarChart3 size={13} /> Phase Breakdown</h3>
                  <div className="rounded-lg border overflow-hidden">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="bg-muted/30">
                          <th className="text-left px-3 py-2 font-medium text-muted-foreground">#</th>
                          <th className="text-left px-3 py-2 font-medium text-muted-foreground">Phase</th>
                          <th className="text-left px-3 py-2 font-medium text-muted-foreground">Difficulty</th>
                          <th className="text-left px-3 py-2 font-medium text-muted-foreground">Coverage</th>
                          <th className="text-right px-3 py-2 font-medium text-muted-foreground">Nodes</th>
                        </tr>
                      </thead>
                      <tbody>
                        {phases.map((p, i) => {
                          const cov = COVERAGE_COLORS[p.defensive_coverage] || COVERAGE_COLORS.none;
                          return (
                            <tr key={i} className="border-t hover:bg-accent/20">
                              <td className="px-3 py-1.5 text-muted-foreground">{p.phase_index}</td>
                              <td className="px-3 py-1.5 font-medium">{p.phase}</td>
                              <td className="px-3 py-1.5">
                                <span className="flex items-center gap-1.5">
                                  <span className={cn('w-2 h-2 rounded-full', DIFFICULTY_COLORS[p.difficulty] || 'bg-gray-400')} />
                                  <span className="capitalize">{p.difficulty}</span>
                                </span>
                              </td>
                              <td className="px-3 py-1.5">
                                <span className={cn('text-[10px] px-1.5 py-0.5 rounded-full', cov.bg, cov.text)}>{cov.label}</span>
                              </td>
                              <td className="px-3 py-1.5 text-right">{p.mapped_nodes?.length || 0}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Weakest Links */}
                {selected.weakest_links && selected.weakest_links.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold mb-2 flex items-center gap-1.5 text-red-400">
                      <AlertTriangle size={13} /> Weakest Links
                    </h3>
                    <div className="space-y-1">
                      {selected.weakest_links.map((link, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs p-2 rounded bg-red-500/5 border border-red-500/10">
                          <AlertTriangle size={11} className="text-red-400 shrink-0 mt-0.5" />
                          <span>{link}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Key Metrics grid */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-center">
                  <div className="p-3 rounded-lg bg-muted/30 border">
                    <div className="text-lg font-bold">{phases.length}</div>
                    <div className="text-[10px] text-muted-foreground">Phases</div>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/30 border">
                    <div className="text-lg font-bold text-amber-500">{totalNodes}</div>
                    <div className="text-[10px] text-muted-foreground">Mapped Nodes</div>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/30 border">
                    <div className="text-lg font-bold text-green-500">{totalBreaks}</div>
                    <div className="text-[10px] text-muted-foreground">Break Points</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <div className="text-lg font-bold text-red-400">{gapPhases}</div>
                    <div className="text-[10px] text-muted-foreground">Coverage Gaps</div>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/30 border">
                    <div className="text-lg font-bold text-orange-500">{hardPhases}</div>
                    <div className="text-[10px] text-muted-foreground">Hard Phases</div>
                  </div>
                </div>
              </div>
            )}

            {/* ═══════ RECOMMENDATIONS TAB ═══════ */}
            {activeTab === 'recommendations' && selected.recommendations?.length > 0 && (
              <div className="p-6 max-w-4xl mx-auto space-y-6">
                {(['critical', 'high', 'medium', 'low'] as const).map(priority => {
                  const recs = selected.recommendations.filter(r => r.priority === priority);
                  if (recs.length === 0) return null;
                  const style = PRIORITY_STYLES[priority] || PRIORITY_STYLES.medium;
                  return (
                    <div key={priority}>
                      <h3 className="text-xs font-semibold mb-2 flex items-center gap-1.5 capitalize">
                        <span className={cn('w-2.5 h-2.5 rounded-full', style.split(' ')[0])} />
                        {priority} Priority ({recs.length})
                      </h3>
                      <div className="space-y-2">
                        {recs.map((r, i) => (
                          <div key={i} className={cn('p-3 rounded-lg border text-xs', style)}>
                            <div className="flex items-start justify-between gap-2">
                              <div className="flex-1">
                                <div className="font-semibold text-sm mb-1">{r.title}</div>
                                <p className="leading-relaxed opacity-90">{r.description}</p>
                              </div>
                              {r.effort && (
                                <span className="text-[10px] px-2 py-0.5 rounded-full bg-black/10 shrink-0">
                                  {r.effort} effort
                                </span>
                              )}
                            </div>
                            {r.addresses_phases && r.addresses_phases.length > 0 && (
                              <div className="flex flex-wrap gap-1 mt-2">
                                {r.addresses_phases.map((ph, pi) => (
                                  <span key={pi} className="text-[9px] px-1.5 py-0.5 rounded bg-black/10">
                                    {ph}
                                  </span>
                                ))}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ──── Delete Confirmation ──── */}
      <ConfirmDialog
        open={!!deleteConfirmId}
        onOpenChange={(open) => { if (!open) setDeleteConfirmId(null); }}
        onConfirm={() => { if (deleteConfirmId) { handleDelete(deleteConfirmId); setDeleteConfirmId(null); } }}
        title="Delete Kill Chain"
        description="This will permanently delete this kill chain and all its phases. This action cannot be undone."
        confirmLabel="Delete"
        destructive
      />
    </div>
  );
}
