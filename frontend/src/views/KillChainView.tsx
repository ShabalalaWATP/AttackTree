import { useState, useEffect, useMemo } from 'react';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import toast from 'react-hot-toast';
import {
  Route, Plus, Trash2, Brain, Loader2, Sparkles, Clock,
  Eye, ShieldAlert, ChevronDown, ChevronRight, Zap, X,
  Timer, AlertTriangle, Target, TrendingUp, BarChart3
} from 'lucide-react';

import { MarkdownContent } from '@/components/MarkdownContent';

interface MappedNode {
  node_id: string;
  node_title: string;
  technique: string;
  confidence: number;
}

interface KillChainPhase {
  phase: string;
  phase_index: number;
  description?: string;
  mapped_nodes: MappedNode[];
  detection_window: string;
  dwell_time: string;
  break_opportunities: string[];
  difficulty: string;
}

interface KillChainData {
  id: string;
  project_id: string;
  name: string;
  description: string;
  framework: string;
  ai_summary: string;
  phases: KillChainPhase[];
  recommendations: Array<{ priority: string; title: string; description: string }>;
  total_estimated_time?: string;
  weakest_links?: string[];
  created_at: string;
}

/** Normalize phases from backend — handles both old (order/node_ids) and new (phase_index/mapped_nodes) formats */
function normalizePhases(phases: any[]): KillChainPhase[] {
  if (!Array.isArray(phases)) return [];
  return phases.map((p, i) => {
    let mappedNodes: MappedNode[] = [];
    if (Array.isArray(p.mapped_nodes)) {
      mappedNodes = p.mapped_nodes;
    } else if (Array.isArray(p.node_ids)) {
      mappedNodes = p.node_ids.map((id: string) => ({ node_id: id, node_title: id, technique: '', confidence: 0.8 }));
    }
    return {
      ...p,
      phase_index: p.phase_index ?? p.order ?? (i + 1),
      mapped_nodes: mappedNodes,
      break_opportunities: p.break_opportunities || [],
      description: p.description || '',
    };
  });
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
  'very hard': 'bg-red-500',
};

export function KillChainView() {
  const { currentProject, nodes, setNodes } = useStore();
  const [killChains, setKillChains] = useState<KillChainData[]>([]);
  const [selected, setSelected] = useState<KillChainData | null>(null);
  const [genLoading, setGenLoading] = useState(false);
  const [mapLoading, setMapLoading] = useState(false);
  const [createFramework, setCreateFramework] = useState('mitre_attck');
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState('');
  const [expandedPhase, setExpandedPhase] = useState<number | null>(null);
  const [nodesChecked, setNodesChecked] = useState(false);
  const [activeTab, setActiveTab] = useState<'timeline' | 'summary'>('timeline');

  // Load nodes from API when entering this view
  useEffect(() => {
    if (currentProject) {
      if (nodes.length === 0) {
        api.listNodes(currentProject.id)
          .then((data) => { if (data.length) setNodes(data); })
          .catch(() => {})
          .finally(() => setNodesChecked(true));
      } else {
        setNodesChecked(true);
      }
    }
  }, [currentProject?.id]);

  useEffect(() => {
    if (currentProject) loadKillChains();
  }, [currentProject?.id]);

  const loadKillChains = async () => {
    if (!currentProject) return;
    try {
      const data = await api.listKillChains(currentProject.id);
      const normalized = data.map((kc: any) => ({ ...kc, phases: normalizePhases(kc.phases) }));
      setKillChains(normalized);
    } catch (e: any) { toast.error(e.message); }
  };

  const handleCreate = async () => {
    if (!currentProject) { toast('Open a project to create kill chains', { icon: '📂' }); return; }
    try {
      const kc = await api.createKillChain({
        project_id: currentProject.id,
        name: createName || `Kill Chain (${FRAMEWORKS.find(f => f.id === createFramework)?.label})`,
        framework: createFramework,
      });
      setKillChains([kc, ...killChains]);
      setSelected(kc);
      setShowCreate(false);
      setCreateName('');
    } catch (e: any) { toast.error(e.message); }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.deleteKillChain(id);
      setKillChains(killChains.filter(k => k.id !== id));
      if (selected?.id === id) setSelected(null);
      toast.success('Kill chain deleted');
    } catch (e: any) { toast.error(e.message); }
  };

  const handleAiMap = async () => {
    if (!selected) return;
    setMapLoading(true);
    try {
      const result = await api.aiMapKillChain(selected.id, {});
      const normalized = { ...result, phases: normalizePhases(result.phases) };
      setSelected(normalized);
      setKillChains(killChains.map(k => k.id === normalized.id ? normalized : k));
      setActiveTab('timeline');
      toast.success('AI mapping complete');
    } catch (e: any) { toast.error(e.message); }
    finally { setMapLoading(false); }
  };

  const handleAiGenerate = async () => {
    if (!currentProject) { toast('Open a project to generate AI kill chains', { icon: '📂' }); return; }
    setGenLoading(true);
    try {
      const result = await api.aiGenerateKillChain(currentProject.id, { framework: createFramework });
      const normalized = { ...result, phases: normalizePhases(result.phases) };
      setKillChains([normalized, ...killChains]);
      setSelected(normalized);
      setActiveTab('timeline');
      toast.success('AI generated kill chain');
    } catch (e: any) { toast.error(e.message); }
    finally { setGenLoading(false); }
  };

  // Normalize phases from selected data (handles data from API on load too)
  const phases = useMemo(() => normalizePhases(selected?.phases || []), [selected?.phases]);

  // Stats
  const totalNodes = phases.reduce((s, p) => s + (p.mapped_nodes?.length || 0), 0);
  const totalBreaks = phases.reduce((s, p) => s + (p.break_opportunities?.length || 0), 0);
  const hardPhases = phases.filter(p => p.difficulty === 'hard' || p.difficulty === 'very hard').length;

  return (
    <div className="h-full flex flex-col">
      {/* Top toolbar */}
      <div className="border-b px-4 py-2 flex items-center gap-3 bg-card shrink-0 flex-wrap">
        <Route size={16} className="text-cyan-500" />
        <h2 className="font-semibold text-sm">Kill Chain Analysis</h2>
        <div className="border-l h-5 mx-1" />

        {/* Select kill chain */}
        <select value={selected?.id || ''} onChange={(e) => setSelected(killChains.find(k => k.id === e.target.value) || null)}
          className="text-xs bg-transparent border rounded px-2 py-1">
          <option value="">Select kill chain...</option>
          {killChains.map(k => <option key={k.id} value={k.id}>{k.name}</option>)}
        </select>

        <select value={createFramework} onChange={(e) => setCreateFramework(e.target.value)}
          className="text-xs bg-transparent border rounded px-2 py-1">
          {FRAMEWORKS.map(f => <option key={f.id} value={f.id}>{f.label}</option>)}
        </select>

        {showCreate ? (
          <div className="flex items-center gap-1">
            <input value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="Name..."
              className="text-xs bg-transparent border rounded px-2 py-1 w-32" />
            <button onClick={handleCreate} className="text-xs px-2 py-1 rounded bg-cyan-600 text-white hover:bg-cyan-700">Create</button>
            <button onClick={() => setShowCreate(false)} className="p-0.5"><X size={12} /></button>
          </div>
        ) : (
          <button onClick={() => setShowCreate(true)} className="p-1 rounded hover:bg-accent"><Plus size={14} /></button>
        )}

        <div className="flex-1" />

        {selected && (
          <button onClick={handleAiMap} disabled={mapLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-cyan-600 text-white text-xs font-medium hover:bg-cyan-700 disabled:opacity-50">
            {mapLoading ? <Loader2 size={13} className="animate-spin" /> : <Brain size={13} />}
            AI Map Nodes
          </button>
        )}

        <button onClick={handleAiGenerate} disabled={genLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-indigo-600 text-white text-xs font-medium hover:bg-indigo-700 disabled:opacity-50">
          {genLoading ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
          AI Generate
        </button>

        {selected && (
          <button onClick={() => handleDelete(selected.id)} className="p-1 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive">
            <Trash2 size={14} />
          </button>
        )}
      </div>

      {/* No-nodes guidance banner — only show after loading check */}
      {nodesChecked && nodes.length === 0 && (
        <div className="mx-4 mt-3 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
          <div className="flex items-start gap-2">
            <ShieldAlert size={14} className="text-amber-500 shrink-0 mt-0.5" />
            <div>
              <p className="text-xs font-medium text-amber-600 dark:text-amber-400">No attack tree nodes in this project</p>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                Kill chains work best with an existing attack tree to map nodes to phases.
                <strong> AI Generate</strong> will create a kill chain from the project objective alone. Use the <strong>Tree Editor</strong> or <strong>AI Agent</strong> to build a tree first for node-mapped analysis.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Content area */}
      {!selected ? (
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center max-w-md">
            <Route size={40} className="mx-auto mb-3 text-cyan-500/50" />
            <p className="text-sm font-medium mb-1">Kill Chain Analysis</p>
            <p className="text-xs mb-4">
              Maps your attack tree nodes to kill chain phases (MITRE ATT&CK, Lockheed Martin, or Unified Kill Chain).
              The AI identifies which phases of an attack your tree covers, estimates dwell times and detection windows,
              and highlights "break the chain" opportunities for defenders.
            </p>
            <div className="flex items-center justify-center gap-2">
              <button onClick={handleAiGenerate} disabled={genLoading}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-gradient-to-r from-indigo-600 to-cyan-600 text-white text-sm font-medium hover:opacity-90 disabled:opacity-50">
                {genLoading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} />}
                One-Click Generate
              </button>
            </div>
            <p className="text-[10px] text-muted-foreground mt-2">
              Or create an empty kill chain with <strong>+</strong> and use <strong>AI Map Nodes</strong> to map specific nodes.
            </p>
          </div>
        </div>
      ) : phases.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center">
            <Brain size={32} className="mx-auto mb-2 text-cyan-500/40" />
            <p className="text-sm">No phases mapped yet</p>
            <p className="text-xs mt-1 mb-3">Click <strong>AI Map Nodes</strong> to analyse and map phases</p>
            <button onClick={handleAiMap} disabled={mapLoading}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-600 text-white text-xs font-medium hover:bg-cyan-700 disabled:opacity-50 mx-auto">
              {mapLoading ? <Loader2 size={13} className="animate-spin" /> : <Brain size={13} />}
              AI Map Nodes
            </button>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Tabs + Quick Stats */}
          <div className="flex items-center border-b shrink-0">
            <button onClick={() => setActiveTab('timeline')}
              className={cn('px-4 py-2 text-xs font-medium border-b-2 transition-colors',
                activeTab === 'timeline' ? 'border-cyan-500 text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>
              Timeline ({phases.length} phases)
            </button>
            <button onClick={() => setActiveTab('summary')}
              className={cn('px-4 py-2 text-xs font-medium border-b-2 transition-colors',
                activeTab === 'summary' ? 'border-cyan-500 text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground')}>
              Campaign Summary
            </button>
            <div className="flex-1" />
            <div className="flex items-center gap-3 pr-4 text-[10px] text-muted-foreground">
              {(selected as any).total_estimated_time && (
                <span className="flex items-center gap-1"><Timer size={10} /> {(selected as any).total_estimated_time}</span>
              )}
              <span className="flex items-center gap-1"><Zap size={10} className="text-amber-500" /> {totalNodes} mapped nodes</span>
              <span className="flex items-center gap-1"><ShieldAlert size={10} className="text-green-500" /> {totalBreaks} break points</span>
              <span className="flex items-center gap-1"><AlertTriangle size={10} className="text-red-500" /> {hardPhases} hard phases</span>
            </div>
          </div>

          <div className="flex-1 overflow-auto">
            {activeTab === 'timeline' && (
              <div className="p-6">
                {/* Framework badge */}
                <div className="flex items-center gap-2 mb-4">
                  <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-500 font-medium border border-cyan-500/20">
                    {FRAMEWORKS.find(f => f.id === selected.framework)?.label || selected.framework}
                  </span>
                </div>

                {/* Vertical Timeline */}
                <div className="relative ml-4">
                  {/* Timeline line */}
                  <div className="absolute top-0 bottom-0 left-3 w-0.5 bg-border" />

                  <div className="space-y-3">
                    {phases.map((phase, idx) => {
                      const hasNodes = phase.mapped_nodes?.length > 0;
                      const isExpanded = expandedPhase === idx;
                      const diffColor = DIFFICULTY_COLORS[phase.difficulty] || 'bg-gray-400';
                      return (
                        <div key={idx} className="relative flex gap-4">
                          {/* Timeline dot */}
                          <div className={cn(
                            'w-7 h-7 rounded-full border-2 z-10 shrink-0 flex items-center justify-center text-[10px] font-bold',
                            hasNodes
                              ? 'bg-cyan-500 border-cyan-600 text-white'
                              : 'bg-muted border-muted-foreground/30 text-muted-foreground'
                          )}>
                            {phase.phase_index}
                          </div>

                          {/* Phase card */}
                          <div className={cn(
                            'flex-1 rounded-lg border transition-all',
                            hasNodes ? 'border-cyan-500/30 bg-cyan-500/5' : 'border-border bg-card',
                            isExpanded && 'ring-1 ring-cyan-500/30'
                          )}>
                            <button
                              onClick={() => setExpandedPhase(isExpanded ? null : idx)}
                              className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-accent/30"
                            >
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="text-sm font-semibold">{phase.phase}</span>
                                  {phase.difficulty && (
                                    <span className="flex items-center gap-1 text-[10px] text-muted-foreground">
                                      <span className={cn('w-2 h-2 rounded-full', diffColor)} />
                                      {phase.difficulty}
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

                            {/* Expanded details */}
                            {isExpanded && (
                              <div className="px-4 pb-4 border-t border-border/50 text-xs space-y-3">
                                {/* Description */}
                                {phase.description && (
                                  <div className="mt-3">
                                    <div className="text-[10px] text-muted-foreground font-semibold mb-1">Phase Description</div>
                                    <p className="leading-relaxed">{phase.description}</p>
                                  </div>
                                )}

                                {/* Timing grid */}
                                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
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
                                </div>

                                {/* Mapped nodes */}
                                {hasNodes && (
                                  <div>
                                    <div className="text-[10px] text-muted-foreground font-semibold mb-1.5 flex items-center gap-1">
                                      <Zap size={10} className="text-amber-500" /> Mapped Attack Tree Nodes
                                    </div>
                                    <div className="space-y-1">
                                      {phase.mapped_nodes.map((n, ni) => (
                                        <div key={ni} className="flex items-center gap-2 p-1.5 rounded bg-muted/20">
                                          <Zap size={10} className="text-amber-500 shrink-0" />
                                          <span className="font-medium flex-1">{n.node_title || n.node_id}</span>
                                          {n.technique && <span className="text-[10px] text-purple-400">{n.technique}</span>}
                                          {n.confidence > 0 && (
                                            <span className="text-[10px] text-muted-foreground">{Math.round(n.confidence * 100)}%</span>
                                          )}
                                        </div>
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
                                          <span className="mt-0.5">•</span>
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

                {/* Recommendations */}
                {selected.recommendations?.length > 0 && (
                  <div className="mt-8 border-t pt-4">
                    <h3 className="text-sm font-semibold mb-3 flex items-center gap-1.5">
                      <Target size={14} className="text-green-500" /> Recommendations
                    </h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {selected.recommendations.map((r: any, i: number) => (
                        <div key={i} className="p-3 rounded-lg border text-xs">
                          <div className="flex items-center gap-2 mb-1">
                            <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold',
                              r.priority === 'critical' ? 'bg-red-500/20 text-red-500' :
                              r.priority === 'high' ? 'bg-orange-500/20 text-orange-500' :
                              r.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-600' :
                              'bg-blue-500/20 text-blue-500'
                            )}>{r.priority}</span>
                            <span className="font-medium">{r.title}</span>
                          </div>
                          <p className="text-muted-foreground">{r.description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'summary' && (
              <div className="p-6 max-w-4xl mx-auto space-y-6">
                {/* AI Summary — rendered as markdown */}
                {selected.ai_summary ? (
                  <div className="bg-cyan-500/5 border border-cyan-500/20 rounded-lg p-4">
                    <div className="text-[11px] font-semibold text-cyan-500 mb-2 flex items-center gap-1.5">
                      <Brain size={13} /> AI Campaign Report
                    </div>
                    <MarkdownContent content={selected.ai_summary} size="sm" />
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">No campaign summary available yet.</p>
                )}

                {/* Key Metrics */}
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
                    <div className="text-lg font-bold text-red-400">{hardPhases}</div>
                    <div className="text-[10px] text-muted-foreground">Hard Phases</div>
                  </div>
                  {(selected as any).total_estimated_time && (
                    <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
                      <div className="text-sm font-bold text-cyan-400">{(selected as any).total_estimated_time}</div>
                      <div className="text-[10px] text-muted-foreground">Est. Duration</div>
                    </div>
                  )}
                </div>

                {/* Difficulty breakdown */}
                <div>
                  <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5"><BarChart3 size={13} /> Phase Difficulty</h3>
                  <div className="space-y-1.5">
                    {phases.map((p, i) => (
                      <div key={i} className="flex items-center gap-2 text-xs">
                        <span className="text-muted-foreground w-6 text-right">{p.phase_index}.</span>
                        <span className={cn('w-2.5 h-2.5 rounded-full shrink-0', DIFFICULTY_COLORS[p.difficulty] || 'bg-gray-400')} />
                        <span className="flex-1 truncate">{p.phase}</span>
                        <span className="text-muted-foreground capitalize shrink-0">{p.difficulty || '—'}</span>
                        <span className="text-muted-foreground shrink-0 w-20 text-right">{p.dwell_time || '—'}</span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Weakest links */}
                {(selected as any).weakest_links?.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5">
                      <AlertTriangle size={13} className="text-red-400" /> Weakest Defensive Links
                    </h3>
                    <div className="space-y-1.5">
                      {(selected as any).weakest_links.map((w: string, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-xs p-2 rounded-lg bg-red-500/5 border border-red-500/10">
                          <AlertTriangle size={11} className="text-red-400 shrink-0 mt-0.5" />
                          <span>{w}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Recommendations in summary view too */}
                {selected.recommendations?.length > 0 && (
                  <div>
                    <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5">
                      <Target size={13} className="text-green-500" /> Recommendations
                    </h3>
                    <div className="space-y-1.5">
                      {selected.recommendations.map((r: any, i: number) => (
                        <div key={i} className="flex items-start gap-2 text-xs p-2 rounded-lg bg-muted/20 border">
                          <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0',
                            r.priority === 'critical' ? 'bg-red-500/20 text-red-500' :
                            r.priority === 'high' ? 'bg-orange-500/20 text-orange-500' :
                            r.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-600' :
                            'bg-blue-500/20 text-blue-500'
                          )}>{r.priority}</span>
                          <div>
                            <span className="font-medium">{r.title}</span>
                            <p className="text-muted-foreground mt-0.5">{r.description}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
