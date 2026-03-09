import { useState, useEffect } from 'react';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import toast from 'react-hot-toast';
import {
  FlaskConical, Plus, Trash2, Play, Brain, ChevronDown, ChevronRight,
  AlertTriangle, Shield, TrendingUp, TrendingDown, Loader2, Sparkles,
  ToggleLeft, ToggleRight, User, Crosshair
} from 'lucide-react';


interface ScenarioData {
  id: string;
  project_id: string;
  name: string;
  description: string;
  status: string;
  attacker_type: string;
  attacker_skill: string;
  attacker_resources: string;
  attacker_motivation: string;
  disabled_controls: string[];
  assumptions: string;
  ai_narrative: string;
  ai_recommendations: Array<{ priority: string; title: string; description: string }>;
  impact_summary: Record<string, any>;
  created_at: string;
}

const ATTACKER_TYPES = [
  { id: 'script_kiddie', label: 'Script Kiddie', icon: '👶' },
  { id: 'opportunistic', label: 'Opportunistic', icon: '🎲' },
  { id: 'insider', label: 'Malicious Insider', icon: '🕵️' },
  { id: 'apt', label: 'APT / Organised Crime', icon: '🎯' },
  { id: 'nation_state', label: 'Nation State', icon: '🏛️' },
];

const SKILL_LEVELS = ['Low', 'Medium', 'High', 'Expert'];
const RESOURCE_LEVELS = ['Low', 'Medium', 'High', 'Unlimited'];

export function ScenarioSimulationView() {
  const { currentProject, nodes, setNodes } = useStore();
  const [scenarios, setScenarios] = useState<ScenarioData[]>([]);
  const [selected, setSelected] = useState<ScenarioData | null>(null);
  const [loading, setLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [simLoading, setSimLoading] = useState(false);
  const [suggestLoading, setSuggestLoading] = useState(false);
  const [question, setQuestion] = useState('');
  const [disabledControls, setDisabledControls] = useState<Set<string>>(new Set());
  const [expandedSection, setExpandedSection] = useState<string>('attacker');

  // Load nodes from API when entering this view (store may be empty if user hasn't visited Tree Editor)
  useEffect(() => {
    if (currentProject && nodes.length === 0) {
      api.listNodes(currentProject.id).then((data) => { if (data.length) setNodes(data); }).catch(() => {});
    }
  }, [currentProject?.id]);

  useEffect(() => {
    if (currentProject) loadScenarios();
  }, [currentProject?.id]);

  const loadScenarios = async () => {
    if (!currentProject) return;
    try {
      const data = await api.listScenarios(currentProject.id);
      setScenarios(data);
    } catch (e: any) { toast.error(e.message); }
  };

  const handleCreate = async () => {
    if (!currentProject) { toast('Open a project to create scenarios', { icon: '📂' }); return; }
    try {
      const s = await api.createScenario({
        project_id: currentProject.id,
        name: `Scenario ${scenarios.length + 1}`,
        description: '',
      });
      setScenarios([s, ...scenarios]);
      setSelected(s);
    } catch (e: any) { toast.error(e.message); }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.deleteScenario(id);
      setScenarios(scenarios.filter(s => s.id !== id));
      if (selected?.id === id) setSelected(null);
      toast.success('Scenario deleted');
    } catch (e: any) { toast.error(e.message); }
  };

  const updateField = async (field: string, value: any) => {
    if (!selected) return;
    try {
      const updated = await api.updateScenario(selected.id, { [field]: value });
      setSelected(updated);
      setScenarios(scenarios.map(s => s.id === updated.id ? updated : s));
    } catch (e: any) { toast.error(e.message); }
  };

  const handleSimulate = async () => {
    if (!selected) return;
    setSimLoading(true);
    try {
      const result = await api.simulateScenario(selected.id, {
        disabled_controls: [...disabledControls],
        modified_scores: {},
        attacker_type: selected.attacker_type,
        attacker_skill: selected.attacker_skill,
        attacker_resources: selected.attacker_resources,
      });
      setSelected(result);
      setScenarios(scenarios.map(s => s.id === result.id ? result : s));
      toast.success('Simulation complete');
    } catch (e: any) { toast.error(e.message); }
    finally { setSimLoading(false); }
  };

  const handleAiAnalyze = async () => {
    if (!selected) return;
    setAiLoading(true);
    try {
      const result = await api.aiAnalyzeScenario(selected.id, { question });
      setSelected(result);
      setScenarios(scenarios.map(s => s.id === result.id ? result : s));
      toast.success('AI analysis complete');
    } catch (e: any) { toast.error(e.message); }
    finally { setAiLoading(false); }
  };

  const handleAiSuggest = async () => {
    if (!currentProject) { toast('Open a project to generate AI scenarios', { icon: '📂' }); return; }
    setSuggestLoading(true);
    try {
      const result = await api.aiGenerateScenarios(currentProject.id);
      const suggestions = result.suggestions || [];
      // Create scenarios from suggestions
      for (const s of suggestions) {
        const created = await api.createScenario({
          project_id: currentProject.id,
          ...s,
        });
        setScenarios(prev => [created, ...prev]);
      }
      toast.success(`AI suggested ${suggestions.length} scenarios`);
    } catch (e: any) { toast.error(e.message); }
    finally { setSuggestLoading(false); }
  };

  const toggleControl = (mitigationId: string) => {
    const next = new Set(disabledControls);
    if (next.has(mitigationId)) next.delete(mitigationId);
    else next.add(mitigationId);
    setDisabledControls(next);
  };

  // Collect all mitigations from nodes
  const allMitigations = nodes.flatMap(n =>
    (n.mitigations || []).map(m => ({ ...m, nodeName: n.title }))
  );

  const impact = selected?.impact_summary || {};

  return (
    <div className="h-full flex">
      {/* Sidebar: scenario list */}
      <div className="w-72 border-r bg-card flex flex-col shrink-0">
        <div className="p-3 border-b">
          <div className="flex items-center justify-between mb-2">
            <h2 className="font-semibold text-sm flex items-center gap-1.5">
              <FlaskConical size={16} className="text-purple-500" /> Scenarios
            </h2>
            <div className="flex gap-1">
              <button onClick={handleAiSuggest} disabled={suggestLoading}
                className="p-1.5 rounded hover:bg-accent text-xs" title="AI suggest scenarios">
                {suggestLoading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} className="text-purple-500" />}
              </button>
              <button onClick={handleCreate} className="p-1.5 rounded hover:bg-accent"><Plus size={14} /></button>
            </div>
          </div>
        </div>
        <div className="flex-1 overflow-auto p-2 space-y-1">
          {scenarios.map(s => (
            <div key={s.id}
              onClick={() => { setSelected(s); setDisabledControls(new Set(s.disabled_controls || [])); }}
              className={cn(
                'p-2 rounded-lg text-xs cursor-pointer border transition-colors',
                selected?.id === s.id ? 'border-primary bg-primary/10' : 'border-transparent hover:bg-accent'
              )}
            >
              <div className="flex items-center justify-between">
                <span className="font-medium truncate">{s.name}</span>
                <button onClick={(e) => { e.stopPropagation(); handleDelete(s.id); }}
                  className="p-0.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive shrink-0">
                  <Trash2 size={11} />
                </button>
              </div>
              <div className="text-muted-foreground mt-0.5 flex items-center gap-1">
                <span>{ATTACKER_TYPES.find(t => t.id === s.attacker_type)?.icon || '🎲'}</span>
                <span>{s.attacker_type}</span>
                {s.status === 'completed' && <span className="ml-auto text-green-500">✓</span>}
              </div>
            </div>
          ))}
          {scenarios.length === 0 && (
            <div className="text-center text-muted-foreground text-xs py-8">
              No scenarios yet.<br />Click + or ✨ to create one.
            </div>
          )}
        </div>
      </div>

      {/* Main area */}
      <div className="flex-1 overflow-auto">
        {/* No-nodes guidance banner */}
        {nodes.length === 0 && (
          <div className="mx-6 mt-4 p-4 rounded-lg bg-amber-500/10 border border-amber-500/30">
            <div className="flex items-start gap-2">
              <AlertTriangle size={16} className="text-amber-500 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-amber-600 dark:text-amber-400">No attack tree nodes in this project</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Scenarios work best with an existing attack tree. You can still create scenarios and use AI analysis,
                  but simulation requires nodes with risk scores. Use the <strong>Tree Editor</strong> or <strong>AI Agent</strong> to build an attack tree first.
                </p>
              </div>
            </div>
          </div>
        )}
        {!selected ? (
          <div className="h-full flex items-center justify-center text-muted-foreground">
            <div className="text-center">
              <FlaskConical size={40} className="mx-auto mb-3 text-purple-500/50" />
              <p className="text-sm mb-1">Select or create a scenario</p>
              <p className="text-xs">Simulate what-if situations by disabling controls and adjusting attacker profiles</p>
            </div>
          </div>
        ) : (
          <div className="max-w-4xl mx-auto p-6 space-y-4">
            {/* Header */}
            <div className="flex items-center gap-3">
              <input
                value={selected.name}
                onChange={(e) => updateField('name', e.target.value)}
                className="text-xl font-bold bg-transparent border-b border-transparent hover:border-border focus:border-primary outline-none flex-1"
              />
              <span className={cn('text-xs px-2 py-1 rounded-full font-medium',
                selected.status === 'completed' ? 'bg-green-500/20 text-green-500' : 'bg-muted text-muted-foreground'
              )}>
                {selected.status}
              </span>
            </div>

            <textarea
              value={selected.description}
              onChange={(e) => updateField('description', e.target.value)}
              placeholder="Describe this scenario..."
              className="w-full text-sm bg-transparent border rounded-lg p-3 resize-none h-16 focus:border-primary outline-none"
            />

            {/* Attacker Profile */}
            <Section title="Attacker Profile" icon={<User size={14} />} id="attacker" expanded={expandedSection} onToggle={setExpandedSection}>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[11px] text-muted-foreground mb-1 block">Attacker Type</label>
                  <div className="grid grid-cols-1 gap-1">
                    {ATTACKER_TYPES.map(t => (
                      <button key={t.id}
                        onClick={() => updateField('attacker_type', t.id)}
                        className={cn('flex items-center gap-2 px-3 py-1.5 rounded text-xs text-left border transition-colors',
                          selected.attacker_type === t.id ? 'border-primary bg-primary/10' : 'border-transparent hover:bg-accent'
                        )}
                      >
                        <span>{t.icon}</span> {t.label}
                      </button>
                    ))}
                  </div>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-[11px] text-muted-foreground mb-1 block">Skill Level</label>
                    <div className="flex gap-1">
                      {SKILL_LEVELS.map(s => (
                        <button key={s} onClick={() => updateField('attacker_skill', s)}
                          className={cn('px-3 py-1 rounded text-xs border',
                            selected.attacker_skill === s ? 'border-primary bg-primary/10' : 'border-transparent hover:bg-accent'
                          )}>{s}</button>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label className="text-[11px] text-muted-foreground mb-1 block">Resources</label>
                    <div className="flex gap-1">
                      {RESOURCE_LEVELS.map(r => (
                        <button key={r} onClick={() => updateField('attacker_resources', r)}
                          className={cn('px-3 py-1 rounded text-xs border',
                            selected.attacker_resources === r ? 'border-primary bg-primary/10' : 'border-transparent hover:bg-accent'
                          )}>{r}</button>
                      ))}
                    </div>
                  </div>
                  <div>
                    <label className="text-[11px] text-muted-foreground mb-1 block">Motivation</label>
                    <input value={selected.attacker_motivation || ''} onChange={(e) => updateField('attacker_motivation', e.target.value)}
                      placeholder="e.g. Financial gain, espionage, disruption..."
                      className="w-full text-xs bg-transparent border rounded px-2 py-1.5 focus:border-primary outline-none" />
                  </div>
                </div>
              </div>
            </Section>

            {/* Controls Toggle */}
            <Section title="Controls / Mitigations" icon={<Shield size={14} />} id="controls" expanded={expandedSection} onToggle={setExpandedSection}>
              <p className="text-xs text-muted-foreground mb-2">Toggle controls on/off to simulate their failure or absence:</p>
              {allMitigations.length === 0 ? (
                <p className="text-xs text-muted-foreground italic">No mitigations found in the attack tree.</p>
              ) : (
                <div className="space-y-1 max-h-48 overflow-auto">
                  {allMitigations.map(m => (
                    <div key={m.id} className="flex items-center justify-between px-3 py-1.5 rounded hover:bg-accent text-xs">
                      <div className="flex-1">
                        <span className="font-medium">{m.title}</span>
                        <span className="text-muted-foreground ml-2">on {m.nodeName}</span>
                        <span className="text-muted-foreground ml-2">({Math.round(m.effectiveness * 100)}% eff.)</span>
                      </div>
                      <button onClick={() => toggleControl(m.id)} className="shrink-0">
                        {disabledControls.has(m.id)
                          ? <ToggleLeft size={20} className="text-red-500" />
                          : <ToggleRight size={20} className="text-green-500" />
                        }
                      </button>
                    </div>
                  ))}
                </div>
              )}
              {disabledControls.size > 0 && (
                <div className="mt-2 text-xs text-red-400">
                  ⚠️ {disabledControls.size} control(s) disabled
                </div>
              )}
            </Section>

            {/* Simulate + AI Analyze */}
            <div className="flex gap-2">
              <button onClick={handleSimulate} disabled={simLoading}
                className="flex items-center gap-2 px-4 py-2 rounded-lg bg-purple-600 text-white text-sm font-medium hover:bg-purple-700 disabled:opacity-50">
                {simLoading ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
                Run Simulation
              </button>
              <div className="flex-1 flex items-center gap-2">
                <input value={question} onChange={(e) => setQuestion(e.target.value)}
                  placeholder="Ask AI about this scenario (optional)..."
                  className="flex-1 text-xs bg-transparent border rounded-lg px-3 py-2 focus:border-primary outline-none" />
                <button onClick={handleAiAnalyze} disabled={aiLoading || selected.status !== 'completed'}
                  className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 text-white text-sm font-medium hover:bg-indigo-700 disabled:opacity-50">
                  {aiLoading ? <Loader2 size={15} className="animate-spin" /> : <Brain size={15} />}
                  AI Analyze
                </button>
              </div>
            </div>

            {/* Results */}
            {impact.original_risk != null && (
              <Section title="Simulation Results" icon={<Crosshair size={14} />} id="results" expanded={expandedSection} onToggle={setExpandedSection}>
                <div className="grid grid-cols-3 gap-3 mb-4">
                  <ResultCard label="Original Risk" value={impact.original_risk} />
                  <ResultCard label="Simulated Risk" value={impact.simulated_risk}
                    delta={impact.delta} />
                  <ResultCard label="Affected Nodes" value={impact.affected_nodes} />
                </div>

                {impact.node_details?.length > 0 && (
                  <div className="space-y-1">
                    <div className="text-[11px] font-semibold text-muted-foreground mb-1">Affected Nodes</div>
                    {impact.node_details.map((n: any) => (
                      <div key={n.id} className="flex items-center justify-between text-xs px-3 py-1.5 rounded bg-muted/30">
                        <span className="font-medium">{n.title}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-muted-foreground">{n.original_risk} →</span>
                          <span className={n.delta > 0 ? 'text-red-500 font-bold' : 'text-green-500 font-bold'}>
                            {n.simulated_risk}
                          </span>
                          <span className={cn('text-[10px]', n.delta > 0 ? 'text-red-400' : 'text-green-400')}>
                            {n.delta > 0 ? <TrendingUp size={12} className="inline" /> : <TrendingDown size={12} className="inline" />}
                            {n.delta > 0 ? '+' : ''}{n.delta}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {impact.key_findings?.length > 0 && (
                  <div className="mt-3">
                    <div className="text-[11px] font-semibold text-muted-foreground mb-1">Key Findings</div>
                    <ul className="space-y-1 text-xs">
                      {impact.key_findings.map((f: string, i: number) => (
                        <li key={i} className="flex gap-2"><AlertTriangle size={12} className="text-amber-500 shrink-0 mt-0.5" />{f}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {impact.answer && (
                  <div className="mt-3 p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/20">
                    <div className="text-[11px] font-semibold text-indigo-400 mb-1">AI Answer</div>
                    <p className="text-xs whitespace-pre-wrap">{impact.answer}</p>
                  </div>
                )}
              </Section>
            )}

            {/* AI Narrative */}
            {selected.ai_narrative && (
              <Section title="AI Narrative" icon={<Brain size={14} />} id="narrative" expanded={expandedSection} onToggle={setExpandedSection}>
                <div className="text-xs whitespace-pre-wrap leading-relaxed">{selected.ai_narrative}</div>
              </Section>
            )}

            {/* Recommendations */}
            {selected.ai_recommendations?.length > 0 && (
              <Section title="Recommendations" icon={<Shield size={14} />} id="recs" expanded={expandedSection} onToggle={setExpandedSection}>
                <div className="space-y-2">
                  {selected.ai_recommendations.map((r: any, i: number) => (
                    <div key={i} className="flex gap-3 text-xs p-2 rounded bg-muted/30">
                      <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0 h-fit',
                        r.priority === 'critical' ? 'bg-red-500/20 text-red-500' :
                        r.priority === 'high' ? 'bg-orange-500/20 text-orange-500' :
                        r.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-600' :
                        'bg-blue-500/20 text-blue-500'
                      )}>{r.priority}</span>
                      <div>
                        <div className="font-medium">{r.title}</div>
                        <div className="text-muted-foreground mt-0.5">{r.description}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </Section>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

// --- Helper components ---

function Section({ title, icon, id, expanded, onToggle, children }: {
  title: string; icon: React.ReactNode; id: string;
  expanded: string; onToggle: (id: string) => void;
  children: React.ReactNode;
}) {
  const isOpen = expanded === id;
  return (
    <div className="border rounded-lg">
      <button onClick={() => onToggle(isOpen ? '' : id)}
        className="flex items-center gap-2 w-full px-4 py-2.5 text-sm font-medium hover:bg-accent/50 rounded-t-lg">
        {icon}
        {title}
        <span className="ml-auto">{isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</span>
      </button>
      {isOpen && <div className="px-4 pb-4">{children}</div>}
    </div>
  );
}

function ResultCard({ label, value, delta }: { label: string; value: any; delta?: number }) {
  return (
    <div className="p-3 rounded-lg bg-muted/30 text-center">
      <div className="text-[10px] text-muted-foreground mb-1">{label}</div>
      <div className="text-lg font-bold">{typeof value === 'number' ? value.toFixed(1) : value}</div>
      {delta != null && (
        <div className={cn('text-xs font-medium', delta > 0 ? 'text-red-500' : delta < 0 ? 'text-green-500' : 'text-muted-foreground')}>
          {delta > 0 ? '+' : ''}{delta.toFixed(1)}
        </div>
      )}
    </div>
  );
}
