import { useState, useEffect, useCallback } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { NODE_TYPE_CONFIG, type NodeType, type LogicType, type NodeStatus, type AttackNodeData, type CommentData, type TagData } from '@/types';
import { cn } from '@/utils/cn';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import toast from 'react-hot-toast';
import { X, Plus, Trash2, Save, HelpCircle, MessageSquare, Tag, Send, Scale } from 'lucide-react';
import { RiskChallengerPanel } from '@/components/RiskChallengerPanel';

function getRiskTextClass(risk: number | null | undefined): string {
  if (risk == null) return 'text-muted-foreground';
  if (risk >= 7) return 'text-risk-critical';
  if (risk >= 4) return 'text-risk-medium';
  return 'text-risk-low';
}

const SCORE_HINTS: Record<string, string> = {
  Likelihood: 'How likely is this attack to occur? 0 = impossible, 10 = almost certain',
  Impact: 'How severe is the damage if successful? 0 = negligible, 10 = catastrophic',
  'Effort (attacker)': 'Resources/time the attacker needs. 0 = trivial, 10 = extreme effort',
  Exploitability: 'How easy is it to exploit? 0 = very difficult, 10 = trivially easy',
  Detectability: 'How easily can this attack be detected? 0 = invisible, 10 = obvious',
  Confidence: 'How confident are you in these scores? 0 = pure guess, 10 = evidence-based',
};

function getInitialScoringMode(): 'simple' | 'advanced' {
  try {
    const stored = localStorage.getItem('atb-scoring-mode');
    if (stored === 'advanced') return 'advanced';
  } catch {}
  return 'simple';
}

export function NodeInspector() {
  const queryClient = useQueryClient();
  const { selectedNodeId, nodes, setInspectorOpen, pushUndo, updateNodeLocal } = useStore();
  const node = nodes.find(n => n.id === selectedNodeId);
  const [activeTab, setActiveTab] = useState<'details' | 'scoring' | 'mitigations' | 'mappings' | 'comments' | 'notes'>('details');
  const [localData, setLocalData] = useState<Partial<AttackNodeData>>({});
  const [dirty, setDirty] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<{ type: 'mitigation' | 'detection' | 'mapping' | 'comment'; id: string; title: string } | null>(null);
  const [scoringMode, setScoringMode] = useState<'simple' | 'advanced'>(getInitialScoringMode);
  const [challengerOpen, setChallengerOpen] = useState(false);

  useEffect(() => {
    if (node) {
      setLocalData({ ...node });
      setDirty(false);
    }
  }, [node?.id, node?.updated_at]);

  const updateField = (field: string, value: any) => {
    setLocalData(prev => ({ ...prev, [field]: value }));
    setDirty(true);
  };

  const save = useCallback(async () => {
    if (!selectedNodeId || !dirty) return;
    try {
      pushUndo('Edit node');
      const updated = await api.updateNode(selectedNodeId, localData);
      updateNodeLocal(selectedNodeId, updated);
      setDirty(false);
      toast.success('Saved');
    } catch (e: any) {
      toast.error(e.message);
    }
  }, [selectedNodeId, localData, dirty, pushUndo, updateNodeLocal]);

  useEffect(() => {
    if (!dirty) return;
    const timer = setTimeout(save, 2000);
    return () => clearTimeout(timer);
  }, [localData, dirty, save]);

  const addMitigation = async () => {
    if (!selectedNodeId || !node) return;
    try {
      await api.createMitigation({ node_id: selectedNodeId, title: 'New Mitigation', effectiveness: 0.5 });
      const nodes = await api.listNodes(node.project_id);
      useStore.getState().setNodes(nodes);
      toast.success('Mitigation added');
    } catch (e: any) { toast.error(e.message); }
  };

  const addDetection = async () => {
    if (!selectedNodeId || !node) return;
    try {
      await api.createDetection({ node_id: selectedNodeId, title: 'New Detection', coverage: 0.5 });
      const nodes = await api.listNodes(node.project_id);
      useStore.getState().setNodes(nodes);
      toast.success('Detection added');
    } catch (e: any) { toast.error(e.message); }
  };

  const addMapping = async (framework: string, refId: string, refName: string) => {
    if (!selectedNodeId || !node) return;
    try {
      await api.createMapping({ node_id: selectedNodeId, framework, ref_id: refId, ref_name: refName });
      const nodes = await api.listNodes(node.project_id);
      useStore.getState().setNodes(nodes);
    } catch (e: any) { toast.error(e.message); }
  };

  const confirmDeleteItem = async () => {
    if (!pendingDelete || !node) return;
    try {
      if (pendingDelete.type === 'mitigation') {
        await api.deleteMitigation(pendingDelete.id);
      } else if (pendingDelete.type === 'detection') {
        await api.deleteDetection(pendingDelete.id);
      } else if (pendingDelete.type === 'mapping') {
        await api.deleteMapping(pendingDelete.id);
      } else if (pendingDelete.type === 'comment') {
        await api.deleteComment(pendingDelete.id);
        queryClient.invalidateQueries({ queryKey: ['comments', node.id] });
      }
      if (pendingDelete.type !== 'comment') {
        const nodes = await api.listNodes(node.project_id);
        useStore.getState().setNodes(nodes);
      }
      toast.success(`${pendingDelete.type.charAt(0).toUpperCase() + pendingDelete.type.slice(1)} deleted`);
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setPendingDelete(null);
    }
  };

  const toggleScoringMode = (mode: 'simple' | 'advanced') => {
    setScoringMode(mode);
    try { localStorage.setItem('atb-scoring-mode', mode); } catch {}
  };

  if (!node) return null;

  const TABS = [
    { id: 'details' as const, label: 'Details' },
    { id: 'scoring' as const, label: 'Scoring' },
    { id: 'mitigations' as const, label: `Mitigations (${node.mitigations?.length || 0})` },
    { id: 'mappings' as const, label: `Mappings (${node.reference_mappings?.length || 0})` },
    { id: 'comments' as const, label: 'Comments' },
    { id: 'notes' as const, label: 'Notes' },
  ];

  return (
    <div className="w-[380px] border-l bg-card flex flex-col h-full shrink-0">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b">
        <div className="flex items-center gap-2 min-w-0">
          <span>{NODE_TYPE_CONFIG[node.node_type as NodeType]?.icon}</span>
          <span className="font-semibold text-sm truncate">{node.title}</span>
          {dirty && <span className="text-xs text-warning">●</span>}
        </div>
        <div className="flex items-center gap-1">
          {dirty && (
            <button onClick={save} className="p-1 rounded hover:bg-accent text-primary">
              <Save size={14} />
            </button>
          )}
          <button onClick={() => setInspectorOpen(false)} className="p-1 rounded hover:bg-accent">
            <X size={14} />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b px-2 gap-0.5 overflow-x-auto">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={cn('px-2 py-2 text-xs font-medium border-b-2 transition-colors whitespace-nowrap', activeTab === tab.id ? 'border-primary text-primary' : 'border-transparent text-muted-foreground hover:text-foreground')}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-auto p-4 space-y-3">
        {activeTab === 'details' && (
          <>
            <Field label="Title">
              <input value={localData.title || ''} onChange={(e) => updateField('title', e.target.value)} className="input-field" />
            </Field>
            <Field label="Node Type">
              <select value={localData.node_type || 'attack_step'} onChange={(e) => updateField('node_type', e.target.value)} className="input-field">
                {Object.entries(NODE_TYPE_CONFIG).map(([k, v]) => <option key={k} value={k}>{v.icon} {v.label}</option>)}
              </select>
            </Field>
            <Field label="Logic Type">
              <div className="flex gap-1">
                {(['OR', 'AND', 'SEQUENCE'] as LogicType[]).map(lt => (
                  <button key={lt} onClick={() => updateField('logic_type', lt)}
                    className={cn('px-3 py-1 text-xs rounded font-bold', localData.logic_type === lt ? 'bg-primary text-primary-foreground' : 'bg-muted text-muted-foreground hover:bg-accent')}>
                    {lt}
                  </button>
                ))}
              </div>
            </Field>
            <Field label="Status">
              <select value={localData.status || 'draft'} onChange={(e) => updateField('status', e.target.value)} className="input-field">
                {['draft', 'validated', 'mitigated', 'accepted', 'archived'].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </Field>
            <Field label="Description">
              <textarea value={localData.description || ''} onChange={(e) => updateField('description', e.target.value)} rows={3} className="input-field" />
            </Field>
            <Field label="Platform / Environment">
              <input value={localData.platform || ''} onChange={(e) => updateField('platform', e.target.value)} className="input-field" placeholder="e.g., AWS, Android, Windows" />
            </Field>
            <Field label="Attack Surface">
              <input value={localData.attack_surface || ''} onChange={(e) => updateField('attack_surface', e.target.value)} className="input-field" placeholder="e.g., Web interface, API endpoint" />
            </Field>
            <Field label="Threat Category">
              <input value={localData.threat_category || ''} onChange={(e) => updateField('threat_category', e.target.value)} className="input-field" placeholder="e.g., Credential abuse" />
            </Field>
            <Field label="Required Access">
              <input value={localData.required_access || ''} onChange={(e) => updateField('required_access', e.target.value)} className="input-field" placeholder="e.g., Network, Physical, Remote" />
            </Field>
            <Field label="Required Privileges">
              <input value={localData.required_privileges || ''} onChange={(e) => updateField('required_privileges', e.target.value)} className="input-field" placeholder="e.g., None, User, Admin" />
            </Field>
            <Field label="Required Skill Level">
              <select value={localData.required_skill || ''} onChange={(e) => updateField('required_skill', e.target.value)} className="input-field">
                <option value="">Not set</option>
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="expert">Expert</option>
              </select>
            </Field>

            {/* Tags Section */}
            <TagsSection nodeId={node.id} projectId={node.project_id} tags={node.tags || []} />
          </>
        )}

        {activeTab === 'scoring' && (
          <>
            {/* Mode Toggle */}
            <div className="flex rounded-lg border overflow-hidden">
              <button
                onClick={() => toggleScoringMode('simple')}
                className={cn('flex-1 px-3 py-1.5 text-xs font-medium transition-colors', scoringMode === 'simple' ? 'bg-primary text-primary-foreground' : 'hover:bg-accent')}
              >
                Simple
              </button>
              <button
                onClick={() => toggleScoringMode('advanced')}
                className={cn('flex-1 px-3 py-1.5 text-xs font-medium transition-colors', scoringMode === 'advanced' ? 'bg-primary text-primary-foreground' : 'hover:bg-accent')}
              >
                Advanced
              </button>
            </div>

            {scoringMode === 'simple' ? (
              <>
                <div className="p-3 rounded-lg bg-muted/50 text-xs text-muted-foreground">
                  <strong>Formula:</strong> Risk = (Likelihood &times; Impact &times; Exploitability) / (Effort &times; Detectability), normalised to 0-10
                </div>
                <ScoreSlider label="Likelihood" hint={SCORE_HINTS['Likelihood']} value={localData.likelihood} onChange={(v) => updateField('likelihood', v)} />
                <ScoreSlider label="Impact" hint={SCORE_HINTS['Impact']} value={localData.impact} onChange={(v) => updateField('impact', v)} />
                <ScoreSlider label="Effort (attacker)" hint={SCORE_HINTS['Effort (attacker)']} value={localData.effort} onChange={(v) => updateField('effort', v)} />
                <ScoreSlider label="Exploitability" hint={SCORE_HINTS['Exploitability']} value={localData.exploitability} onChange={(v) => updateField('exploitability', v)} />
                <ScoreSlider label="Detectability" hint={SCORE_HINTS['Detectability']} value={localData.detectability} onChange={(v) => updateField('detectability', v)} />
                <ScoreSlider label="Confidence" hint={SCORE_HINTS['Confidence']} value={localData.confidence} onChange={(v) => updateField('confidence', v)} />
              </>
            ) : (
              <>
                <div className="p-3 rounded-lg bg-muted/50 text-xs text-muted-foreground">
                  <strong>Advanced Formula:</strong> Risk = Probability &times; Impact &times; (10 / Cost), normalised to 0-10
                </div>
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className="text-xs font-medium">Probability</span>
                    <span className="text-muted-foreground" title="Probability the attack succeeds. 0 = impossible, 1.0 = certain">
                      <HelpCircle size={12} />
                    </span>
                    <span className={cn('text-xs font-bold ml-auto', getRiskTextClass((localData.probability ?? 0) * 10))}>
                      {localData.probability ?? '—'}
                    </span>
                  </div>
                  <input
                    type="range"
                    min={0}
                    max={1}
                    step={0.05}
                    value={localData.probability ?? 0}
                    onChange={(e) => {
                      const v = Number(e.target.value);
                      updateField('probability', v === 0 ? null : v);
                    }}
                    className="w-full"
                  />
                  <div className="flex justify-between text-[10px] text-muted-foreground -mt-0.5">
                    <span>0</span>
                    <span>0.5</span>
                    <span>1.0</span>
                  </div>
                </div>
                <ScoreSlider label="Impact" hint="How severe is the damage if successful? 0 = negligible, 10 = catastrophic" value={localData.impact} onChange={(v) => updateField('impact', v)} />
                <div>
                  <div className="flex items-center gap-1.5 mb-1">
                    <span className="text-xs font-medium">Cost to Attacker</span>
                    <span className="text-muted-foreground" title="Resources the attacker must invest. 1 = cheap, 10 = very expensive">
                      <HelpCircle size={12} />
                    </span>
                    <span className={cn('text-xs font-bold ml-auto', (localData.cost_to_attacker ?? 0) >= 7 ? 'text-risk-low' : (localData.cost_to_attacker ?? 0) >= 4 ? 'text-risk-medium' : 'text-risk-critical')}>
                      {localData.cost_to_attacker ?? '—'}
                    </span>
                  </div>
                  <input
                    type="range"
                    min={1}
                    max={10}
                    step={1}
                    value={localData.cost_to_attacker ?? 1}
                    onChange={(e) => updateField('cost_to_attacker', Number(e.target.value))}
                    className="w-full"
                  />
                  <div className="flex justify-between text-[10px] text-muted-foreground -mt-0.5">
                    <span>1</span>
                    <span>5</span>
                    <span>10</span>
                  </div>
                </div>
              </>
            )}

            <div className="border-t pt-3 mt-3 space-y-2">
              <div className="flex justify-between text-sm">
                <span className="font-medium">Inherent Risk</span>
                <span className={cn('font-bold', getRiskTextClass(node.inherent_risk))}>
                  {node.inherent_risk ?? '—'}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="font-medium">Residual Risk</span>
                <span className="font-bold text-risk-low">{node.residual_risk ?? '—'}</span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="font-medium">Rolled-up Risk</span>
                <span className="font-bold">{node.rolled_up_risk ?? '—'}</span>
              </div>
            </div>
            <Field label="CVE References">
              <input value={localData.cve_references || ''} onChange={(e) => updateField('cve_references', e.target.value)} className="input-field" placeholder="CVE-2024-XXXX" />
            </Field>

            {/* Challenge Scores button */}
            <button
              onClick={() => setChallengerOpen(true)}
              className="w-full flex items-center justify-center gap-2 py-2 mt-2 rounded-lg bg-gradient-to-r from-amber-500/10 to-red-500/10 border border-amber-500/20 text-amber-400 text-xs font-medium hover:border-amber-500/40 transition-colors"
            >
              <Scale size={13} /> AI Challenge My Scores
            </button>
          </>
        )}

        {activeTab === 'mitigations' && (
          <>
            <button onClick={addMitigation} className="flex items-center gap-1 text-xs text-primary hover:underline">
              <Plus size={13} /> Add Mitigation
            </button>
            <button onClick={addDetection} className="flex items-center gap-1 text-xs text-primary hover:underline">
              <Plus size={13} /> Add Detection
            </button>
            {node.mitigations?.map(m => (
              <div key={m.id} className="p-2 rounded border success-box text-xs space-y-1">
                <div className="flex justify-between font-medium">
                  <span>&#10003; {m.title}</span>
                  <button
                    onClick={() => setPendingDelete({ type: 'mitigation', id: m.id, title: m.title })}
                    className="text-destructive hover:underline"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
                <div>Effectiveness: {(m.effectiveness * 100).toFixed(0)}%</div>
                <div className="text-muted-foreground">{m.status}</div>
              </div>
            ))}
            {node.detections?.map(d => (
              <div key={d.id} className="p-2 rounded border info-box text-xs space-y-1">
                <div className="flex justify-between font-medium">
                  <span>&#128065; {d.title}</span>
                  <button
                    onClick={() => setPendingDelete({ type: 'detection', id: d.id, title: d.title })}
                    className="text-destructive"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
                <div>Coverage: {(d.coverage * 100).toFixed(0)}%</div>
              </div>
            ))}
            {!node.mitigations?.length && !node.detections?.length && (
              <div className="text-xs text-muted-foreground text-center py-4">No mitigations or detections yet</div>
            )}
          </>
        )}

        {activeTab === 'mappings' && (
          <>
            <MappingAdder nodeId={node.id} onAdd={addMapping} />
            {node.reference_mappings?.map(r => (
              <div key={r.id} className="flex items-center justify-between p-2 rounded border text-xs">
                <div>
                  <span className="font-bold uppercase">{r.framework}</span>
                  <span className="ml-2 font-mono">{r.ref_id}</span>
                  <span className="ml-2 text-muted-foreground">{r.ref_name}</span>
                </div>
                <button
                  onClick={() => setPendingDelete({ type: 'mapping', id: r.id, title: `${r.framework} ${r.ref_id}` })}
                  className="text-destructive"
                >
                  <Trash2 size={12} />
                </button>
              </div>
            ))}
          </>
        )}

        {activeTab === 'comments' && (
          <CommentsTab nodeId={node.id} onRequestDelete={(id, preview) => setPendingDelete({ type: 'comment', id, title: preview })} />
        )}

        {activeTab === 'notes' && (
          <>
            <Field label="Detailed Analyst Notes">
              <textarea value={localData.notes || ''} onChange={(e) => updateField('notes', e.target.value)} rows={6} className="input-field" placeholder="Detailed analysis, findings, rationale..." />
            </Field>
            <Field label="Assumptions & Dependencies">
              <textarea value={localData.assumptions || ''} onChange={(e) => updateField('assumptions', e.target.value)} rows={3} className="input-field" placeholder="Key assumptions..." />
            </Field>
            <Field label="Analyst / Owner">
              <input value={localData.analyst || ''} onChange={(e) => updateField('analyst', e.target.value)} className="input-field" />
            </Field>
          </>
        )}
      </div>

      <ConfirmDialog
        open={!!pendingDelete}
        onOpenChange={(open) => { if (!open) setPendingDelete(null); }}
        onConfirm={confirmDeleteItem}
        title={`Delete ${pendingDelete?.type || 'item'}`}
        description={`Are you sure you want to delete "${pendingDelete?.title || 'this item'}"?`}
        confirmLabel="Delete"
        destructive
      />

      {node && (
        <RiskChallengerPanel node={node} open={challengerOpen} onClose={() => setChallengerOpen(false)} />
      )}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">{label}</label>
      <div className="mt-1">{children}</div>
    </div>
  );
}

function ScoreSlider({ label, hint, value, onChange }: { label: string; hint?: string; value: number | null | undefined; onChange: (v: number | null) => void }) {
  const [showHint, setShowHint] = useState(false);
  const numVal = value ?? 0;

  const getValueColor = () => {
    if (value == null) return 'text-muted-foreground';
    if (label === 'Effort (attacker)' || label === 'Detectability') {
      if (numVal >= 7) return 'text-risk-low';
      if (numVal >= 4) return 'text-risk-medium';
      return 'text-risk-critical';
    }
    if (numVal >= 7) return 'text-risk-critical';
    if (numVal >= 4) return 'text-risk-medium';
    return 'text-risk-low';
  };

  return (
    <div>
      <div className="flex items-center gap-1.5 mb-1">
        <span className="text-xs font-medium">{label}</span>
        {hint && (
          <button
            onClick={() => setShowHint(!showHint)}
            className="text-muted-foreground hover:text-foreground transition-colors"
            title={hint}
          >
            <HelpCircle size={12} />
          </button>
        )}
        <span className={cn('text-xs font-bold ml-auto', getValueColor())}>{value ?? '—'}</span>
      </div>
      {showHint && (
        <div className="text-[11px] text-muted-foreground mb-1.5 leading-relaxed">
          {hint}
        </div>
      )}
      <input
        type="range"
        min={0}
        max={10}
        step={1}
        value={numVal}
        onChange={(e) => {
          const v = Number(e.target.value);
          onChange(v === 0 ? null : v);
        }}
        className="w-full"
      />
      <div className="flex justify-between text-[10px] text-muted-foreground -mt-0.5">
        <span>0</span>
        <span>5</span>
        <span>10</span>
      </div>
    </div>
  );
}

function CommentsTab({ nodeId, onRequestDelete }: { nodeId: string; onRequestDelete: (id: string, preview: string) => void }) {
  const queryClient = useQueryClient();
  const [newComment, setNewComment] = useState('');
  const [author, setAuthor] = useState('analyst');

  const { data: comments = [], isLoading } = useQuery({
    queryKey: ['comments', nodeId],
    queryFn: () => api.listComments(nodeId),
  });

  const createMutation = useMutation({
    mutationFn: api.createComment,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['comments', nodeId] });
      setNewComment('');
      toast.success('Comment added');
    },
    onError: (e: any) => toast.error(e.message),
  });

  const handleSubmit = () => {
    if (!newComment.trim()) return;
    createMutation.mutate({ node_id: nodeId, author, text: newComment.trim() });
  };

  const formatTime = (dateStr: string) => {
    try {
      const d = new Date(dateStr);
      const now = new Date();
      const diff = now.getTime() - d.getTime();
      const mins = Math.floor(diff / 60000);
      if (mins < 1) return 'just now';
      if (mins < 60) return `${mins}m ago`;
      const hours = Math.floor(mins / 60);
      if (hours < 24) return `${hours}h ago`;
      const days = Math.floor(hours / 24);
      if (days < 7) return `${days}d ago`;
      return d.toLocaleDateString();
    } catch {
      return dateStr;
    }
  };

  return (
    <div className="space-y-3">
      <div className="space-y-2">
        <div className="flex gap-2">
          <input
            value={author}
            onChange={(e) => setAuthor(e.target.value)}
            className="input-field !w-24 !py-1 text-xs"
            placeholder="Author"
          />
          <div className="flex-1" />
        </div>
        <div className="flex gap-1">
          <textarea
            value={newComment}
            onChange={(e) => setNewComment(e.target.value)}
            placeholder="Add a comment..."
            rows={2}
            className="input-field flex-1"
            onKeyDown={(e) => {
              if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) handleSubmit();
            }}
          />
        </div>
        <div className="flex justify-between items-center">
          <span className="text-[10px] text-muted-foreground">Ctrl+Enter to post</span>
          <button
            onClick={handleSubmit}
            disabled={!newComment.trim() || createMutation.isPending}
            className="flex items-center gap-1 px-3 py-1 text-xs rounded-md bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50"
          >
            <Send size={12} /> Post
          </button>
        </div>
      </div>

      {isLoading ? (
        <div className="space-y-2">
          {[1, 2, 3].map(i => <div key={i} className="h-16 skeleton rounded" />)}
        </div>
      ) : comments.length === 0 ? (
        <div className="text-xs text-muted-foreground text-center py-6">
          <MessageSquare size={20} className="mx-auto mb-2 opacity-40" />
          No comments yet
        </div>
      ) : (
        <div className="space-y-2">
          {[...comments].reverse().map((c: CommentData) => (
            <div key={c.id} className="p-2.5 rounded-lg border bg-muted/30 text-xs space-y-1">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="font-semibold">{c.author}</span>
                  <span className="text-muted-foreground">{formatTime(c.created_at)}</span>
                </div>
                <button
                  onClick={() => onRequestDelete(c.id, c.text.substring(0, 30) + (c.text.length > 30 ? '...' : ''))}
                  className="text-muted-foreground hover:text-destructive transition-colors"
                >
                  <Trash2 size={11} />
                </button>
              </div>
              <p className="text-foreground leading-relaxed whitespace-pre-wrap">{c.text}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TagsSection({ nodeId, projectId, tags }: { nodeId: string; projectId: string; tags: TagData[] }) {
  const [inputValue, setInputValue] = useState('');
  const [showSuggestions, setShowSuggestions] = useState(false);

  const { data: allTags = [] } = useQuery({
    queryKey: ['tags'],
    queryFn: api.listTags,
  });

  const queryClient = useQueryClient();

  const refreshNodes = async () => {
    const nodes = await api.listNodes(projectId);
    useStore.getState().setNodes(nodes);
  };

  const addTag = async (tag: TagData) => {
    try {
      await api.addTagToNode(nodeId, tag.id);
      await refreshNodes();
      queryClient.invalidateQueries({ queryKey: ['tags'] });
      setInputValue('');
      setShowSuggestions(false);
      toast.success(`Tag "${tag.name}" added`);
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const createAndAddTag = async (name: string) => {
    try {
      const tag = await api.createTag({ name: name.trim() });
      await api.addTagToNode(nodeId, tag.id);
      await refreshNodes();
      queryClient.invalidateQueries({ queryKey: ['tags'] });
      setInputValue('');
      setShowSuggestions(false);
      toast.success(`Tag "${name}" created and added`);
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const removeTag = async (tagId: string) => {
    try {
      await api.removeTagFromNode(nodeId, tagId);
      await refreshNodes();
      toast.success('Tag removed');
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const currentTagIds = new Set(tags.map(t => t.id));
  const suggestions = allTags
    .filter((t: TagData) => !currentTagIds.has(t.id) && t.name.toLowerCase().includes(inputValue.toLowerCase()))
    .slice(0, 8);
  const exactMatch = allTags.find((t: TagData) => t.name.toLowerCase() === inputValue.trim().toLowerCase());

  const TAG_COLORS = ['bg-blue-500/20 text-blue-300', 'bg-purple-500/20 text-purple-300', 'bg-emerald-500/20 text-emerald-300', 'bg-amber-500/20 text-amber-300', 'bg-rose-500/20 text-rose-300', 'bg-cyan-500/20 text-cyan-300'];
  const getTagColor = (name: string) => TAG_COLORS[Math.abs(name.split('').reduce((a, c) => a + c.charCodeAt(0), 0)) % TAG_COLORS.length];

  return (
    <Field label="Tags">
      <div className="space-y-2">
        {tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {tags.map(tag => (
              <span key={tag.id} className={cn('inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium', getTagColor(tag.name))}>
                <Tag size={10} />
                {tag.name}
                <button onClick={() => removeTag(tag.id)} className="hover:opacity-70 ml-0.5">&times;</button>
              </span>
            ))}
          </div>
        )}

        <div className="relative">
          <input
            value={inputValue}
            onChange={(e) => { setInputValue(e.target.value); setShowSuggestions(true); }}
            onFocus={() => setShowSuggestions(true)}
            onBlur={() => setTimeout(() => setShowSuggestions(false), 200)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && inputValue.trim()) {
                e.preventDefault();
                if (exactMatch && !currentTagIds.has(exactMatch.id)) {
                  addTag(exactMatch);
                } else if (!exactMatch) {
                  createAndAddTag(inputValue);
                }
              }
            }}
            placeholder="Add tag..."
            className="input-field !py-1 text-xs"
          />
          {showSuggestions && inputValue.trim() && (suggestions.length > 0 || (!exactMatch && inputValue.trim())) && (
            <div className="absolute z-10 mt-1 w-full bg-card border rounded-lg shadow-lg max-h-40 overflow-auto">
              {suggestions.map((t: TagData) => (
                <button
                  key={t.id}
                  onMouseDown={(e) => { e.preventDefault(); addTag(t); }}
                  className="w-full text-left px-3 py-1.5 text-xs hover:bg-accent transition-colors"
                >
                  <Tag size={10} className="inline mr-1.5 opacity-50" />{t.name}
                </button>
              ))}
              {!exactMatch && inputValue.trim() && (
                <button
                  onMouseDown={(e) => { e.preventDefault(); createAndAddTag(inputValue); }}
                  className="w-full text-left px-3 py-1.5 text-xs hover:bg-accent transition-colors text-primary"
                >
                  <Plus size={10} className="inline mr-1.5" />Create "{inputValue.trim()}"
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    </Field>
  );
}

function MappingAdder({ nodeId, onAdd }: { nodeId: string; onAdd: (framework: string, refId: string, refName: string) => void }) {
  const [fw, setFw] = useState('attack');
  const [refId, setRefId] = useState('');
  const [refName, setRefName] = useState('');
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [query, setQuery] = useState('');

  const search = async () => {
    if (!query.trim()) return;
    try {
      const result = await api.browseReferences(fw, query);
      setSearchResults(result.items.slice(0, 10));
    } catch {
      setSearchResults([]);
    }
  };

  return (
    <div className="space-y-2">
      <div className="flex gap-1">
        <select value={fw} onChange={(e) => { setFw(e.target.value); setSearchResults([]); }} className="input-field !w-auto !py-1">
          <option value="attack">ATT&CK</option>
          <option value="capec">CAPEC</option>
          <option value="cwe">CWE</option>
          <option value="owasp">OWASP</option>
        </select>
        <input value={query} onChange={(e) => setQuery(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && search()} placeholder="Search references..." className="input-field !py-1" />
        <button onClick={search} className="px-2 py-1 text-xs rounded bg-primary text-primary-foreground shrink-0">Search</button>
      </div>
      {searchResults.map((item, i) => (
        <button
          key={i}
          onClick={() => { onAdd(fw, item.id, item.name); setSearchResults([]); setQuery(''); toast.success(`Added ${item.id}`); }}
          className="w-full text-left p-2 rounded border hover:bg-accent text-xs"
        >
          <span className="font-mono font-bold">{item.id}</span>
          <span className="ml-2">{item.name}</span>
        </button>
      ))}
      <div className="flex gap-1">
        <input value={refId} onChange={(e) => setRefId(e.target.value)} placeholder="Ref ID (e.g., T1566)" className="input-field !py-1" />
        <input value={refName} onChange={(e) => setRefName(e.target.value)} placeholder="Name" className="input-field !py-1" />
        <button onClick={() => { if (refId) { onAdd(fw, refId, refName); setRefId(''); setRefName(''); } }} className="px-2 py-1 text-xs rounded border hover:bg-accent shrink-0">
          <Plus size={13} />
        </button>
      </div>
    </div>
  );
}
