import { useEffect, useMemo, useRef, useState } from 'react';
import type { PlanningProfile } from '@/types';
import {
  AlertTriangle,
  BadgeAlert,
  Brain,
  BriefcaseBusiness,
  Crosshair,
  FlaskConical,
  Focus,
  Globe,
  Layers3,
  Loader2,
  Play,
  Plus,
  Radar,
  Shield,
  Sparkles,
  Trash2,
  Waypoints,
} from 'lucide-react';
import toast from 'react-hot-toast';

import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import { getPlanningProfileOption, PLANNING_PROFILE_OPTIONS } from '@/utils/planningProfiles';
import { formatContextPreset, getContextPresetOption, getEnvironmentContextPresets } from '@/utils/contextPresets';

interface ScenarioData {
  id: string;
  project_id: string | null;
  project_name: string;
  scope: 'standalone' | 'project';
  name: string;
  description: string;
  status: string;
  scenario_type: string;
  operation_goal: string;
  target_profile: string;
  target_environment: string;
  execution_tempo: string;
  stealth_level: string;
  access_level: string;
  attacker_type: string;
  attacker_skill: string;
  attacker_resources: string;
  attacker_motivation: string;
  entry_vectors: string[];
  campaign_phases: string[];
  constraints: string[];
  dependencies: string[];
  intelligence_gaps: string[];
  success_criteria: string[];
  focus_node_ids: string[];
  focus_tags: string[];
  disabled_controls: string[];
  degraded_detections: string[];
  modified_scores: Record<string, Record<string, number>>;
  assumptions: string;
  planning_notes: string;
  ai_narrative: string;
  ai_recommendations: Array<{ priority: string; title: string; description: string }>;
  impact_summary: Record<string, any>;
  created_at: string;
  updated_at: string;
}

type ScopeFilter = 'workspace' | 'project' | 'standalone';

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

function recommendationList(value: unknown): Array<{ priority: string; title: string; description: string }> {
  if (!Array.isArray(value)) return [];
  return value
    .filter(isRecord)
    .map((item) => ({
      priority: typeof item.priority === 'string' && item.priority.trim() ? item.priority : 'medium',
      title: typeof item.title === 'string' ? item.title : 'Untitled recommendation',
      description: typeof item.description === 'string' ? item.description : '',
    }));
}

function normalizeModifiedScores(value: unknown): Record<string, Record<string, number>> {
  if (!isRecord(value)) return {};
  const result: Record<string, Record<string, number>> = {};
  Object.entries(value).forEach(([nodeId, scores]) => {
    if (!isRecord(scores)) return;
    const normalizedScores: Record<string, number> = {};
    Object.entries(scores).forEach(([key, raw]) => {
      if (typeof raw === 'number' && Number.isFinite(raw)) {
        normalizedScores[key] = raw;
      }
    });
    result[nodeId] = normalizedScores;
  });
  return result;
}

function normalizeImpactSummary(value: unknown): Record<string, any> {
  if (!isRecord(value)) return {};
  return {
    ...value,
    campaign_profile: isRecord(value.campaign_profile) ? value.campaign_profile : {},
    planning_findings: stringList(value.planning_findings),
    key_findings: stringList(value.key_findings),
    attack_paths_enabled: stringList(value.attack_paths_enabled),
    intelligence_priorities: stringList(value.intelligence_priorities),
    defender_pain_points: stringList(value.defender_pain_points),
    top_exposed_controls: Array.isArray(value.top_exposed_controls) ? value.top_exposed_controls.filter(isRecord) : [],
    top_degraded_detections: Array.isArray(value.top_degraded_detections) ? value.top_degraded_detections.filter(isRecord) : [],
    node_details: Array.isArray(value.node_details) ? value.node_details.filter(isRecord) : [],
    phase_plan: Array.isArray(value.phase_plan) ? value.phase_plan.filter(isRecord).map((item) => ({
      ...item,
      phase: typeof item.phase === 'string' ? item.phase : 'Unnamed phase',
      objective: typeof item.objective === 'string' ? item.objective : '',
      actions: stringList(item.actions),
      dependencies: stringList(item.dependencies),
      detection_considerations: stringList(item.detection_considerations),
    })) : [],
    executive_summary: typeof value.executive_summary === 'string' ? value.executive_summary : '',
    note: typeof value.note === 'string' ? value.note : '',
    answer: typeof value.answer === 'string' ? value.answer : '',
    simulation_mode: typeof value.simulation_mode === 'string' ? value.simulation_mode : '',
  };
}

function normalizeScenario(value: any): ScenarioData {
  const scope = value?.scope === 'project' ? 'project' : 'standalone';
  const targetEnvironment =
    typeof value?.target_environment === 'string'
      ? (getContextPresetOption(value.target_environment)?.name || value.target_environment)
      : '';
  return {
    ...value,
    project_id: typeof value?.project_id === 'string' ? value.project_id : null,
    project_name: typeof value?.project_name === 'string' ? value.project_name : '',
    scope,
    name: typeof value?.name === 'string' ? value.name : 'Untitled Scenario',
    description: typeof value?.description === 'string' ? value.description : '',
    status: typeof value?.status === 'string' ? value.status : 'draft',
    scenario_type: typeof value?.scenario_type === 'string' ? value.scenario_type : 'campaign',
    operation_goal: typeof value?.operation_goal === 'string' ? value.operation_goal : '',
    target_profile: typeof value?.target_profile === 'string' ? value.target_profile : '',
    target_environment: targetEnvironment,
    execution_tempo: typeof value?.execution_tempo === 'string' ? value.execution_tempo : 'balanced',
    stealth_level: typeof value?.stealth_level === 'string' ? value.stealth_level : 'balanced',
    access_level: typeof value?.access_level === 'string' ? value.access_level : 'external',
    attacker_type: typeof value?.attacker_type === 'string' ? value.attacker_type : 'opportunistic',
    attacker_skill: typeof value?.attacker_skill === 'string' ? value.attacker_skill : 'Medium',
    attacker_resources: typeof value?.attacker_resources === 'string' ? value.attacker_resources : 'Medium',
    attacker_motivation: typeof value?.attacker_motivation === 'string' ? value.attacker_motivation : '',
    entry_vectors: stringList(value?.entry_vectors),
    campaign_phases: stringList(value?.campaign_phases),
    constraints: stringList(value?.constraints),
    dependencies: stringList(value?.dependencies),
    intelligence_gaps: stringList(value?.intelligence_gaps),
    success_criteria: stringList(value?.success_criteria),
    focus_node_ids: stringList(value?.focus_node_ids),
    focus_tags: stringList(value?.focus_tags),
    disabled_controls: stringList(value?.disabled_controls),
    degraded_detections: stringList(value?.degraded_detections),
    modified_scores: normalizeModifiedScores(value?.modified_scores),
    assumptions: typeof value?.assumptions === 'string' ? value.assumptions : '',
    planning_notes: typeof value?.planning_notes === 'string' ? value.planning_notes : '',
    ai_narrative: typeof value?.ai_narrative === 'string' ? value.ai_narrative : '',
    ai_recommendations: recommendationList(value?.ai_recommendations),
    impact_summary: normalizeImpactSummary(value?.impact_summary),
    created_at: typeof value?.created_at === 'string' ? value.created_at : '',
    updated_at: typeof value?.updated_at === 'string' ? value.updated_at : '',
  };
}

const SCENARIO_TYPES = [
  { id: 'campaign', label: 'Campaign' },
  { id: 'collection', label: 'Collection' },
  { id: 'disruption', label: 'Disruption' },
  { id: 'identity', label: 'Identity' },
  { id: 'supply_chain', label: 'Supply Chain' },
  { id: 'tabletop', label: 'Tabletop' },
];

const ATTACKER_TYPES = [
  { id: 'script_kiddie', label: 'Script Kiddie' },
  { id: 'opportunistic', label: 'Opportunistic' },
  { id: 'insider', label: 'Insider' },
  { id: 'apt', label: 'APT / Organised Crime' },
  { id: 'nation_state', label: 'Nation State' },
  { id: 'red_team', label: 'Red Team' },
];

const SKILL_LEVELS = ['Low', 'Medium', 'High', 'Expert'];
const RESOURCE_LEVELS = ['Low', 'Medium', 'High', 'Unlimited'];
const TEMPO_OPTIONS = ['deliberate', 'balanced', 'rapid'];
const STEALTH_OPTIONS = ['covert', 'balanced', 'aggressive'];
const ACCESS_OPTIONS = ['external', 'partner', 'insider', 'privileged'];
const ENVIRONMENT_PRESET_OPTIONS = getEnvironmentContextPresets();

const SCENARIO_PRESETS = [
  {
    name: 'Enterprise Intrusion',
    description: 'Multi-stage enterprise intrusion with identity and lateral movement emphasis.',
    scenario_type: 'campaign',
    attacker_type: 'apt',
    entry_vectors: ['Phishing', 'External remote access', 'Trusted partner access'],
    campaign_phases: ['Initial access', 'Credential access', 'Lateral movement', 'Collection', 'Exfiltration'],
  },
  {
    name: 'Cloud Control Plane Abuse',
    description: 'Identity-driven cloud campaign focused on control-plane takeover and persistence.',
    scenario_type: 'identity',
    attacker_type: 'apt',
    entry_vectors: ['Leaked credentials', 'OAuth abuse', 'CI/CD secrets exposure'],
    campaign_phases: ['Credential acquisition', 'Privilege escalation', 'Persistence', 'Collection'],
  },
  {
    name: 'Insider Abuse',
    description: 'Privileged insider misuse with access and detection asymmetry.',
    scenario_type: 'collection',
    attacker_type: 'insider',
    access_level: 'insider',
    entry_vectors: ['Privileged account misuse', 'Shadow admin paths'],
    campaign_phases: ['Access validation', 'Discovery', 'Collection', 'Cover tracks'],
  },
  {
    name: 'Supply Chain Pivot',
    description: 'Third-party compromise used to gain trusted access into the target estate.',
    scenario_type: 'supply_chain',
    attacker_type: 'apt',
    access_level: 'partner',
    entry_vectors: ['Vendor remote access', 'Build pipeline compromise', 'Dependency poisoning'],
    campaign_phases: ['Supplier compromise', 'Trust exploitation', 'Execution', 'Persistence'],
  },
  {
    name: 'Service Disruption',
    description: 'High-tempo disruption scenario designed to stress resilience, detection, and response.',
    scenario_type: 'disruption',
    attacker_type: 'nation_state',
    execution_tempo: 'rapid',
    stealth_level: 'aggressive',
    entry_vectors: ['Internet-facing service abuse', 'Identity takeover', 'Admin tooling abuse'],
    campaign_phases: ['Preparation', 'Execution', 'Impact', 'Recovery friction'],
  },
];

export function ScenarioSimulationView() {
  const { currentProject, nodes, setNodes } = useStore();
  const [scenarios, setScenarios] = useState<ScenarioData[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>(currentProject ? 'workspace' : 'standalone');
  const [loading, setLoading] = useState(false);
  const [simLoading, setSimLoading] = useState(false);
  const [aiLoading, setAiLoading] = useState(false);
  const [suggestLoading, setSuggestLoading] = useState(false);
  const [question, setQuestion] = useState('');
  const [planningProfile, setPlanningProfile] = useState<PlanningProfile>('planning_first');
  const patchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const queuedPatchIdRef = useRef<string | null>(null);
  const queuedPatchRef = useRef<Partial<ScenarioData>>({});

  const selected = useMemo(
    () => scenarios.find((scenario) => scenario.id === selectedId) ?? null,
    [scenarios, selectedId]
  );
  const selectedPlanningProfile = useMemo(
    () => getPlanningProfileOption(planningProfile),
    [planningProfile],
  );

  useEffect(() => {
    if (!currentProject && scopeFilter !== 'standalone') {
      setScopeFilter('standalone');
    }
  }, [currentProject, scopeFilter]);

  useEffect(() => {
    if (currentProject && nodes.length === 0) {
      api.listNodes(currentProject.id).then((data) => setNodes(data)).catch(() => {});
    }
  }, [currentProject?.id]);

  useEffect(() => {
    loadScenarios();
  }, [currentProject?.id, scopeFilter]);

  useEffect(() => {
    return () => {
      if (patchTimerRef.current) {
        clearTimeout(patchTimerRef.current);
      }
    };
  }, []);

  useEffect(() => {
    if (queuedPatchIdRef.current && selectedId && queuedPatchIdRef.current !== selectedId) {
      void flushScenarioPatch(queuedPatchIdRef.current);
    }
  }, [selectedId]);

  const allMitigations = useMemo(
    () => nodes.flatMap((node) => (node.mitigations || []).map((mitigation) => ({ ...mitigation, nodeName: node.title }))),
    [nodes]
  );
  const allDetections = useMemo(
    () => nodes.flatMap((node) => (node.detections || []).map((detection) => ({ ...detection, nodeName: node.title }))),
    [nodes]
  );

  async function loadScenarios() {
    setLoading(true);
    try {
      const rawData =
        scopeFilter === 'workspace'
          ? await api.listScenarioWorkspace(currentProject?.id)
          : await api.listScenarios(currentProject?.id, scopeFilter);
      const data = Array.isArray(rawData) ? rawData.map((item) => normalizeScenario(item)) : [];
      setScenarios(data);
      setSelectedId((current) => (current && data.some((item: ScenarioData) => item.id === current) ? current : data[0]?.id ?? null));
    } catch (error: any) {
      toast.error(error.message);
      setScenarios([]);
      setSelectedId(null);
    } finally {
      setLoading(false);
    }
  }

  async function flushScenarioPatch(scenarioId?: string) {
    const targetId = scenarioId || queuedPatchIdRef.current;
    if (!targetId) return;
    const updates = { ...queuedPatchRef.current };
    if (!Object.keys(updates).length) return;
    queuedPatchRef.current = {};
    queuedPatchIdRef.current = null;
    if (patchTimerRef.current) {
      clearTimeout(patchTimerRef.current);
      patchTimerRef.current = null;
    }
    try {
      const updated = await api.updateScenario(targetId, updates);
      syncScenario(normalizeScenario(updated));
    } catch (error: any) {
      toast.error(error.message);
      loadScenarios();
    }
  }

  async function patchScenario(updates: Partial<ScenarioData>, options?: { debounce?: boolean }) {
    if (!selected) return;
    const optimistic = { ...selected, ...updates };
    setScenarios((current) => current.map((scenario) => (scenario.id === selected.id ? optimistic : scenario)));

    if (options?.debounce) {
      queuedPatchIdRef.current = selected.id;
      queuedPatchRef.current = { ...queuedPatchRef.current, ...updates };
      if (patchTimerRef.current) {
        clearTimeout(patchTimerRef.current);
      }
      patchTimerRef.current = setTimeout(() => {
        void flushScenarioPatch(selected.id);
      }, 500);
      return;
    }

    const immediateUpdates = queuedPatchIdRef.current === selected.id
      ? { ...queuedPatchRef.current, ...updates }
      : updates;
    queuedPatchRef.current = {};
    queuedPatchIdRef.current = null;
    if (patchTimerRef.current) {
      clearTimeout(patchTimerRef.current);
      patchTimerRef.current = null;
    }
    try {
      const updated = await api.updateScenario(selected.id, immediateUpdates);
      syncScenario(normalizeScenario(updated));
    } catch (error: any) {
      toast.error(error.message);
      loadScenarios();
    }
  }

  function patchScenarioText(updates: Partial<ScenarioData>) {
    void patchScenario(updates, { debounce: true });
  }

  function syncScenario(updated: ScenarioData) {
    const normalized = normalizeScenario(updated);
    setScenarios((current) => current.map((scenario) => (scenario.id === normalized.id ? normalized : scenario)));
    setSelectedId(normalized.id);
  }

  async function handleCreate(preset?: Partial<ScenarioData>) {
    const scope = !currentProject || scopeFilter === 'standalone' ? 'standalone' : 'project';
    const payload = {
      scope,
      project_id: scope === 'project' ? currentProject?.id : null,
      name: preset?.name || `${scope === 'project' ? 'Project' : 'Standalone'} Scenario ${scenarios.length + 1}`,
      description: preset?.description || '',
      scenario_type: preset?.scenario_type || 'campaign',
      operation_goal: preset?.operation_goal || currentProject?.root_objective || '',
      target_profile: preset?.target_profile || currentProject?.name || '',
      target_environment: preset?.target_environment || (currentProject?.context_preset ? formatContextPreset(currentProject.context_preset) : ''),
      execution_tempo: preset?.execution_tempo || 'balanced',
      stealth_level: preset?.stealth_level || 'balanced',
      access_level: preset?.access_level || 'external',
      attacker_type: preset?.attacker_type || 'opportunistic',
      attacker_skill: preset?.attacker_skill || 'Medium',
      attacker_resources: preset?.attacker_resources || 'Medium',
      attacker_motivation: preset?.attacker_motivation || '',
      entry_vectors: preset?.entry_vectors || [],
      campaign_phases: preset?.campaign_phases || [],
      constraints: preset?.constraints || [],
      dependencies: preset?.dependencies || [],
      intelligence_gaps: preset?.intelligence_gaps || [],
      success_criteria: preset?.success_criteria || [],
      assumptions: preset?.assumptions || '',
      planning_notes: preset?.planning_notes || '',
    };

    try {
      const created = await api.createScenario(payload);
      const normalized = normalizeScenario(created);
      setScenarios((current) => [normalized, ...current]);
      setSelectedId(normalized.id);
    } catch (error: any) {
      toast.error(error.message);
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.deleteScenario(id);
      setScenarios((current) => current.filter((scenario) => scenario.id !== id));
      setSelectedId((current) => (current === id ? null : current));
      toast.success('Scenario deleted');
    } catch (error: any) {
      toast.error(error.message);
    }
  }

  async function handleSimulate() {
    if (!selected) return;
    setSimLoading(true);
    try {
      await flushScenarioPatch(selected.id);
      const result = await api.simulateScenario(selected.id, {
        disabled_controls: selected.disabled_controls || [],
        degraded_detections: selected.degraded_detections || [],
        modified_scores: selected.modified_scores || {},
        attacker_type: selected.attacker_type,
        attacker_skill: selected.attacker_skill,
        attacker_resources: selected.attacker_resources,
        execution_tempo: selected.execution_tempo,
        stealth_level: selected.stealth_level,
        access_level: selected.access_level,
        focus_node_ids: selected.focus_node_ids || [],
        focus_tags: selected.focus_tags || [],
      });
      syncScenario(normalizeScenario(result));
      toast.success('Planning pass complete');
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setSimLoading(false);
    }
  }

  async function handleAiAnalyze() {
    if (!selected) return;
    setAiLoading(true);
    try {
      await flushScenarioPatch(selected.id);
      const result = await api.aiAnalyzeScenario(selected.id, { question, planning_profile: planningProfile });
      syncScenario(normalizeScenario(result));
      toast.success('AI planning brief ready');
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setAiLoading(false);
    }
  }

  async function handleAiSuggest() {
    setSuggestLoading(true);
    try {
      const result = await api.generateScenarioSuggestions({
        project_id: currentProject?.id,
        focus: selected?.operation_goal || currentProject?.root_objective || '',
        count: 6,
        planning_profile: planningProfile,
      });
      const suggestions = result.suggestions || [];
      const created = await Promise.all(suggestions.map((suggestion: any) => api.createScenario(suggestion)));
      const normalizedCreated = created.map((item) => normalizeScenario(item));
      setScenarios((current) => [...normalizedCreated, ...current]);
      if (normalizedCreated[0]?.id) setSelectedId(normalizedCreated[0].id);
      toast.success(`Generated ${normalizedCreated.length} scenario ideas`);
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setSuggestLoading(false);
    }
  }

  function toggleListValue(field: 'disabled_controls' | 'degraded_detections' | 'focus_node_ids', value: string) {
    if (!selected) return;
    const current = new Set(selected[field] || []);
    if (current.has(value)) current.delete(value);
    else current.add(value);
    patchScenario({ [field]: [...current] } as Partial<ScenarioData>);
  }

  const linkedProjectActive = !!selected?.project_id && selected.project_id === currentProject?.id;
  const impact = selected?.impact_summary || {};
  const profile = impact.campaign_profile || {};
  const planningMode = impact.simulation_mode === 'planning' || !selected?.project_id;

  return (
    <div className="h-full flex bg-[radial-gradient(circle_at_top_left,_rgba(56,189,248,0.08),_transparent_32%),radial-gradient(circle_at_top_right,_rgba(168,85,247,0.09),_transparent_28%)]">
      <aside className="w-80 border-r border-border/40 bg-card/70 backdrop-blur-sm flex flex-col shrink-0">
        <div className="p-4 border-b border-border/40 space-y-3">
          <div className="flex items-start justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 text-sm font-semibold">
                <FlaskConical size={16} className="text-cyan-400" />
                Scenario Workspace
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {currentProject
                  ? `Planning against ${currentProject.name} plus standalone scenarios`
                  : 'Standalone planning library for cyber operations'}
              </p>
            </div>
            <div className="flex gap-1">
              <button onClick={() => handleCreate()} className="p-2 rounded-lg hover:bg-accent" title="New scenario">
                <Plus size={14} />
              </button>
              <button onClick={handleAiSuggest} disabled={suggestLoading} className="p-2 rounded-lg hover:bg-accent" title="Generate diverse scenarios">
                {suggestLoading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} className="text-amber-400" />}
              </button>
            </div>
          </div>

          <div className="flex gap-1">
            {[
              { id: 'workspace', label: 'Workspace', disabled: !currentProject },
              { id: 'project', label: 'Project', disabled: !currentProject },
              { id: 'standalone', label: 'Standalone', disabled: false },
            ].map((option) => (
              <button
                key={option.id}
                onClick={() => !option.disabled && setScopeFilter(option.id as ScopeFilter)}
                disabled={option.disabled}
                className={cn(
                  'flex-1 rounded-lg px-2.5 py-1.5 text-[11px] font-medium border transition-colors',
                  scopeFilter === option.id ? 'border-primary bg-primary/10 text-primary' : 'border-border/50 text-muted-foreground hover:bg-accent',
                  option.disabled && 'opacity-40 cursor-not-allowed'
                )}
              >
                {option.label}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-2">
            {SCENARIO_PRESETS.slice(0, 4).map((preset) => (
              <button
                key={preset.name}
                onClick={() => handleCreate(preset)}
                className="rounded-xl border border-border/40 bg-background/60 px-3 py-2 text-left hover:border-primary/30 hover:bg-primary/5 transition-colors"
              >
                <div className="text-xs font-semibold">{preset.name}</div>
                <div className="text-[11px] text-muted-foreground mt-1 line-clamp-2">{preset.description}</div>
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-auto p-3 space-y-2">
          {loading ? (
            <div className="text-sm text-muted-foreground text-center py-12">Loading scenarios...</div>
          ) : scenarios.length === 0 ? (
            <div className="rounded-2xl border border-dashed border-border/50 p-5 text-center text-sm text-muted-foreground">
              Create a scenario manually, use a preset, or generate a coverage set with AI.
            </div>
          ) : (
            scenarios.map((scenario) => (
              <div
                key={scenario.id}
                onClick={() => setSelectedId(scenario.id)}
                className={cn(
                  'w-full rounded-2xl border p-3 text-left transition-colors',
                  selectedId === scenario.id ? 'border-primary bg-primary/10' : 'border-border/40 bg-background/40 hover:bg-accent'
                )}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="font-medium text-sm truncate">{scenario.name}</div>
                    <div className="text-[11px] text-muted-foreground mt-1 line-clamp-2">
                      {scenario.operation_goal || scenario.description || 'No objective defined yet'}
                    </div>
                  </div>
                  <button
                    onClick={(event) => {
                      event.stopPropagation();
                      handleDelete(scenario.id);
                    }}
                    className="p-1 rounded hover:bg-destructive/10 text-muted-foreground hover:text-destructive"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
                <div className="flex flex-wrap items-center gap-1.5 mt-3 text-[10px]">
                  <Pill tone={scenario.scope === 'project' ? 'cyan' : 'slate'}>{scenario.scope}</Pill>
                  <Pill tone="violet">{getScenarioTypeLabel(scenario.scenario_type)}</Pill>
                  <Pill tone={scenario.status === 'completed' ? 'emerald' : 'amber'}>{scenario.status}</Pill>
                </div>
              </div>
            ))
          )}
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        {!selected ? (
          <EmptyScenarioState currentProjectName={currentProject?.name || ''} />
        ) : (
          <div className="max-w-6xl mx-auto px-6 py-6 space-y-5">
            <section className="rounded-3xl border border-border/40 bg-card/70 backdrop-blur-sm p-5">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <Pill tone={selected.scope === 'project' ? 'cyan' : 'slate'}>
                      {selected.scope === 'project' ? `Linked to ${selected.project_name || 'project'}` : 'Standalone'}
                    </Pill>
                    <Pill tone="violet">{getScenarioTypeLabel(selected.scenario_type)}</Pill>
                    {selected.project_id && !linkedProjectActive && (
                      <Pill tone="amber">Open linked project to edit tree-driven controls</Pill>
                    )}
                  </div>
                  <input
                    value={selected.name}
                    onChange={(event) => patchScenarioText({ name: event.target.value })}
                    className="w-full bg-transparent text-2xl font-bold outline-none border-b border-transparent hover:border-border focus:border-primary"
                  />
                  <textarea
                    value={selected.description}
                    onChange={(event) => patchScenarioText({ description: event.target.value })}
                    placeholder="Summarise the scenario change, hypothesis, or operational question."
                    className="mt-3 w-full min-h-[86px] rounded-2xl border border-border/50 bg-background/40 px-4 py-3 text-sm outline-none focus:border-primary"
                  />
                </div>

                <div className="w-full lg:w-[280px] rounded-2xl border border-border/40 bg-background/40 p-4 space-y-3">
                  <div>
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Attachment</div>
                    <div className="mt-2 flex gap-2">
                      <button
                        onClick={() => patchScenario({ scope: 'standalone', project_id: null, project_name: '' } as Partial<ScenarioData>)}
                        className={cn('flex-1 rounded-xl px-3 py-2 text-xs font-medium border', selected.scope === 'standalone' ? 'border-primary bg-primary/10 text-primary' : 'border-border/50 hover:bg-accent')}
                      >
                        Standalone
                      </button>
                      <button
                        onClick={() => currentProject && patchScenario({ scope: 'project', project_id: currentProject.id, project_name: currentProject.name } as Partial<ScenarioData>)}
                        disabled={!currentProject}
                        className={cn('flex-1 rounded-xl px-3 py-2 text-xs font-medium border', selected.scope === 'project' ? 'border-primary bg-primary/10 text-primary' : 'border-border/50 hover:bg-accent', !currentProject && 'opacity-40 cursor-not-allowed')}
                      >
                        Current Project
                      </button>
                    </div>
                  </div>

                  <div>
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">AI Planning Mode</div>
                    <select
                      value={planningProfile}
                      onChange={(event) => setPlanningProfile(event.target.value as PlanningProfile)}
                      className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                    >
                      {PLANNING_PROFILE_OPTIONS.map((option) => (
                        <option key={option.value} value={option.value}>{option.label}</option>
                      ))}
                    </select>
                    <p className="mt-2 text-xs text-muted-foreground leading-relaxed">{selectedPlanningProfile.description}</p>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <MetricCard label="Coverage" value={profile.coverage_score} />
                    <MetricCard label="Complexity" value={profile.complexity_score} />
                    <MetricCard label="Exposure" value={profile.exposure_score} />
                    <MetricCard label="Readiness" value={profile.readiness_score} />
                  </div>

                  <div className="flex gap-2">
                    <button onClick={handleSimulate} disabled={simLoading} className="flex-1 rounded-xl bg-cyan-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-cyan-700 disabled:opacity-50 flex items-center justify-center gap-2">
                      {simLoading ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
                      Run Planning Pass
                    </button>
                    <button onClick={handleAiAnalyze} disabled={aiLoading} className="flex-1 rounded-xl bg-violet-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-violet-700 disabled:opacity-50 flex items-center justify-center gap-2">
                      {aiLoading ? <Loader2 size={15} className="animate-spin" /> : <Brain size={15} />}
                      AI Brief
                    </button>
                  </div>
                </div>
              </div>
            </section>

            <div className="grid gap-5 xl:grid-cols-[1.35fr_1fr]">
              <div className="space-y-5">
                <Panel icon={<BriefcaseBusiness size={15} />} title="Mission Framing" description="Define what the operation is trying to achieve and the terrain it applies to.">
                  <div className="grid md:grid-cols-2 gap-4">
                    <ChoiceBlock
                      label="Scenario Type"
                      value={selected.scenario_type}
                      options={SCENARIO_TYPES.map((item) => item.id)}
                      display={(item) => getScenarioTypeLabel(item)}
                      onSelect={(value) => patchScenario({ scenario_type: value })}
                    />
                    <div>
                      <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Target Profile</label>
                      <input
                        value={selected.target_profile}
                        onChange={(event) => patchScenarioText({ target_profile: event.target.value })}
                        placeholder="Target organisation, business unit, or user cohort"
                        className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                      />
                    </div>
                    <div className="md:col-span-2">
                      <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Operation Goal</label>
                      <textarea
                        value={selected.operation_goal}
                        onChange={(event) => patchScenarioText({ operation_goal: event.target.value })}
                        placeholder="Primary mission goal or planning question"
                        className="mt-2 w-full min-h-[86px] rounded-2xl border border-border/50 bg-background/40 px-3 py-3 text-sm outline-none focus:border-primary"
                      />
                    </div>
                    <div className="md:col-span-2">
                      <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Target Environment</label>
                      <input
                        list="scenario-environment-presets"
                        value={selected.target_environment}
                        onChange={(event) => patchScenarioText({ target_environment: event.target.value })}
                        placeholder="Environment, estate, terrain, or business context"
                        className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                      />
                      <datalist id="scenario-environment-presets">
                        {ENVIRONMENT_PRESET_OPTIONS.map((preset) => (
                          <option key={preset.id} value={preset.name} />
                        ))}
                      </datalist>
                      <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                        {currentProject?.context_preset ? (
                          <button
                            type="button"
                            onClick={() => patchScenario({ target_environment: formatContextPreset(currentProject.context_preset) })}
                            className="rounded-full border border-border/50 bg-background/60 px-2.5 py-1 hover:border-primary/30 hover:bg-primary/5 hover:text-foreground"
                          >
                            Use workspace preset: {formatContextPreset(currentProject.context_preset)}
                          </button>
                        ) : null}
                        <span>Start with a known environment label, then refine it if the terrain is more specific.</span>
                      </div>
                    </div>
                  </div>
                </Panel>

                <Panel icon={<Radar size={15} />} title="Operational Design" description="Broaden coverage beyond one path by structuring vectors, phases, and conditions.">
                  <div className="grid lg:grid-cols-2 gap-4">
                    <TokenEditor
                      label="Entry Vectors"
                      helper="One per line. Cover multiple plausible access routes."
                      value={selected.entry_vectors}
                      onChange={(value) => patchScenarioText({ entry_vectors: value })}
                    />
                    <TokenEditor
                      label="Campaign Phases"
                      helper="Sequence the operation from access through outcome."
                      value={selected.campaign_phases}
                      onChange={(value) => patchScenarioText({ campaign_phases: value })}
                    />
                    <TokenEditor
                      label="Constraints"
                      helper="Operational limits, legal bounds, timelines, access limits, blast-radius controls."
                      value={selected.constraints}
                      onChange={(value) => patchScenarioText({ constraints: value })}
                    />
                    <TokenEditor
                      label="Dependencies"
                      helper="Preconditions, enablers, external approvals, third parties, infrastructure."
                      value={selected.dependencies}
                      onChange={(value) => patchScenarioText({ dependencies: value })}
                    />
                    <TokenEditor
                      label="Success Criteria"
                      helper="How you will decide the operation succeeded."
                      value={selected.success_criteria}
                      onChange={(value) => patchScenarioText({ success_criteria: value })}
                    />
                    <TokenEditor
                      label="Intelligence Gaps"
                      helper="Unanswered questions that materially affect feasibility or risk."
                      value={selected.intelligence_gaps}
                      onChange={(value) => patchScenarioText({ intelligence_gaps: value })}
                    />
                    <TokenEditor
                      label="Focus Tags"
                      helper="Optional tag-based focus for project-linked scenarios."
                      value={selected.focus_tags}
                      onChange={(value) => patchScenarioText({ focus_tags: value })}
                    />
                  </div>
                  <div className="grid md:grid-cols-2 gap-4 mt-4">
                    <TextAreaField
                      label="Assumptions"
                      value={selected.assumptions}
                      placeholder="Assumptions the plan depends on"
                      onChange={(value) => patchScenarioText({ assumptions: value })}
                    />
                    <TextAreaField
                      label="Planning Notes"
                      value={selected.planning_notes}
                      placeholder="Additional planning detail, decision points, or rationale"
                      onChange={(value) => patchScenarioText({ planning_notes: value })}
                    />
                  </div>
                </Panel>

                <Panel icon={<Globe size={15} />} title="Adversary Model" description="Use a richer attacker profile to shape the simulated operating conditions.">
                  <div className="grid lg:grid-cols-2 gap-4">
                    <ChoiceBlock label="Attacker Type" value={selected.attacker_type} options={ATTACKER_TYPES.map((item) => item.id)} display={(item) => ATTACKER_TYPES.find((option) => option.id === item)?.label || item} onSelect={(value) => patchScenario({ attacker_type: value })} />
                    <ChoiceBlock label="Skill Level" value={selected.attacker_skill} options={SKILL_LEVELS} onSelect={(value) => patchScenario({ attacker_skill: value })} />
                    <ChoiceBlock label="Resources" value={selected.attacker_resources} options={RESOURCE_LEVELS} onSelect={(value) => patchScenario({ attacker_resources: value })} />
                    <ChoiceBlock label="Execution Tempo" value={selected.execution_tempo} options={TEMPO_OPTIONS} display={formatEnumLabel} onSelect={(value) => patchScenario({ execution_tempo: value })} />
                    <ChoiceBlock label="Stealth Level" value={selected.stealth_level} options={STEALTH_OPTIONS} display={formatEnumLabel} onSelect={(value) => patchScenario({ stealth_level: value })} />
                    <ChoiceBlock label="Access Level" value={selected.access_level} options={ACCESS_OPTIONS} display={formatEnumLabel} onSelect={(value) => patchScenario({ access_level: value })} />
                    <div className="lg:col-span-2">
                      <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Motivation</label>
                      <input
                        value={selected.attacker_motivation}
                        onChange={(event) => patchScenarioText({ attacker_motivation: event.target.value })}
                        placeholder="Financial, espionage, coercion, validation, resilience exercise"
                        className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                      />
                    </div>
                  </div>
                </Panel>
              </div>

              <div className="space-y-5">
                <Panel icon={<Focus size={15} />} title="Workspace Focus" description="When linked to the active workspace, focus the scenario on nodes, controls, and detections that matter.">
                  {!selected.project_id ? (
                    <InlineNotice tone="amber" text="This scenario is standalone. Attach it to the current workspace to use tree-driven planning controls." />
                  ) : !linkedProjectActive ? (
                    <InlineNotice tone="amber" text="Open the linked workspace to edit node, control, and detection focus from the tree." />
                  ) : (
                    <div className="space-y-4">
                        <div>
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Focus Nodes</div>
                          {nodes.length === 0 ? (
                            <InlineNotice tone="amber" text="No attack tree nodes exist in this workspace yet." />
                          ) : (
                          <div className="max-h-52 overflow-auto space-y-2">
                            {nodes.map((node) => (
                              <button
                                key={node.id}
                                onClick={() => toggleListValue('focus_node_ids', node.id)}
                                className={cn(
                                  'w-full rounded-xl border px-3 py-2 text-left text-xs transition-colors',
                                  selected.focus_node_ids.includes(node.id) ? 'border-primary bg-primary/10' : 'border-border/40 hover:bg-accent'
                                )}
                              >
                                <div className="font-medium">{node.title}</div>
                                <div className="text-muted-foreground mt-1">{node.node_type} · risk {node.residual_risk ?? node.inherent_risk ?? 'n/a'}</div>
                              </button>
                            ))}
                          </div>
                        )}
                      </div>

                      <ToggleCollection
                        title="Controls to Stress"
                        helper="Turn specific controls off to model failure, absence, or degraded enforcement."
                        empty="No mitigations found in the current tree."
                        items={allMitigations.map((item) => ({ id: item.id, title: item.title, meta: `${item.nodeName} · ${Math.round(item.effectiveness * 100)}% effective` }))}
                        active={new Set(selected.disabled_controls)}
                        onToggle={(value) => toggleListValue('disabled_controls', value)}
                      />

                      <ToggleCollection
                        title="Detections to Degrade"
                        helper="Reduce defender visibility for selected detections."
                        empty="No detections found in the current tree."
                        items={allDetections.map((item) => ({ id: item.id, title: item.title, meta: `${item.nodeName} · ${Math.round(item.coverage * 100)}% coverage` }))}
                        active={new Set(selected.degraded_detections)}
                        onToggle={(value) => toggleListValue('degraded_detections', value)}
                      />
                    </div>
                  )}
                </Panel>

                <Panel icon={<Crosshair size={15} />} title="Planning Output" description="Use the latest planning pass, AI brief, and workspace-specific impacts to drive next decisions.">
                  <div className="grid grid-cols-2 gap-3">
                    {planningMode ? (
                      <>
                        <MetricCard label="Coverage" value={profile.coverage_score} />
                        <MetricCard label="Complexity" value={profile.complexity_score} />
                        <MetricCard label="Exposure" value={profile.exposure_score} />
                        <MetricCard label="Readiness" value={profile.readiness_score} />
                      </>
                    ) : (
                      <>
                        <MetricCard label="Baseline Risk" value={impact.original_risk} />
                        <MetricCard label="Scenario Risk" value={impact.simulated_risk} accent={impact.delta > 0 ? 'red' : 'emerald'} />
                        <MetricCard label="Risk Delta" value={impact.delta} accent={impact.delta > 0 ? 'red' : 'emerald'} />
                        <MetricCard label="Affected Nodes" value={impact.affected_nodes} />
                      </>
                    )}
                  </div>

                  {impact.note && <InlineNotice tone="cyan" text={impact.note} className="mt-4" />}

                  {impact.planning_findings?.length > 0 && (
                    <div className="mt-4 space-y-2">
                      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Planning Findings</div>
                      {impact.planning_findings.map((item: string, index: number) => (
                        <div key={index} className="flex gap-2 text-xs rounded-xl bg-background/40 px-3 py-2">
                          <BadgeAlert size={13} className="text-amber-400 shrink-0 mt-0.5" />
                          <span>{item}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="mt-4">
                    <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Ask AI a specific question</label>
                    <input
                      value={question}
                      onChange={(event) => setQuestion(event.target.value)}
                      placeholder="What would stress the defender most? Which path deserves first attention?"
                      className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                    />
                  </div>
                </Panel>
              </div>
            </div>

            {!planningMode && impact.node_details?.length > 0 && (
              <Panel icon={<Layers3 size={15} />} title="Most Affected Nodes" description="Where the scenario changed risk the most in the linked attack tree.">
                <div className="space-y-2">
                  {impact.node_details.map((item: any) => (
                    <div key={item.id} className="rounded-2xl border border-border/40 bg-background/40 px-4 py-3">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="font-medium text-sm">{item.title}</div>
                          <div className="text-xs text-muted-foreground mt-1">
                            {item.node_type} · {item.attack_surface || 'surface not set'} · {item.platform || 'platform not set'}
                          </div>
                        </div>
                        <div className={cn('text-sm font-semibold', item.delta > 0 ? 'text-red-400' : 'text-emerald-400')}>
                          {item.original_risk} to {item.simulated_risk} ({item.delta > 0 ? '+' : ''}{item.delta})
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </Panel>
            )}

            {(impact.top_exposed_controls?.length > 0 || impact.top_degraded_detections?.length > 0) && (
              <div className="grid gap-5 lg:grid-cols-2">
                <SimpleListPanel
                  icon={<Shield size={15} />}
                  title="Controls Under Stress"
                  items={impact.top_exposed_controls || []}
                  render={(item: any) => `${item.title} on ${item.node} (${item.count} affected path${item.count === 1 ? '' : 's'})`}
                />
                <SimpleListPanel
                  icon={<Radar size={15} />}
                  title="Visibility Gaps"
                  items={impact.top_degraded_detections || []}
                  render={(item: any) => `${item.title} on ${item.node} (${item.count} affected path${item.count === 1 ? '' : 's'})`}
                />
              </div>
            )}

            {(impact.executive_summary || selected.ai_narrative || selected.ai_recommendations?.length > 0) && (
              <div className="grid gap-5 lg:grid-cols-[1.2fr_0.8fr]">
                <Panel icon={<Brain size={15} />} title="AI Planning Brief" description="Narrative analysis, phase framing, and decision support.">
                  {impact.executive_summary && <p className="text-sm leading-7 whitespace-pre-wrap">{impact.executive_summary}</p>}
                  {selected.ai_narrative && <p className="text-sm leading-7 whitespace-pre-wrap mt-4">{selected.ai_narrative}</p>}
                  {impact.phase_plan?.length > 0 && (
                    <div className="mt-5 grid gap-3">
                      {impact.phase_plan.map((phase: any, index: number) => (
                        <div key={index} className="rounded-2xl border border-border/40 bg-background/40 p-4">
                          <div className="font-semibold text-sm">{phase.phase}</div>
                          <div className="text-xs text-muted-foreground mt-1">{phase.objective}</div>
                          <div className="mt-3 grid gap-3 md:grid-cols-3 text-xs">
                            <MiniList title="Actions" items={phase.actions || []} />
                            <MiniList title="Dependencies" items={phase.dependencies || []} />
                            <MiniList title="Detection" items={phase.detection_considerations || []} />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>

                <div className="space-y-5">
                  <SimpleListPanel icon={<AlertTriangle size={15} />} title="Key Findings" items={impact.key_findings || []} render={(item: string) => item} />
                  <SimpleListPanel icon={<Waypoints size={15} />} title="Enabled Paths" items={impact.attack_paths_enabled || []} render={(item: string) => item} />
                  <SimpleListPanel icon={<Brain size={15} />} title="Intelligence Priorities" items={impact.intelligence_priorities || []} render={(item: string) => item} />
                  <SimpleListPanel icon={<BadgeAlert size={15} />} title="Defender Pain Points" items={impact.defender_pain_points || []} render={(item: string) => item} />
                  {impact.answer && <InlineNotice tone="violet" text={impact.answer} />}
                </div>
              </div>
            )}

            {selected.ai_recommendations?.length > 0 && (
              <Panel icon={<Shield size={15} />} title="Recommendations" description="Prioritised actions generated from the current scenario state.">
                <div className="grid gap-3">
                  {selected.ai_recommendations.map((recommendation, index) => (
                    <div key={`${recommendation.title}-${index}`} className="rounded-2xl border border-border/40 bg-background/40 p-4">
                      <div className="flex items-center gap-2 text-sm font-semibold">
                        <Pill tone={priorityTone(recommendation.priority)}>{recommendation.priority}</Pill>
                        {recommendation.title}
                      </div>
                      <p className="text-sm text-muted-foreground mt-2 leading-6">{recommendation.description}</p>
                    </div>
                  ))}
                </div>
              </Panel>
            )}
          </div>
        )}
      </main>
    </div>
  );
}

function EmptyScenarioState({ currentProjectName }: { currentProjectName: string }) {
  return (
    <div className="h-full flex items-center justify-center px-6">
      <div className="max-w-3xl w-full rounded-[32px] border border-border/40 bg-card/70 backdrop-blur-sm p-8">
        <div className="flex items-center gap-3 text-cyan-400 mb-3">
          <FlaskConical size={20} />
          <span className="text-sm font-semibold uppercase tracking-wider">Scenario Planning</span>
        </div>
        <h1 className="text-3xl font-bold max-w-2xl">Broaden coverage first, then go deep on the paths and conditions that matter.</h1>
        <p className="text-sm text-muted-foreground mt-3 max-w-2xl leading-7">
          Build standalone scenario libraries for operations planning, or attach scenarios to {currentProjectName || 'a project'} to stress specific tree paths, controls, and detections.
        </p>
        <div className="grid gap-4 md:grid-cols-3 mt-6">
          <FeatureCard icon={<Globe size={16} />} title="Standalone" text="Use scenarios as a planning dossier even without a project tree." />
          <FeatureCard icon={<Shield size={16} />} title="Project-Linked" text="Attach scenarios to a project and stress controls, detections, and focused nodes." />
          <FeatureCard icon={<Brain size={16} />} title="AI Briefing" text="Generate broader scenario coverage and deep planning briefs from the current state." />
        </div>
      </div>
    </div>
  );
}

function Panel({ icon, title, description, children }: { icon: React.ReactNode; title: string; description: string; children: React.ReactNode }) {
  return (
    <section className="rounded-3xl border border-border/40 bg-card/70 backdrop-blur-sm p-5">
      <div className="flex items-start gap-3 mb-4">
        <div className="w-9 h-9 rounded-2xl bg-primary/10 text-primary flex items-center justify-center shrink-0">{icon}</div>
        <div>
          <h2 className="text-base font-semibold">{title}</h2>
          <p className="text-sm text-muted-foreground mt-1">{description}</p>
        </div>
      </div>
      {children}
    </section>
  );
}

function ChoiceBlock({
  label,
  value,
  options,
  onSelect,
  display = (item) => item,
}: {
  label: string;
  value: string;
  options: string[];
  onSelect: (value: string) => void;
  display?: (value: string) => string;
}) {
  return (
    <div>
      <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</label>
      <div className="mt-2 flex flex-wrap gap-2">
        {options.map((option) => (
          <button
            key={option}
            onClick={() => onSelect(option)}
            className={cn(
              'rounded-xl border px-3 py-2 text-xs font-medium transition-colors',
              value === option ? 'border-primary bg-primary/10 text-primary' : 'border-border/50 hover:bg-accent'
            )}
          >
            {display(option)}
          </button>
        ))}
      </div>
    </div>
  );
}

function TextAreaField({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (value: string) => void; placeholder: string }) {
  return (
    <div>
      <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</label>
      <textarea
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        className="mt-2 w-full min-h-[116px] rounded-2xl border border-border/50 bg-background/40 px-3 py-3 text-sm outline-none focus:border-primary"
      />
    </div>
  );
}

function TokenEditor({
  label,
  helper,
  value,
  onChange,
}: {
  label: string;
  helper: string;
  value: string[];
  onChange: (value: string[]) => void;
}) {
  return (
    <div>
      <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</label>
      <p className="text-[11px] text-muted-foreground mt-1">{helper}</p>
      <textarea
        value={value.join('\n')}
        onChange={(event) => onChange(parseList(event.target.value))}
        className="mt-2 w-full min-h-[110px] rounded-2xl border border-border/50 bg-background/40 px-3 py-3 text-sm outline-none focus:border-primary"
        placeholder="One item per line"
      />
      {value.length > 0 && (
        <div className="flex flex-wrap gap-1.5 mt-3">
          {value.map((item) => (
            <span key={item} className="rounded-full bg-primary/10 px-2.5 py-1 text-[11px] text-primary">
              {item}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

function ToggleCollection({
  title,
  helper,
  empty,
  items,
  active,
  onToggle,
}: {
  title: string;
  helper: string;
  empty: string;
  items: Array<{ id: string; title: string; meta: string }>;
  active: Set<string>;
  onToggle: (value: string) => void;
}) {
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{title}</div>
      <p className="text-[11px] text-muted-foreground mt-1">{helper}</p>
      {items.length === 0 ? (
        <InlineNotice tone="amber" text={empty} className="mt-3" />
      ) : (
        <div className="mt-3 max-h-60 overflow-auto space-y-2">
          {items.map((item) => (
            <button
              key={item.id}
              onClick={() => onToggle(item.id)}
              className={cn(
                'w-full rounded-2xl border px-3 py-2 text-left transition-colors',
                active.has(item.id) ? 'border-primary bg-primary/10' : 'border-border/40 hover:bg-accent'
              )}
            >
              <div className="text-xs font-medium">{item.title}</div>
              <div className="text-[11px] text-muted-foreground mt-1">{item.meta}</div>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function SimpleListPanel({
  icon,
  title,
  items,
  render,
}: {
  icon: React.ReactNode;
  title: string;
  items: any[];
  render: (item: any) => string;
}) {
  if (!items || items.length === 0) return null;
  return (
    <Panel icon={icon} title={title} description="">
      <div className="space-y-2">
        {items.map((item, index) => (
          <div key={index} className="rounded-2xl border border-border/40 bg-background/40 px-4 py-3 text-sm">
            {render(item)}
          </div>
        ))}
      </div>
    </Panel>
  );
}

function MiniList({ title, items }: { title: string; items: string[] }) {
  return (
    <div>
      <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{title}</div>
      <div className="mt-2 space-y-1.5">
        {items.length === 0 ? (
          <div className="text-[11px] text-muted-foreground">None supplied</div>
        ) : (
          items.map((item) => (
            <div key={item} className="rounded-xl bg-background/60 px-2.5 py-2">
              {item}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function InlineNotice({ tone, text, className }: { tone: 'amber' | 'cyan' | 'violet'; text: string; className?: string }) {
  return (
    <div
      className={cn(
        'rounded-2xl border px-4 py-3 text-sm',
        tone === 'amber' && 'border-amber-500/30 bg-amber-500/10 text-amber-100',
        tone === 'cyan' && 'border-cyan-500/30 bg-cyan-500/10 text-cyan-100',
        tone === 'violet' && 'border-violet-500/30 bg-violet-500/10 text-violet-100',
        className
      )}
    >
      {text}
    </div>
  );
}

function MetricCard({ label, value, accent }: { label: string; value: number | string | null | undefined; accent?: 'red' | 'emerald' }) {
  return (
    <div className="rounded-2xl border border-border/40 bg-background/40 px-3 py-3">
      <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{label}</div>
      <div className={cn('mt-2 text-2xl font-bold', accent === 'red' && 'text-red-400', accent === 'emerald' && 'text-emerald-400')}>
        {formatMetric(value)}
      </div>
    </div>
  );
}

function Pill({ children, tone }: { children: React.ReactNode; tone: 'cyan' | 'violet' | 'emerald' | 'amber' | 'slate' }) {
  return (
    <span
      className={cn(
        'rounded-full px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider',
        tone === 'cyan' && 'bg-cyan-500/10 text-cyan-300',
        tone === 'violet' && 'bg-violet-500/10 text-violet-300',
        tone === 'emerald' && 'bg-emerald-500/10 text-emerald-300',
        tone === 'amber' && 'bg-amber-500/10 text-amber-300',
        tone === 'slate' && 'bg-slate-500/10 text-slate-300'
      )}
    >
      {children}
    </span>
  );
}

function FeatureCard({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return (
    <div className="rounded-2xl border border-border/40 bg-background/40 p-4">
      <div className="w-9 h-9 rounded-2xl bg-primary/10 text-primary flex items-center justify-center">{icon}</div>
      <div className="font-semibold text-sm mt-3">{title}</div>
      <div className="text-sm text-muted-foreground mt-1 leading-6">{text}</div>
    </div>
  );
}

function getScenarioTypeLabel(value: string) {
  return SCENARIO_TYPES.find((item) => item.id === value)?.label || formatEnumLabel(value);
}

function formatEnumLabel(value: string) {
  return value
    .split('_')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function parseList(value: string) {
  return Array.from(new Set(value.split(/\n|,/).map((item) => item.trim()).filter(Boolean)));
}

function formatMetric(value: number | string | null | undefined) {
  if (value == null || value === '') return 'NA';
  if (typeof value === 'number') return Number.isInteger(value) ? String(value) : value.toFixed(1);
  return value;
}

function priorityTone(priority: string): 'emerald' | 'amber' | 'cyan' | 'violet' | 'slate' {
  const normalised = priority.toLowerCase();
  if (normalised === 'critical' || normalised === 'high') return 'amber';
  if (normalised === 'medium') return 'cyan';
  if (normalised === 'low') return 'slate';
  return 'violet';
}
