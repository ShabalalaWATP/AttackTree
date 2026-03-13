import { useEffect, useMemo, useRef, useState } from 'react';
import type { PlanningProfile } from '@/types';
import type { ReferenceLink } from '@/types';
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
import { ReferencePicker } from '@/components/ReferencePicker';
import { getPlanningProfileOption, PLANNING_PROFILE_OPTIONS } from '@/utils/planningProfiles';
import { formatContextPreset, getContextPresetOption, getEnvironmentContextPresets } from '@/utils/contextPresets';
import { mergeReferenceLinks, normalizeReferenceLinks, removeReferenceLink } from '@/utils/referenceLinks';
import { useAdvisorPageContext } from '@/hooks/useAdvisorPageContext';

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
  reference_mappings: ReferenceLink[];
  ai_narrative: string;
  ai_recommendations: Array<{ priority: string; title: string; description: string }>;
  impact_summary: Record<string, any>;
  created_at: string;
  updated_at: string;
}

type ScenarioScope = ScenarioData['scope'];
type ScopeFilter = 'all' | 'project' | 'standalone';
type ScenarioWizardMode = 'draft' | 'output';

interface ScenarioWizardDraft {
  scope: ScenarioScope;
  name: string;
  description: string;
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
  success_criteria: string[];
  planning_notes: string;
}

const SCENARIO_FILTER_OPTIONS: Array<{ id: ScopeFilter; label: string }> = [
  { id: 'all', label: 'All' },
  { id: 'project', label: 'This Project' },
  { id: 'standalone', label: 'Library' },
];

const SCENARIO_WIZARD_STEPS = [
  'Where It Lives',
  'Mission',
  'Attacker',
  'Focus',
];

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
    reference_mappings: normalizeReferenceLinks(value?.reference_mappings),
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
  const { currentProject, nodes, setNodes, pendingViewSelection, clearPendingViewSelection } = useStore();
  const [scenarios, setScenarios] = useState<ScenarioData[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [scopeFilter, setScopeFilter] = useState<ScopeFilter>(currentProject ? 'all' : 'standalone');
  const [loading, setLoading] = useState(false);
  const [outputLoading, setOutputLoading] = useState(false);
  const [suggestLoading, setSuggestLoading] = useState(false);
  const [question, setQuestion] = useState('');
  const [planningProfile, setPlanningProfile] = useState<PlanningProfile>('planning_first');
  const patchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const queuedPatchIdRef = useRef<string | null>(null);
  const queuedPatchRef = useRef<Partial<ScenarioData>>({});
  const [wizardOpen, setWizardOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState(0);
  const [wizardMode, setWizardMode] = useState<ScenarioWizardMode | null>(null);
  const [wizardDraft, setWizardDraft] = useState<ScenarioWizardDraft>(() => createWizardDraft());
  const [showSetupDetails, setShowSetupDetails] = useState(false);

  function createWizardDraft(preset?: Partial<ScenarioData>): ScenarioWizardDraft {
    const scope: ScenarioScope = !currentProject || scopeFilter === 'standalone' ? 'standalone' : 'project';
    const projectPreset = currentProject?.context_preset ? formatContextPreset(currentProject.context_preset) : '';
    return {
      scope,
      name: preset?.name || `${scope === 'project' ? 'Project' : 'Library'} Scenario ${scenarios.length + 1}`,
      description: preset?.description || '',
      scenario_type: preset?.scenario_type || 'campaign',
      operation_goal: preset?.operation_goal || currentProject?.root_objective || '',
      target_profile: preset?.target_profile || currentProject?.name || '',
      target_environment: preset?.target_environment || projectPreset,
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
      success_criteria: preset?.success_criteria || [],
      planning_notes: preset?.planning_notes || '',
    };
  }

  function buildScenarioPayload(draft: ScenarioWizardDraft) {
    const scope: ScenarioScope = draft.scope === 'project' && currentProject ? 'project' : 'standalone';
    return {
      scope,
      project_id: scope === 'project' ? currentProject?.id : null,
      name: draft.name.trim() || `${scope === 'project' ? 'Project' : 'Library'} Scenario ${scenarios.length + 1}`,
      description: draft.description.trim(),
      scenario_type: draft.scenario_type,
      operation_goal: draft.operation_goal.trim(),
      target_profile: draft.target_profile.trim(),
      target_environment: draft.target_environment.trim(),
      execution_tempo: draft.execution_tempo,
      stealth_level: draft.stealth_level,
      access_level: draft.access_level,
      attacker_type: draft.attacker_type,
      attacker_skill: draft.attacker_skill,
      attacker_resources: draft.attacker_resources,
      attacker_motivation: draft.attacker_motivation.trim(),
      entry_vectors: draft.entry_vectors,
      campaign_phases: draft.campaign_phases,
      constraints: draft.constraints,
      dependencies: [],
      intelligence_gaps: [],
      success_criteria: draft.success_criteria,
      assumptions: '',
      planning_notes: draft.planning_notes.trim(),
    };
  }

  function buildSimulationPayload(scenario: ScenarioData) {
    return {
      disabled_controls: scenario.disabled_controls || [],
      degraded_detections: scenario.degraded_detections || [],
      modified_scores: scenario.modified_scores || {},
      attacker_type: scenario.attacker_type,
      attacker_skill: scenario.attacker_skill,
      attacker_resources: scenario.attacker_resources,
      execution_tempo: scenario.execution_tempo,
      stealth_level: scenario.stealth_level,
      access_level: scenario.access_level,
      focus_node_ids: scenario.focus_node_ids || [],
      focus_tags: scenario.focus_tags || [],
    };
  }

  function openScenarioWizard(preset?: Partial<ScenarioData>) {
    setWizardDraft(createWizardDraft(preset));
    setWizardStep(0);
    setWizardMode(null);
    setWizardOpen(true);
  }

  function closeScenarioWizard() {
    if (wizardMode) return;
    setWizardOpen(false);
    setWizardStep(0);
  }

  const selected = useMemo(
    () => scenarios.find((scenario) => scenario.id === selectedId) ?? null,
    [scenarios, selectedId]
  );
  const selectedPlanningProfile = useMemo(
    () => getPlanningProfileOption(planningProfile),
    [planningProfile],
  );
  const advisorContext = useMemo(() => ({
    view: 'scenarios' as const,
    title: selected ? `Scenario: ${selected.name}` : 'Scenario Planning',
    summary: selected
      ? (selected.operation_goal || selected.description || 'Reviewing the selected scenario plan, attacker profile, and generated analysis.')
      : 'Scenario library and planning workspace for operational what-if analysis.',
    packets: [
      selected ? `Scenario type: ${selected.scenario_type}` : '',
      selected ? `Attacker type: ${selected.attacker_type}` : '',
      selected ? `Target environment: ${selected.target_environment || 'Unspecified'}` : '',
      selected ? `Focus nodes: ${selected.focus_node_ids.length}` : '',
      selected ? `Disabled controls: ${selected.disabled_controls.length}` : '',
      selected ? `Degraded detections: ${selected.degraded_detections.length}` : '',
      selected?.ai_narrative ? 'Decision brief available' : '',
      selected?.impact_summary?.executive_summary ? 'Scenario analysis available' : '',
      `Planning profile: ${selectedPlanningProfile.label}`,
    ],
  }), [selected, selectedPlanningProfile.label]);
  useAdvisorPageContext(advisorContext);

  useEffect(() => {
    if (!currentProject && scopeFilter !== 'standalone') {
      setScopeFilter('standalone');
    }
  }, [currentProject, scopeFilter]);

  useEffect(() => {
    if (!currentProject) {
      setWizardDraft((current) => (current.scope === 'project' ? { ...current, scope: 'standalone' } : current));
    }
  }, [currentProject]);

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

  useEffect(() => {
    setShowSetupDetails(false);
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
        scopeFilter === 'all'
          ? await api.listScenarioWorkspace(currentProject?.id)
          : await api.listScenarios(currentProject?.id, scopeFilter);
      const data = Array.isArray(rawData) ? rawData.map((item) => normalizeScenario(item)) : [];
      const requestedScenarioId = pendingViewSelection?.view === 'scenarios' ? pendingViewSelection.artifactId : null;
      setScenarios(data);
      setSelectedId((current) => {
        if (requestedScenarioId) {
          return data.find((item: ScenarioData) => item.id === requestedScenarioId)?.id || data[0]?.id || null;
        }
        return current && data.some((item: ScenarioData) => item.id === current) ? current : data[0]?.id ?? null;
      });
      if (requestedScenarioId) {
        clearPendingViewSelection();
      }
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

  function addScenarioReference(item: {
    framework: string;
    ref_id: string;
    ref_name: string;
    score: number;
    reasons: string[];
  }) {
    if (!selected) return;
    void patchScenario({
      reference_mappings: mergeReferenceLinks(selected.reference_mappings, [item]),
    });
  }

  function removeScenarioReference(framework: string, refId: string) {
    if (!selected) return;
    void patchScenario({
      reference_mappings: removeReferenceLink(selected.reference_mappings, framework, refId),
    });
  }

  async function createScenario(payload: ReturnType<typeof buildScenarioPayload>) {
    const created = await api.createScenario(payload);
    const normalized = normalizeScenario(created);
    setScenarios((current) => [normalized, ...current]);
    setSelectedId(normalized.id);
    if (currentProject && scopeFilter !== 'all' && scopeFilter !== normalized.scope) {
      setScopeFilter('all');
    }
    return normalized;
  }

  async function handleWizardSubmit(mode: ScenarioWizardMode) {
    setWizardMode(mode);
    try {
      const created = await createScenario(buildScenarioPayload(wizardDraft));
      if (mode === 'output') {
        await generateScenarioOutput(created, '');
        toast.success('Scenario created with analysis and decision brief');
      } else {
        toast.success('Scenario created');
      }
      setWizardOpen(false);
      setWizardStep(0);
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setWizardMode(null);
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

  async function generateScenarioOutput(scenario: ScenarioData, briefQuestion: string) {
    const simulated = await api.simulateScenario(scenario.id, buildSimulationPayload(scenario));
    const normalizedSimulation = normalizeScenario(simulated);
    syncScenario(normalizedSimulation);
    const brief = await api.aiAnalyzeScenario(normalizedSimulation.id, { question: briefQuestion, planning_profile: planningProfile });
    const normalizedBrief = normalizeScenario(brief);
    syncScenario(normalizedBrief);
    return normalizedBrief;
  }

  async function handleGenerateOutput() {
    if (!selected) return;
    setOutputLoading(true);
    try {
      await flushScenarioPatch(selected.id);
      await generateScenarioOutput(selected, question);
      toast.success('Scenario analysis and brief ready');
    } catch (error: any) {
      toast.error(error.message);
    } finally {
      setOutputLoading(false);
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
                Scenario Library
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                {currentProject
                  ? `Keep multiple scenarios for ${currentProject.name} or save reusable ones to your library`
                  : 'Keep reusable scenarios in your standalone planning library'}
              </p>
              <p className="text-[11px] text-muted-foreground mt-2">
                {scenarios.length} scenario{scenarios.length === 1 ? '' : 's'} in this view
              </p>
            </div>
            <div className="flex gap-1">
              <button onClick={() => openScenarioWizard()} className="p-2 rounded-lg hover:bg-accent" title="Add scenario">
                <Plus size={14} />
              </button>
              <button onClick={handleAiSuggest} disabled={suggestLoading} className="p-2 rounded-lg hover:bg-accent" title="Generate diverse scenarios">
                {suggestLoading ? <Loader2 size={14} className="animate-spin" /> : <Sparkles size={14} className="text-amber-400" />}
              </button>
            </div>
          </div>

          <div className="flex gap-1">
            {SCENARIO_FILTER_OPTIONS.map((option) => (
              <button
                key={option.id}
                onClick={() => !(option.id !== 'standalone' && !currentProject) && setScopeFilter(option.id)}
                disabled={option.id !== 'standalone' && !currentProject}
                className={cn(
                  'flex-1 rounded-lg px-2.5 py-1.5 text-[11px] font-medium border transition-colors',
                  scopeFilter === option.id ? 'border-primary bg-primary/10 text-primary' : 'border-border/50 text-muted-foreground hover:bg-accent',
                  option.id !== 'standalone' && !currentProject && 'opacity-40 cursor-not-allowed'
                )}
              >
                {option.label}
              </button>
            ))}
          </div>

          <p className="text-[11px] leading-5 text-muted-foreground">
            Scenarios only live in two places: this project or your standalone library. <span className="text-foreground">All</span> simply shows both together.
          </p>

          <div className="grid grid-cols-2 gap-2">
            {SCENARIO_PRESETS.slice(0, 4).map((preset) => (
              <button
                key={preset.name}
                onClick={() => openScenarioWizard(preset)}
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
              Start a guided scenario, use a template, or generate a coverage set with AI.
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
                  <Pill tone={scenario.scope === 'project' ? 'cyan' : 'slate'}>{scenario.scope === 'project' ? 'Project' : 'Library'}</Pill>
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
          <EmptyScenarioState currentProjectName={currentProject?.name || ''} onCreate={() => openScenarioWizard()} />
        ) : (
          <div className="max-w-6xl mx-auto px-6 py-6 space-y-5">
            <section className="rounded-3xl border border-border/40 bg-card/70 backdrop-blur-sm p-5">
              <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-3">
                    <Pill tone={selected.scope === 'project' ? 'cyan' : 'slate'}>
                      {selected.scope === 'project' ? `Linked to ${selected.project_name || 'project'}` : 'Library'}
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
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Where It Lives</div>
                    <div className="mt-2 flex gap-2">
                      <button
                        onClick={() => patchScenario({ scope: 'standalone', project_id: null, project_name: '' } as Partial<ScenarioData>)}
                        className={cn('flex-1 rounded-xl px-3 py-2 text-xs font-medium border', selected.scope === 'standalone' ? 'border-primary bg-primary/10 text-primary' : 'border-border/50 hover:bg-accent')}
                      >
                        Library
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
                    <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Analysis Style</div>
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

                  <button onClick={handleGenerateOutput} disabled={outputLoading} className="w-full rounded-xl bg-cyan-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-cyan-700 disabled:opacity-50 flex items-center justify-center gap-2">
                    {outputLoading ? <Loader2 size={15} className="animate-spin" /> : <Brain size={15} />}
                    Generate Analysis + Brief
                  </button>

                  <button
                    onClick={() => setShowSetupDetails((current) => !current)}
                    className="w-full rounded-xl border border-border/50 px-4 py-2.5 text-sm font-medium text-muted-foreground hover:bg-accent hover:text-foreground"
                  >
                    {showSetupDetails ? 'Hide Setup Details' : 'Review Or Edit Setup'}
                  </button>
                </div>
              </div>
            </section>

            <section className="rounded-3xl border border-border/40 bg-card/60 p-4 backdrop-blur-sm">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
                <div>
                  <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Scenario Setup</div>
                  <p className="mt-2 text-sm text-muted-foreground">
                    Mission framing, attacker conditions, project focus, and supporting references are hidden by default so the analysis stays in focus.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                  <Pill tone={selected.scope === 'project' ? 'cyan' : 'slate'}>{selected.scope === 'project' ? 'Project linked' : 'Library scenario'}</Pill>
                  <Pill tone="violet">{selected.target_environment || 'Environment pending'}</Pill>
                  <Pill tone="amber">{selected.entry_vectors.length} vector{selected.entry_vectors.length === 1 ? '' : 's'}</Pill>
                </div>
              </div>
            </section>

            {showSetupDetails && (
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
                            Use project preset: {formatContextPreset(currentProject.context_preset)}
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
                  <Panel icon={<Focus size={15} />} title="Project Focus" description="When linked to the current project, focus the scenario on nodes, controls, and detections that matter.">
                  {!selected.project_id ? (
                    <InlineNotice tone="amber" text="This scenario is in the library. Attach it to the current project to use tree-driven planning controls." />
                  ) : !linkedProjectActive ? (
                    <InlineNotice tone="amber" text="Open the linked project to edit node, control, and detection focus from the tree." />
                  ) : (
                    <div className="space-y-4">
                        <div>
                          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground mb-2">Focus Nodes</div>
                          {nodes.length === 0 ? (
                            <InlineNotice tone="amber" text="No attack tree nodes exist in this project yet." />
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

                  <Panel icon={<BriefcaseBusiness size={15} />} title="Supporting References" description="Anchor the scenario to the most relevant frameworks, attack patterns, and environment concepts.">
                  <ReferencePicker
                    artifactType="scenario"
                    contextPreset={currentProject?.context_preset || ''}
                    objective={selected.operation_goal || currentProject?.root_objective || selected.name}
                    scope={selected.description || currentProject?.description || ''}
                    targetKind="scenario"
                    targetSummary={[
                      selected.name,
                      selected.description,
                      selected.target_environment,
                      selected.entry_vectors.join(' '),
                      selected.campaign_phases.join(' '),
                    ].filter(Boolean).join(' ')}
                    placeholder="Search supporting references for this scenario"
                    onAdd={addScenarioReference}
                  />
                  <div className="mt-3 space-y-2">
                    {selected.reference_mappings.length === 0 ? (
                      <InlineNotice tone="cyan" text="No supporting references attached yet." />
                    ) : (
                      selected.reference_mappings.map((reference) => (
                        <div key={`${reference.framework}:${reference.ref_id}`} className="rounded-xl border border-border/40 bg-background/40 px-3 py-2">
                          <div className="flex items-start gap-3">
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2 text-xs">
                                <span className="font-semibold uppercase tracking-wide text-muted-foreground">{reference.framework}</span>
                                <span className="font-mono text-cyan-400">{reference.ref_id}</span>
                              </div>
                              <div className="mt-1 text-sm font-medium">{reference.ref_name}</div>
                              {(reference.source || reference.confidence != null || reference.rationale) && (
                                <div className="mt-1 text-[11px] text-muted-foreground leading-5">
                                  {reference.source ? `Source: ${reference.source}` : ''}
                                  {reference.confidence != null ? `${reference.source ? ' · ' : ''}Confidence: ${Math.round(reference.confidence * 100)}%` : ''}
                                  {reference.rationale ? ` · ${reference.rationale}` : ''}
                                </div>
                              )}
                            </div>
                            <button
                              type="button"
                              onClick={() => removeScenarioReference(reference.framework, reference.ref_id)}
                              className="rounded-lg border border-transparent p-1.5 text-muted-foreground transition-colors hover:border-destructive/20 hover:bg-destructive/5 hover:text-destructive"
                              title="Remove reference"
                            >
                              <Trash2 size={12} />
                            </button>
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                  </Panel>
                </div>
              </div>
            )}

            <Panel icon={<Crosshair size={15} />} title="Scenario Analysis" description="Use the latest analysis, briefing output, and project-specific impacts to drive next decisions.">
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
                  <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Analysis Findings</div>
                  {impact.planning_findings.map((item: string, index: number) => (
                    <div key={index} className="flex gap-2 text-xs rounded-xl bg-background/40 px-3 py-2">
                      <BadgeAlert size={13} className="text-amber-400 shrink-0 mt-0.5" />
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              )}

              <div className="mt-4">
                <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Guide the brief</label>
                <input
                  value={question}
                  onChange={(event) => setQuestion(event.target.value)}
                  placeholder="Optional: What would stress the defender most? Which path deserves first attention?"
                  className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                />
              </div>
            </Panel>

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
                <Panel icon={<Brain size={15} />} title="Decision Brief" description="Narrative analysis, phase framing, and decision support.">
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

      <ScenarioWizardModal
        open={wizardOpen}
        draft={wizardDraft}
        step={wizardStep}
        submitting={wizardMode}
        currentProjectName={currentProject?.name || ''}
        currentProjectPreset={currentProject?.context_preset ? formatContextPreset(currentProject.context_preset) : ''}
        hasProject={!!currentProject}
        onClose={closeScenarioWizard}
        onDraftChange={(updates) => setWizardDraft((current) => ({ ...current, ...updates }))}
        onStepChange={setWizardStep}
        onSubmit={handleWizardSubmit}
      />
    </div>
  );
}

function EmptyScenarioState({ currentProjectName, onCreate }: { currentProjectName: string; onCreate: () => void }) {
  return (
    <div className="h-full flex items-center justify-center px-6">
      <div className="max-w-3xl w-full rounded-[32px] border border-border/40 bg-card/70 backdrop-blur-sm p-8">
        <div className="flex items-center gap-3 text-cyan-400 mb-3">
          <FlaskConical size={20} />
          <span className="text-sm font-semibold uppercase tracking-wider">Scenario Planning</span>
        </div>
        <h1 className="text-3xl font-bold max-w-2xl">Broaden coverage first, then go deep on the paths and conditions that matter.</h1>
        <p className="text-sm text-muted-foreground mt-3 max-w-2xl leading-7">
          Keep multiple scenarios in a reusable library, or attach them to {currentProjectName || 'a project'} to stress specific tree paths, controls, and detections.
        </p>
        <div className="mt-6">
          <button onClick={onCreate} className="rounded-xl bg-cyan-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-cyan-700">
            Start Guided Scenario
          </button>
        </div>
        <div className="grid gap-4 md:grid-cols-3 mt-6">
          <FeatureCard icon={<Globe size={16} />} title="Library" text="Keep reusable scenarios even when they are not tied to one project." />
          <FeatureCard icon={<Shield size={16} />} title="Project Linked" text="Attach scenarios to a project and stress controls, detections, and focused nodes." />
              <FeatureCard icon={<Brain size={16} />} title="Analysis + Brief" text="Generate the scenario assessment first, then the decision brief from the same current state." />
        </div>
      </div>
    </div>
  );
}

function ScenarioWizardModal({
  open,
  draft,
  step,
  submitting,
  currentProjectName,
  currentProjectPreset,
  hasProject,
  onClose,
  onDraftChange,
  onStepChange,
  onSubmit,
}: {
  open: boolean;
  draft: ScenarioWizardDraft;
  step: number;
  submitting: ScenarioWizardMode | null;
  currentProjectName: string;
  currentProjectPreset: string;
  hasProject: boolean;
  onClose: () => void;
  onDraftChange: (updates: Partial<ScenarioWizardDraft>) => void;
  onStepChange: (step: number) => void;
  onSubmit: (mode: ScenarioWizardMode) => void;
}) {
  if (!open) return null;

  const busy = submitting !== null;
  const lastStep = SCENARIO_WIZARD_STEPS.length - 1;
  const canGoBack = step > 0 && !busy;
  const canGoForward = step < lastStep && !busy;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-slate-950/70 p-4 backdrop-blur-sm sm:items-center">
      <div className="flex w-full max-w-5xl max-h-[calc(100vh-2rem)] flex-col overflow-hidden rounded-[32px] border border-border/50 bg-card/95 shadow-2xl">
        <div className="shrink-0 border-b border-border/40 px-6 py-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
            <div className="min-w-0">
              <div className="text-[11px] font-semibold uppercase tracking-[0.25em] text-cyan-400">Scenario Setup</div>
              <h2 className="mt-2 text-2xl font-bold">Capture the basics in a simple order, then review the result.</h2>
              <p className="mt-2 max-w-3xl text-sm leading-7 text-muted-foreground">
                You can keep multiple scenarios. Each one lives either in the current project or in your standalone library.
              </p>
            </div>
            <button
              onClick={onClose}
              disabled={busy}
              className="rounded-xl border border-border/50 px-3 py-2 text-sm font-medium text-muted-foreground hover:bg-accent disabled:opacity-50"
            >
              Close
            </button>
          </div>

          <div className="mt-5 grid gap-2 md:grid-cols-4">
            {SCENARIO_WIZARD_STEPS.map((label, index) => (
              <button
                key={label}
                onClick={() => !busy && onStepChange(index)}
                disabled={busy}
                className={cn(
                  'rounded-2xl border px-3 py-3 text-left transition-colors',
                  step === index ? 'border-primary bg-primary/10' : 'border-border/40 bg-background/40 hover:bg-accent',
                  busy && 'cursor-not-allowed opacity-70'
                )}
              >
                <div className="text-[10px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">Step {index + 1}</div>
                <div className="mt-1 text-sm font-semibold">{label}</div>
              </button>
            ))}
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-auto px-6 py-6 pb-8">
          {busy ? (
            <div className="flex min-h-[360px] items-center justify-center">
              <div className="max-w-md text-center">
                <Loader2 size={28} className="mx-auto animate-spin text-cyan-400" />
                <div className="mt-4 text-xl font-semibold">
                  {submitting === 'output'
                    ? 'Creating the scenario, generating analysis, and writing the brief'
                    : 'Creating the scenario'}
                </div>
                <p className="mt-3 text-sm leading-7 text-muted-foreground">
                  The setup window will close as soon as the scenario is ready and the report view can take over.
                </p>
              </div>
            </div>
          ) : step === 0 ? (
            <div className="space-y-5">
              <div className="max-w-3xl">
                <h3 className="text-xl font-semibold">Choose where this scenario should live</h3>
                <p className="mt-2 text-sm leading-7 text-muted-foreground">
                  There are only two places a scenario can live. Save it to this project if you want to use the project attack tree, or save it to the library if you want to reuse it elsewhere.
                </p>
              </div>

              {!hasProject && (
                <InlineNotice tone="amber" text="No project is open right now, so this scenario will be saved to the standalone library." />
              )}

              <div className="grid gap-4 md:grid-cols-2">
                <button
                  onClick={() => hasProject && onDraftChange({ scope: 'project' })}
                  disabled={!hasProject}
                  className={cn(
                    'rounded-[28px] border p-5 text-left transition-colors',
                    draft.scope === 'project' ? 'border-primary bg-primary/10' : 'border-border/40 bg-background/40 hover:bg-accent',
                    !hasProject && 'cursor-not-allowed opacity-50'
                  )}
                >
                  <div className="text-sm font-semibold">Current Project</div>
                  <p className="mt-2 text-sm leading-7 text-muted-foreground">
                    Use {currentProjectName || 'the active project'} tree nodes, controls, detections, and project context during planning.
                  </p>
                </button>
                <button
                  onClick={() => onDraftChange({ scope: 'standalone' })}
                  className={cn(
                    'rounded-[28px] border p-5 text-left transition-colors',
                    draft.scope === 'standalone' ? 'border-primary bg-primary/10' : 'border-border/40 bg-background/40 hover:bg-accent'
                  )}
                >
                  <div className="text-sm font-semibold">Standalone Library</div>
                  <p className="mt-2 text-sm leading-7 text-muted-foreground">
                    Keep this scenario reusable and independent from any one project. You can still refine and run it like any other scenario.
                  </p>
                </button>
              </div>
            </div>
          ) : step === 1 ? (
            <div className="space-y-6">
              <div className="max-w-3xl">
                <h3 className="text-xl font-semibold">Describe what you want to plan</h3>
                <p className="mt-2 text-sm leading-7 text-muted-foreground">
                  Keep this simple. Name the scenario, describe the operational question, and give the AI enough context to produce a useful first pass.
                </p>
              </div>

              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Scenario Name</label>
                  <input
                    value={draft.name}
                    onChange={(event) => onDraftChange({ name: event.target.value })}
                    placeholder="Quarter-end phishing exercise"
                    className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                  />
                </div>
                <div>
                  <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Target Profile</label>
                  <input
                    value={draft.target_profile}
                    onChange={(event) => onDraftChange({ target_profile: event.target.value })}
                    placeholder="Business unit, organisation, or user group"
                    className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                  />
                </div>
              </div>

              <ChoiceBlock
                label="Scenario Type"
                value={draft.scenario_type}
                options={SCENARIO_TYPES.map((item) => item.id)}
                display={(item) => getScenarioTypeLabel(item)}
                onSelect={(value) => onDraftChange({ scenario_type: value })}
              />

              <TextAreaField
                label="What are you trying to learn or achieve?"
                value={draft.operation_goal}
                placeholder="Test identity escalation paths across the production estate"
                onChange={(value) => onDraftChange({ operation_goal: value })}
              />

              <TextAreaField
                label="Scenario Context"
                value={draft.description}
                placeholder="Short plain-English description of the situation, change, or concern"
                onChange={(value) => onDraftChange({ description: value })}
              />

              <div>
                <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Environment or Terrain</label>
                <input
                  list="scenario-wizard-environment-presets"
                  value={draft.target_environment}
                  onChange={(event) => onDraftChange({ target_environment: event.target.value })}
                  placeholder="Cloud tenant, datacentre, corporate network, hybrid estate"
                  className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                />
                <datalist id="scenario-wizard-environment-presets">
                  {ENVIRONMENT_PRESET_OPTIONS.map((preset) => (
                    <option key={preset.id} value={preset.name} />
                  ))}
                </datalist>
                <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px] text-muted-foreground">
                  {currentProjectPreset ? (
                    <button
                      type="button"
                      onClick={() => onDraftChange({ target_environment: currentProjectPreset })}
                      className="rounded-full border border-border/50 bg-background/60 px-2.5 py-1 hover:border-primary/30 hover:bg-primary/5 hover:text-foreground"
                    >
                      Use project preset: {currentProjectPreset}
                    </button>
                  ) : null}
                  <span>Start broad here. You can add more detail after the first pass.</span>
                </div>
              </div>
            </div>
          ) : step === 2 ? (
            <div className="space-y-6">
              <div className="max-w-3xl">
                <h3 className="text-xl font-semibold">Set the attacker conditions</h3>
                <p className="mt-2 text-sm leading-7 text-muted-foreground">
                  These settings tell the planner how capable, fast, and stealthy the simulated attacker should be.
                </p>
              </div>

              <div className="grid gap-5 lg:grid-cols-2">
                <ChoiceBlock
                  label="Attacker Type"
                  value={draft.attacker_type}
                  options={ATTACKER_TYPES.map((item) => item.id)}
                  display={(item) => ATTACKER_TYPES.find((option) => option.id === item)?.label || item}
                  onSelect={(value) => onDraftChange({ attacker_type: value })}
                />
                <ChoiceBlock
                  label="Access Level"
                  value={draft.access_level}
                  options={ACCESS_OPTIONS}
                  display={formatEnumLabel}
                  onSelect={(value) => onDraftChange({ access_level: value })}
                />
                <ChoiceBlock label="Skill Level" value={draft.attacker_skill} options={SKILL_LEVELS} onSelect={(value) => onDraftChange({ attacker_skill: value })} />
                <ChoiceBlock label="Resources" value={draft.attacker_resources} options={RESOURCE_LEVELS} onSelect={(value) => onDraftChange({ attacker_resources: value })} />
                <ChoiceBlock
                  label="Execution Tempo"
                  value={draft.execution_tempo}
                  options={TEMPO_OPTIONS}
                  display={formatEnumLabel}
                  onSelect={(value) => onDraftChange({ execution_tempo: value })}
                />
                <ChoiceBlock
                  label="Stealth Level"
                  value={draft.stealth_level}
                  options={STEALTH_OPTIONS}
                  display={formatEnumLabel}
                  onSelect={(value) => onDraftChange({ stealth_level: value })}
                />
              </div>

              <div>
                <label className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Motivation</label>
                <input
                  value={draft.attacker_motivation}
                  onChange={(event) => onDraftChange({ attacker_motivation: event.target.value })}
                  placeholder="Fraud, espionage, disruption, validation, coercion"
                  className="mt-2 w-full rounded-xl border border-border/50 bg-background/40 px-3 py-2 text-sm outline-none focus:border-primary"
                />
              </div>
            </div>
          ) : (
            <div className="space-y-6">
              <div className="max-w-3xl">
                <h3 className="text-xl font-semibold">Add the most important focus and limits</h3>
                <p className="mt-2 text-sm leading-7 text-muted-foreground">
                  Give the planner the main routes, phases, and boundaries to respect. Anything else can be refined after the first result appears.
                </p>
              </div>

              <div className="grid gap-4 lg:grid-cols-2">
                <TokenEditor
                  label="Likely Entry Vectors"
                  helper="One per line. Keep only the main options."
                  value={draft.entry_vectors}
                  onChange={(value) => onDraftChange({ entry_vectors: value })}
                />
                <TokenEditor
                  label="Likely Campaign Phases"
                  helper="Sequence the operation in simple stages."
                  value={draft.campaign_phases}
                  onChange={(value) => onDraftChange({ campaign_phases: value })}
                />
                <TokenEditor
                  label="Constraints"
                  helper="Operational limits, timing, legal bounds, blast-radius constraints."
                  value={draft.constraints}
                  onChange={(value) => onDraftChange({ constraints: value })}
                />
                <TokenEditor
                  label="Success Criteria"
                  helper="How you will know the scenario plan was useful or complete."
                  value={draft.success_criteria}
                  onChange={(value) => onDraftChange({ success_criteria: value })}
                />
              </div>

              <TextAreaField
                label="Anything else the planner should keep in mind?"
                value={draft.planning_notes}
                placeholder="Optional notes, assumptions, or caveats for the first pass"
                onChange={(value) => onDraftChange({ planning_notes: value })}
              />

              <div className="grid gap-3 md:grid-cols-2">
                <WizardOutcomeCard
                  title="Save Setup Only"
                  description="Keep the scenario ready without generating output yet."
                />
                <WizardOutcomeCard
                  title="Generate Analysis + Brief"
                  description="Build the first scenario assessment, then write the narrative decision brief automatically."
                />
              </div>
            </div>
          )}
        </div>

        <div className="shrink-0 border-t border-border/40 px-6 py-4">
          <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="text-sm text-muted-foreground">
            Step {step + 1} of {SCENARIO_WIZARD_STEPS.length}. You can refine the full scenario after this setup closes.
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => canGoBack && onStepChange(step - 1)}
              disabled={!canGoBack}
              className="rounded-xl border border-border/50 px-4 py-2 text-sm font-medium hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
            >
              Back
            </button>
            {step < lastStep ? (
              <button
                onClick={() => canGoForward && onStepChange(step + 1)}
                disabled={!canGoForward}
                className="rounded-xl bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-50"
              >
                Continue
              </button>
            ) : (
              <>
                <button
                  onClick={() => onSubmit('draft')}
                  disabled={busy}
                  className="rounded-xl border border-border/50 px-4 py-2 text-sm font-medium hover:bg-accent disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Save Setup Only
                </button>
                <button
                  onClick={() => onSubmit('output')}
                  disabled={busy}
                  className="rounded-xl bg-cyan-600 px-4 py-2 text-sm font-semibold text-white hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  Save And Generate Analysis + Brief
                </button>
              </>
            )}
          </div>
        </div>
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

function WizardOutcomeCard({ title, description }: { title: string; description: string }) {
  return (
    <div className="rounded-2xl border border-border/40 bg-background/40 p-4">
      <div className="text-sm font-semibold">{title}</div>
      <div className="mt-2 text-xs leading-6 text-muted-foreground">{description}</div>
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
