import { useState, useEffect } from 'react';
import { api } from '@/utils/api';
import type {
  LLMAgentGenerationProfile,
  LLMAgentMode,
  LLMAgentResponseData,
  TemplateInfo,
} from '@/types';
import toast from 'react-hot-toast';
import { Bot, Loader2, X, Wand2, FileText, GitBranch } from 'lucide-react';
import { cn } from '@/utils/cn';
import { getPlanningProfileOption, PLANNING_PROFILE_OPTIONS } from '@/utils/planningProfiles';
import { formatContextPreset } from '@/utils/contextPresets';

interface AIAgentDialogProps {
  projectId: string;
  open: boolean;
  onClose: () => void;
  onComplete: () => void | Promise<void>;
}

const MODE_OPTIONS: { value: LLMAgentMode; label: string; description: string; icon: typeof Wand2 }[] = [
  { value: 'generate', label: 'Generate', description: 'Build new tree from scratch with AI', icon: Wand2 },
  { value: 'from_template', label: 'From Template', description: 'Expand a template with AI enrichment', icon: FileText },
  { value: 'expand', label: 'Gap Analysis', description: 'Find missing attack paths in existing tree', icon: GitBranch },
];

const PRESET_CATEGORIES = [
  {
    category: 'Enterprise / IT',
    presets: [
      { label: 'Data Centre Attack', objective: 'Compromise a data centre to disrupt operations and exfiltrate sensitive data', scope: 'Physical data centre with network infrastructure, servers, cooling systems, access controls, and staff' },
      { label: 'Web Application Compromise', objective: 'Compromise a production web application to steal user data', scope: 'Internet-facing web application with authentication, API backend, database, and cloud hosting' },
      { label: 'Ransomware Intrusion', objective: 'Deploy ransomware across an enterprise network', scope: 'Corporate Windows domain environment with Active Directory, email, VPN, and endpoint protection' },
      { label: 'Supply Chain Attack', objective: 'Compromise a software supply chain to distribute malicious code', scope: 'Software development pipeline with CI/CD, package repositories, code signing, and third-party dependencies' },
      { label: 'Cloud Infrastructure Takeover', objective: 'Gain full control of a cloud environment', scope: 'Multi-account AWS/Azure cloud environment with IAM, compute, storage, and networking resources' },
    ],
  },
  {
    category: 'SCADA / ICS / OT',
    presets: [
      { label: 'OT/ICS Process Manipulation', objective: 'Manipulate industrial control system processes to cause physical damage', scope: 'Industrial control system with SCADA, PLCs, HMIs, and IT/OT network boundary' },
      { label: 'Electrical Substation IED', objective: 'Manipulate substation IEDs to cause cascading grid faults via IEC 61850 / DNP3 protocol abuse', scope: 'Electrical substation with IEDs, protective relays, circuit breakers, IEC 61850 process bus, DNP3 outstations, and IT/OT DMZ' },
      { label: 'PLC Firmware Implant', objective: 'Implant malicious PLC firmware to covertly manipulate industrial processes while reporting normal telemetry', scope: 'Industrial facility with Siemens/Rockwell/ABB PLCs, engineering workstations, air-gapped OT network, and DCS' },
      { label: 'Gas Turbine DCS Attack', objective: 'Compromise gas turbine DCS to cause turbine overspeed, compressor surge, or forced shutdown', scope: 'Power generation plant with gas turbines, DCS (GE Mark VIe / Siemens T3000), SIS, and data historian' },
      { label: 'Water / Sewage Plant SCADA', objective: 'Compromise wastewater treatment SCADA to disable disinfection or release untreated sewage', scope: 'Municipal wastewater treatment plant with SCADA HMI, PLCs, chemical dosing, and remote cellular access' },
      { label: 'LNG Terminal DCS/SIS', objective: 'Attack LNG terminal DCS and safety systems to cause overpressure or disable emergency shutdown', scope: 'LNG regasification terminal with Yokogawa/Honeywell DCS, Triconex SIS, cryogenic storage tanks, and BOG compressors' },
      { label: 'Oil Refinery DCS/SIS', objective: 'Compromise refinery control and safety layers to disrupt production, damage process units, or degrade product quality', scope: 'Oil refinery with process-unit DCS HMIs, SIS logic solvers, tank farm automation, turnaround contractors, and laboratory release workflows' },
      { label: 'Drilling Rig Well Control', objective: 'Compromise drilling automation and well-control systems to cause operational disruption or unsafe process conditions', scope: 'Offshore or onshore drilling rig with drill-floor HMIs, BOP controls, mud logging, satcom links, and OEM remote support paths' },
    ],
  },
  {
    category: 'Power / Energy / Grid',
    presets: [
      { label: 'Solar Farm Inverter', objective: 'Compromise solar farm inverters and SCADA to destabilize grid frequency or disable generation', scope: 'Utility-scale solar farm with grid-tied inverters, Modbus TCP/SunSpec, cloud management portal, and cellular gateway' },
      { label: 'Wind Farm SCADA', objective: 'Take over wind farm SCADA to disable turbines or cause physical damage via pitch/yaw manipulation', scope: 'Onshore/offshore wind farm with turbine controllers, SCADA master, inter-turbine fibre network, and VPN to operations centre' },
      { label: 'Grid DERMS Attack', objective: 'Compromise DERMS to coordinate DER manipulation causing grid instability', scope: 'Utility DERMS managing distributed solar, battery storage, and EV chargers via OpenADR/IEEE 2030.5' },
      { label: 'Water Dam SCADA', objective: 'Override dam SCADA controls to cause uncontrolled water release or turbine damage', scope: 'Hydroelectric dam with SCADA, spillway gate RTUs, penstock controls, VSAT/cellular link, and on-site control room' },
    ],
  },
  {
    category: 'IoT / Smart Infrastructure',
    presets: [
      { label: 'IIoT Gateway Compromise', objective: 'Compromise IIoT gateways to pivot between IT/OT networks and manipulate industrial data', scope: 'Industrial IoT gateways bridging Modbus/OPC-UA to MQTT/AMQP cloud platforms with embedded Linux OS' },
      { label: 'Smart Building IoT Botnet', objective: 'Compromise BACnet/KNX building IoT devices to build a botnet or pivot into the corporate network', scope: 'Smart commercial building with BMS (Niagara/Desigo), BACnet/IP controllers, Zigbee sensors, HVAC, lighting, and access control' },
      { label: 'EV Charging Network', objective: 'Compromise EV charging infrastructure to disrupt services or destabilize the local grid', scope: 'EV charging network with OCPP 1.6/2.0 chargers, cloud CSMS, cellular/WiFi connectivity, and payment terminals' },
      { label: 'Airport Operations', objective: 'Disrupt airport operations by abusing baggage automation, operations systems, or airside support services', scope: 'Airport environment with AODB/FIDS, baggage handling, ground operations, fuel systems, building automation, and airline integration points' },
      { label: 'Satellite Ground Station', objective: 'Compromise a satellite ground segment to abuse TT&C, mission scheduling, or teleport operations', scope: 'Ground station with antenna control, TT&C processors, uplink/downlink chains, mission-control networks, and WAN backhaul to operator systems' },
      { label: 'Port / Naval Yard Operations', objective: 'Disrupt dockside or shipyard operations by abusing crane, shore-power, and partner access workflows', scope: 'Shipyard or naval-base environment with dry docks, crane control, dock systems, shore power, maintenance work orders, and partner remote access' },
    ],
  },
  {
    category: 'Defence & Mission Systems',
    presets: [
      { label: 'Military Headquarters', objective: 'Compromise a military headquarters to access mission planning, secure communications, or coalition coordination workflows', scope: 'Military headquarters with SCIF enclaves, secure messaging, identity infrastructure, cross-domain transfer points, and mission support workstations' },
      { label: 'Defence Manufacturing Plant', objective: 'Sabotage defence manufacturing by abusing production automation, traceability systems, or secure test workflows', scope: 'Defence manufacturing plant with PLCs, robotics, secure production lines, PLM systems, traceability records, and acceptance test rigs' },
    ],
  },
  {
    category: 'Software Research / Reverse Engineering',
    presets: [
      { label: 'Windows Client RE', objective: 'Reverse engineer a Windows desktop client to abuse trusted backend or helper functionality', scope: 'Electron, .NET, or native Windows client with updater, helper service, local cache, and authenticated backend APIs' },
      { label: 'Patch Diff N-Day', objective: 'Turn a freshly patched software issue into a reproducible n-day exploit path', scope: 'Old and new builds, vendor advisory, reachable parser or RPC surface, and a controlled analysis lab' },
      { label: 'File Parser Bug', objective: 'Develop an exploit path from a reachable file parser weakness', scope: 'Desktop or server-side parser handling attacker-controlled documents, archives, or media files with production mitigations enabled' },
      { label: 'Secure Updater Abuse', objective: 'Subvert a software updater trust chain to deliver malicious code or persistence', scope: 'Signed updater, manifest endpoint, privileged install helper, rollback logic, and local staging directories' },
      { label: 'Firmware Research', objective: 'Reverse engineer embedded firmware to find exploitable trust boundaries and persistent device-control paths', scope: 'Embedded Linux or RTOS device with OTA update workflow, bootloader trust checks, local management protocols, and physical debug interfaces' },
    ],
  },
];

const MAX_RECOMMENDED_AGENT_NODES = 300;
const TERMINAL_AGENT_RUN_STATUSES = new Set(['completed', 'completed_with_warnings', 'failed']);

function estimateTreeNodeBudget(depth: number, breadth: number): number {
  let total = 1;
  let levelSize = 1;
  for (let level = 1; level < depth; level += 1) {
    levelSize *= breadth;
    total += levelSize;
  }
  return total;
}

export function AIAgentDialog({ projectId, open, onClose, onComplete }: AIAgentDialogProps) {
  const [objective, setObjective] = useState('');
  const [scope, setScope] = useState('');
  const [depth, setDepth] = useState(4);
  const [breadth, setBreadth] = useState(5);
  const [mode, setMode] = useState<LLMAgentMode>('generate');
  const [generationProfile, setGenerationProfile] = useState<LLMAgentGenerationProfile>('balanced');
  const [templateId, setTemplateId] = useState<string>('');
  const [templates, setTemplates] = useState<TemplateInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [elapsedSec, setElapsedSec] = useState(0);
  const [result, setResult] = useState<LLMAgentResponseData | null>(null);
  const [errorMessage, setErrorMessage] = useState('');
  const selectedTemplate = templates.find((template) => template.id === templateId);
  const selectedGenerationProfile = getPlanningProfileOption(generationProfile);
  const estimatedNodeBudget = estimateTreeNodeBudget(depth, breadth);
  const exceedsRecommendedBudget = mode !== 'expand' && estimatedNodeBudget > MAX_RECOMMENDED_AGENT_NODES;

  // Load templates for "from_template" mode
  useEffect(() => {
    if (open && templates.length === 0) {
      api.listTemplates().then((res) => setTemplates(res.templates || [])).catch(() => {});
    }
  }, [open, templates.length]);

  // Elapsed timer
  useEffect(() => {
    if (!loading) { setElapsedSec(0); return; }
    const t = setInterval(() => setElapsedSec((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, [loading]);

  useEffect(() => {
    if (!open || !result?.agent_run_id || !result.background_processing) return;

    let cancelled = false;

    const pollStatus = async () => {
      try {
        const status = await api.getAgentRunStatus(result.agent_run_id!);
        if (cancelled) return;

        setResult((prev) => {
          if (!prev) return prev;
          return {
            ...prev,
            nodes_created: status.nodes_created,
            model_used: status.model_used || prev.model_used,
            elapsed_ms: status.elapsed_ms,
            passes_completed: status.passes_completed,
            total_passes: status.total_passes,
            warnings: status.warnings,
            background_processing: status.background_processing,
            current_stage: status.current_stage,
            post_processing_status: status.status,
            error_message: status.error_message,
            checkpoints: status.checkpoints,
          };
        });

        if (TERMINAL_AGENT_RUN_STATUSES.has(status.status)) {
          if (status.status === 'completed') {
            toast.success('Background AI post-processing completed');
          } else if (status.status === 'completed_with_warnings') {
            toast.success('Background AI post-processing completed with warnings');
          } else {
            toast.error(status.error_message || 'Background AI post-processing failed');
          }
          await onComplete();
        }
      } catch {
        // Best-effort polling; keep the generated tree usable even if status refresh fails.
      }
    };

    void pollStatus();
    const timer = setInterval(() => {
      void pollStatus();
    }, 3000);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [open, result?.agent_run_id, result?.background_processing, onComplete]);

  const PROGRESS_STEPS = [
    'Preparing prompts, templates, and planning context...',
    'Estimated stage: generating skeleton and expanding branches...',
    'Estimated stage: enriching node detail...',
    'Estimated stage: mapping references and controls...',
    'Estimated stage: finalizing the generated tree...',
  ];
  const progressStep = Math.min(Math.floor(elapsedSec / 15), PROGRESS_STEPS.length - 1);

  const handleGenerate = async () => {
    if (!objective.trim() && mode !== 'expand') {
      toast.error('Enter an attacker objective');
      return;
    }
    if (mode === 'from_template' && !templateId) {
      toast.error('Select a template');
      return;
    }
    setLoading(true);
    setResult(null);
    setErrorMessage('');
    try {
      const res = await api.agentGenerateTree({
        project_id: projectId,
        objective: objective.trim(),
        scope: scope.trim(),
        depth,
        breadth,
        mode,
        template_id: templateId || undefined,
        generation_profile: generationProfile,
      });
      setResult(res);
      if (res.background_processing && res.agent_run_id) {
        toast.success(`Generated ${res.nodes_created} nodes. Background AI post-processing started.`);
      } else {
        const passesMsg = res.passes_completed ? ` (${res.passes_completed} passes)` : '';
        const warningsMsg = res.warnings?.length ? ` with ${res.warnings.length} warning${res.warnings.length === 1 ? '' : 's'}` : '';
        toast.success(`Generated ${res.nodes_created} nodes${passesMsg}${warningsMsg}`);
      }
    } catch (e: any) {
      const msg = e.message || 'Unknown error';
      let friendly = msg;
      if (msg.includes('timed out') || msg.includes('504')) {
        friendly = 'Request timed out. Try reducing depth or breadth, or switch to a faster model.';
      } else if (msg.includes('invalid tree structure')) {
        friendly = 'AI returned malformed tree output. Try again with lower depth or breadth.';
      } else if (msg.includes('max_completion_tokens') || msg.includes('max_tokens')) {
        friendly = 'The configured model rejected the token-budget parameter. Retry now that the provider compatibility fix is in place.';
      } else if (msg.includes('already contains nodes')) {
        friendly = 'This project already has a tree. Use Gap Analysis to extend it, or create a new project for a fresh generation.';
      } else if (msg.includes('Gap analysis requires an existing tree')) {
        friendly = 'Gap Analysis only works on a project that already has nodes.';
      } else if (msg.includes('Select a valid template')) {
        friendly = 'The selected template could not be loaded. Reopen the dialog and choose it again.';
      } else if (msg.includes('Requested tree size is too large')) {
        friendly = 'The requested tree shape is too large for a robust run. Reduce depth or breadth before generating.';
      }
      setErrorMessage(friendly);
      toast.error(friendly);
    } finally {
      setLoading(false);
    }
  };

  const postProcessingStageLabel = result?.current_stage
    ? result.current_stage.replace(/_/g, ' ')
    : 'queued';

  const handleDone = () => {
    setObjective('');
    setScope('');
    setGenerationProfile('balanced');
    setResult(null);
    setErrorMessage('');
    onComplete();
    onClose();
  };

  const applyPreset = (preset: { objective: string; scope: string }) => {
    setObjective(preset.objective);
    setScope(preset.scope);
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-card border rounded-xl shadow-xl w-full max-w-2xl max-h-[85vh] overflow-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b">
          <div className="flex items-center gap-2">
            <Bot size={20} className="text-primary" />
            <h2 className="font-bold text-lg">AI Agent — Generate Attack Tree</h2>
          </div>
          <button onClick={onClose} className="p-1 rounded hover:bg-accent" disabled={loading}>
            <X size={16} />
          </button>
        </div>

        <div className="px-6 py-4 space-y-4">
          {/* Mode selector */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Generation Mode</label>
            <div className="grid grid-cols-3 gap-2">
              {MODE_OPTIONS.map((opt) => {
                const Icon = opt.icon;
                return (
                  <button
                    key={opt.value}
                    onClick={() => setMode(opt.value)}
                    disabled={loading}
                    className={cn(
                      "p-2 rounded-lg border text-left transition-colors disabled:opacity-50",
                      mode === opt.value
                        ? "border-primary bg-primary/10 ring-1 ring-primary/30"
                        : "hover:bg-accent"
                    )}
                  >
                    <div className="flex items-center gap-1.5 mb-0.5">
                      <Icon size={12} className={mode === opt.value ? "text-primary" : "text-muted-foreground"} />
                      <span className="text-xs font-medium">{opt.label}</span>
                    </div>
                    <p className="text-[10px] text-muted-foreground leading-tight">{opt.description}</p>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Template picker (from_template mode) */}
          {mode === 'from_template' && (
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Template <span className="text-destructive">*</span>
              </label>
              <select
                value={templateId}
                onChange={(e) => setTemplateId(e.target.value)}
                disabled={loading}
                className="w-full px-3 py-2 text-sm rounded-md border bg-background"
              >
                <option value="">Select a template...</option>
                {templates.map((t) => (
                  <option key={t.id} value={t.id}>{t.name}</option>
                ))}
              </select>
              {selectedTemplate && (
                <div className="mt-2 rounded-lg border p-3 space-y-2">
                  <div className="flex flex-wrap gap-1">
                    <span className="inline-flex rounded-full bg-muted px-2 py-0.5 text-[10px] font-medium">
                      {selectedTemplate.node_count} nodes
                    </span>
                    <span className="inline-flex rounded-full bg-muted px-2 py-0.5 text-[10px] font-medium">
                      {formatContextPreset(selectedTemplate.context_preset)}
                    </span>
                    <span className={cn(
                      'inline-flex rounded-full px-2 py-0.5 text-[10px] font-medium',
                      selectedTemplate.technical_profile === 'standard'
                        ? 'bg-muted text-muted-foreground'
                        : 'bg-primary/10 text-primary'
                    )}>
                      {selectedTemplate.technical_profile === 'standard' ? 'Standard' : 'Deep Technical'}
                    </span>
                  </div>
                  <p className="text-[11px] text-muted-foreground">
                    {selectedTemplate.description}
                  </p>
                  {selectedTemplate.focus_areas.length > 0 && (
                    <div className="text-[11px] text-muted-foreground">
                      Focus: {selectedTemplate.focus_areas.slice(0, 3).join(' • ')}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Quick presets (generate mode) */}
          {mode === 'generate' && (
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Quick Presets</label>
              <div className="space-y-2 max-h-40 overflow-y-auto pr-1">
                {PRESET_CATEGORIES.map((cat) => (
                  <div key={cat.category}>
                    <span className="text-[10px] font-semibold text-muted-foreground/70 uppercase tracking-wider">{cat.category}</span>
                    <div className="flex flex-wrap gap-1 mt-0.5">
                      {cat.presets.map((p) => (
                        <button
                          key={p.label}
                          onClick={() => applyPreset(p)}
                          disabled={loading}
                          className="px-2 py-0.5 text-[11px] rounded-full border hover:bg-accent transition-colors disabled:opacity-50"
                        >
                          {p.label}
                        </button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
              Generation Profile
            </label>
            <div className="grid gap-2 sm:grid-cols-3">
              {PLANNING_PROFILE_OPTIONS.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setGenerationProfile(option.value)}
                  disabled={loading}
                  className={cn(
                    'rounded-lg border p-3 text-left transition-colors disabled:opacity-50',
                    generationProfile === option.value
                      ? 'border-primary bg-primary/5'
                      : 'hover:bg-accent'
                  )}
                >
                  <div className="text-sm font-medium">{option.label}</div>
                  <div className="mt-1 text-[11px] text-muted-foreground leading-relaxed">
                    {option.description}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Objective */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
              Attacker Objective <span className="text-destructive">*</span>
            </label>
            <textarea
              value={objective}
              onChange={(e) => setObjective(e.target.value)}
              disabled={loading}
              placeholder="e.g. Compromise a data centre to disrupt operations and exfiltrate sensitive data"
              className="w-full px-3 py-2 text-sm rounded-md border bg-background resize-none h-20"
            />
          </div>

          {/* Scope */}
          <div>
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
              Target Scope / Description
            </label>
            <textarea
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              disabled={loading}
              placeholder="e.g. Physical data centre with network infrastructure, servers, cooling systems, access controls, and staff"
              className="w-full px-3 py-2 text-sm rounded-md border bg-background resize-none h-16"
            />
          </div>

          {/* Depth & Breadth */}
          {mode === 'expand' ? (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-muted-foreground">
              Gap Analysis uses the existing tree and ignores depth and breadth controls.
            </div>
          ) : (
            <div className="space-y-3">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                    Tree Depth (levels): {depth}
                  </label>
                  <input
                    type="range" min={2} max={6} value={depth}
                    onChange={(e) => setDepth(Number(e.target.value))}
                    disabled={loading}
                    className="w-full"
                  />
                  <div className="flex justify-between text-[10px] text-muted-foreground">
                    <span>Shallow (2)</span><span>Deep (6)</span>
                  </div>
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                    Breadth (children per node): {breadth}
                  </label>
                  <input
                    type="range" min={2} max={6} value={breadth}
                    onChange={(e) => setBreadth(Number(e.target.value))}
                    disabled={loading}
                    className="w-full"
                  />
                  <div className="flex justify-between text-[10px] text-muted-foreground">
                    <span>Narrow (2)</span><span>Wide (6)</span>
                  </div>
                </div>
              </div>
              <div className="text-[11px] text-muted-foreground">
                Estimated max nodes at full branching: {estimatedNodeBudget}. Actual output is often smaller.
              </div>
              {exceedsRecommendedBudget && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-700 dark:text-red-300">
                  This tree shape is too large for the hardened generator. Reduce depth or breadth until the estimate is at most {MAX_RECOMMENDED_AGENT_NODES} nodes.
                </div>
              )}
            </div>
          )}

          {/* Info box */}
          <div className="p-3 rounded-lg bg-muted/50 text-xs text-muted-foreground">
            {mode === 'generate' && (
              <>The AI agent performs staged generation: it first builds a compact skeleton, then expands each major branch with local context so later prompts do not resend the full tree.
              After structure generation it enriches missing node attributes, maps MITRE ATT&amp;CK / CAPEC / CWE references,
              and generates mitigations &amp; detections for leaf nodes. A matching template is auto-selected for few-shot guidance.</>
            )}
            {mode === 'from_template' && (
              <>The AI agent takes the selected template as a skeleton and expands it with additional attack paths,
              enriched descriptions, and risk scores tailored to your specific objective while keeping the chosen planning profile.</>
            )}
            {mode === 'expand' && (
              <>The AI agent analyses the existing attack tree in this workspace and identifies missing attack paths,
              uncovered vectors, and gaps in coverage, then generates nodes to fill them according to the selected planning profile.</>
            )}
            <div className="mt-2">
              <strong>{selectedGenerationProfile.label}:</strong> {selectedGenerationProfile.description}
            </div>
          </div>

          {/* Progress indicator */}
          {loading && (
            <div className="p-3 rounded-lg bg-blue-500/10 border border-blue-500/30 space-y-2">
              <div className="flex items-center gap-2">
                <Loader2 size={14} className="animate-spin text-blue-500" />
                <span className="text-sm font-medium text-blue-600 dark:text-blue-400">{PROGRESS_STEPS[progressStep]}</span>
              </div>
              <div className="w-full h-1.5 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-500 rounded-full transition-all duration-1000 ease-linear"
                  style={{ width: `${Math.min(((elapsedSec / (depth * breadth * 2)) * 100), 95)}%` }}
                />
              </div>
              <div className="text-[10px] text-muted-foreground">
                {elapsedSec}s elapsed &middot; Depth {depth} &times; Breadth {breadth} &middot; Stage text is estimated until the request completes
              </div>
            </div>
          )}

          {/* Result */}
          {result && (
            <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/30 text-sm space-y-2">
              <p className="font-medium text-green-600 dark:text-green-400">
                {result.background_processing ? 'Tree generated. Background post-processing is running.' : 'Tree generated successfully'}
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                {result.nodes_created} nodes created &middot; {result.passes_completed || 1}/{result.total_passes || 4} passes completed &middot; Model: {result.model_used} &middot; {(result.elapsed_ms / 1000).toFixed(1)}s
              </p>
              {result.background_processing && (
                <div className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-3 text-xs text-blue-800 dark:text-blue-200">
                  <div className="flex items-center gap-2">
                    <Loader2 size={12} className="animate-spin" />
                    <span>Current stage: {postProcessingStageLabel}</span>
                  </div>
                  <p className="mt-2 text-muted-foreground">
                    The tree structure is already saved. Enrichment, reference mapping, and control generation are checkpointed in the background.
                  </p>
                </div>
              )}
              {result.warnings && result.warnings.length > 0 && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-800 dark:text-amber-200">
                  <p className="font-medium">Generation warnings</p>
                  <ul className="mt-2 list-disc space-y-1 pl-4">
                    {result.warnings.map((warning, index) => (
                      <li key={index}>{warning}</li>
                    ))}
                  </ul>
                </div>
              )}
              {result.error_message && !result.background_processing && (
                <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-800 dark:text-red-200">
                  {result.error_message}
                </div>
              )}
            </div>
          )}

          {errorMessage && !loading && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-sm">
              <p className="font-medium text-red-600 dark:text-red-400">
                Generation failed
              </p>
              <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                {errorMessage}
              </p>
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end gap-2 pt-2">
            {result ? (
              <button
                onClick={handleDone}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md bg-primary text-primary-foreground hover:opacity-90"
              >
                {result.background_processing ? 'View Tree While Background Runs' : 'View Tree'}
              </button>
            ) : (
              <>
                <button
                  onClick={onClose}
                  disabled={loading}
                  className="px-4 py-2 text-sm rounded-md border hover:bg-accent disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={handleGenerate}
                  disabled={loading || (mode !== 'expand' && !objective.trim()) || exceedsRecommendedBudget}
                  className={cn(
                    "flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-md",
                    "bg-primary text-primary-foreground hover:opacity-90 disabled:opacity-50"
                  )}
                >
                  {loading ? (
                    <>
                      <Loader2 size={14} className="animate-spin" />
                      {mode === 'expand' ? 'Analysing tree...' : 'Generating tree...'}
                    </>
                  ) : (
                    <>
                      <Wand2 size={14} />
                      {mode === 'expand' ? 'Run Gap Analysis' : mode === 'from_template' ? 'Expand Template' : 'Generate Attack Tree'}
                    </>
                  )}
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
