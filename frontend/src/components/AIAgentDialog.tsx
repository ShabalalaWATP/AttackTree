import { useState, useEffect } from 'react';
import { api } from '@/utils/api';
import toast from 'react-hot-toast';
import { Bot, Loader2, X, Wand2, Layers, FileText, GitBranch } from 'lucide-react';
import { cn } from '@/utils/cn';

interface AIAgentDialogProps {
  projectId: string;
  open: boolean;
  onClose: () => void;
  onComplete: () => void;
}

type AgentMode = 'generate' | 'from_template' | 'expand';

const MODE_OPTIONS: { value: AgentMode; label: string; description: string; icon: typeof Wand2 }[] = [
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
    ],
  },
];

export function AIAgentDialog({ projectId, open, onClose, onComplete }: AIAgentDialogProps) {
  const [objective, setObjective] = useState('');
  const [scope, setScope] = useState('');
  const [depth, setDepth] = useState(4);
  const [breadth, setBreadth] = useState(5);
  const [mode, setMode] = useState<AgentMode>('generate');
  const [templateId, setTemplateId] = useState<string>('');
  const [templates, setTemplates] = useState<{ id: string; name: string; description: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [elapsedSec, setElapsedSec] = useState(0);
  const [result, setResult] = useState<{ nodes_created: number; model_used: string; elapsed_ms: number; passes_completed?: number } | null>(null);

  // Load templates for "from_template" mode
  useEffect(() => {
    if (open && templates.length === 0) {
      api.listTemplates().then((res) => setTemplates(res.templates || [])).catch(() => {});
    }
  }, [open]);

  // Elapsed timer
  useEffect(() => {
    if (!loading) { setElapsedSec(0); return; }
    const t = setInterval(() => setElapsedSec((s) => s + 1), 1000);
    return () => clearInterval(t);
  }, [loading]);

  const PROGRESS_STEPS = [
    'Detecting domain & loading references...',
    'Building attack tree structure (Pass 1)...',
    'Enriching node attributes (Pass 2)...',
    'Mapping MITRE ATT&CK / CAPEC / CWE (Pass 3)...',
    'Generating mitigations & detections (Pass 4)...',
    'Saving nodes to project...',
  ];
  const progressStep = Math.min(Math.floor(elapsedSec / 12), PROGRESS_STEPS.length - 1);

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
    try {
      const res = await api.agentGenerateTree({
        project_id: projectId,
        objective: objective.trim(),
        scope: scope.trim(),
        depth,
        breadth,
        mode,
        template_id: templateId || undefined,
      });
      setResult(res);
      const passesMsg = res.passes_completed ? ` (${res.passes_completed} passes)` : '';
      toast.success(`Generated ${res.nodes_created} nodes${passesMsg}`);
    } catch (e: any) {
      const msg = e.message || 'Unknown error';
      if (msg.includes('timed out') || msg.includes('504')) {
        toast.error('Request timed out — try reducing depth/breadth or use a faster model');
      } else if (msg.includes('invalid tree structure')) {
        toast.error('AI returned malformed output — try again with lower depth/breadth');
      } else {
        toast.error(msg);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleDone = () => {
    setObjective('');
    setScope('');
    setResult(null);
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
              {templateId && templates.find(t => t.id === templateId) && (
                <p className="text-[10px] text-muted-foreground mt-1">
                  {templates.find(t => t.id === templateId)?.description}
                </p>
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
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Tree Depth (levels): {depth}
              </label>
              <input
                type="range" min={2} max={9} value={depth}
                onChange={(e) => setDepth(Number(e.target.value))}
                disabled={loading}
                className="w-full"
              />
              <div className="flex justify-between text-[10px] text-muted-foreground">
                <span>Shallow (2)</span><span>Deep (9)</span>
              </div>
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Breadth (children per node): {breadth}
              </label>
              <input
                type="range" min={2} max={10} value={breadth}
                onChange={(e) => setBreadth(Number(e.target.value))}
                disabled={loading}
                className="w-full"
              />
              <div className="flex justify-between text-[10px] text-muted-foreground">
                <span>Narrow (2)</span><span>Wide (10)</span>
              </div>
            </div>
          </div>

          {/* Info box */}
          <div className="p-3 rounded-lg bg-muted/50 text-xs text-muted-foreground">
            {mode === 'generate' && (
              <>The AI agent performs <strong>4 passes</strong>: (1) generate tree structure with domain-specific prompting,
              (2) enrich missing node attributes, (3) map MITRE ATT&amp;CK / CAPEC / CWE references,
              (4) generate mitigations &amp; detections for leaf nodes. A matching template is auto-selected for few-shot guidance.</>
            )}
            {mode === 'from_template' && (
              <>The AI agent takes the selected template as a skeleton and expands it with additional attack paths,
              enriched descriptions, and risk scores tailored to your specific objective.</>
            )}
            {mode === 'expand' && (
              <>The AI agent analyses the existing attack tree in this project and identifies missing attack paths,
              uncovered vectors, and gaps in coverage, then generates nodes to fill them.</>
            )}
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
              <div className="text-[10px] text-muted-foreground">{elapsedSec}s elapsed &middot; Depth {depth} &times; Breadth {breadth}</div>
            </div>
          )}

          {/* Result */}
          {result && (
            <div className="p-3 rounded-lg bg-green-500/10 border border-green-500/30 text-sm">
              <p className="font-medium text-green-600 dark:text-green-400">
                Tree generated successfully
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                {result.nodes_created} nodes created &middot; {result.passes_completed || 1} passes &middot; Model: {result.model_used} &middot; {(result.elapsed_ms / 1000).toFixed(1)}s
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
                View Tree
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
                  disabled={loading || !objective.trim()}
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
