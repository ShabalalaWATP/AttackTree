import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import { StandaloneLanding } from '@/components/StandaloneLanding';
import toast from 'react-hot-toast';
import {
  ShieldCheck, Plus, Trash2, Brain, Loader2, Sparkles, Database, ArrowRight,
  Server, Globe, Lock, User, Cloud, ChevronDown, ChevronRight, Link2,
  AlertTriangle, Shield, Box, X, Search, Filter, Target, BarChart3,
  Grid3X3, Eye, Zap, TrendingUp, Crosshair, ExternalLink, Info
} from 'lucide-react';


interface Component {
  id: string;
  name: string;
  type: string;
  technology: string;
  x: number;
  y: number;
}

interface DataFlow {
  id: string;
  source: string;
  target: string;
  protocol: string;
  data_classification: string;
  authentication?: string;
  label?: string;
}

interface TrustBoundary {
  id: string;
  name: string;
  component_ids: string[];
}

interface Threat {
  id: string;
  component_id: string;
  component_name: string;
  category: string;
  title: string;
  description: string;
  severity: string;
  attack_vector: string;
  mitigation: string;
  likelihood: string | number;
  impact: string | number;
  risk_score?: number;
  prerequisites?: string;
  exploitation_complexity?: string;
  real_world_examples?: string;
  mitre_technique?: string;
  linked_node_id?: string;
}

interface ThreatModelData {
  id: string;
  project_id: string;
  name: string;
  description: string;
  methodology: string;
  scope: string;
  components: Component[];
  data_flows: DataFlow[];
  trust_boundaries: TrustBoundary[];
  threats: Threat[];
  ai_summary: string;
  created_at: string;
}

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

function normalizeThreatModel(data: any): ThreatModelData {
  const components = Array.isArray(data?.components)
    ? data.components.filter(isRecord).map((item: Record<string, any>) => ({
        id: typeof item.id === 'string' ? item.id : crypto.randomUUID(),
        name: typeof item.name === 'string' ? item.name : 'Unnamed component',
        type: typeof item.type === 'string' ? item.type : 'service',
        technology: typeof item.technology === 'string' ? item.technology : '',
        x: typeof item.x === 'number' ? item.x : 0,
        y: typeof item.y === 'number' ? item.y : 0,
      }))
    : [];

  const dataFlows = Array.isArray(data?.data_flows)
    ? data.data_flows.filter(isRecord).map((item: Record<string, any>) => ({
        id: typeof item.id === 'string' ? item.id : crypto.randomUUID(),
        source: typeof item.source === 'string' ? item.source : '',
        target: typeof item.target === 'string' ? item.target : '',
        protocol: typeof item.protocol === 'string' ? item.protocol : '',
        data_classification: typeof item.data_classification === 'string' ? item.data_classification : '',
        authentication: typeof item.authentication === 'string' ? item.authentication : undefined,
        label: typeof item.label === 'string' ? item.label : undefined,
      }))
    : [];

  const trustBoundaries = Array.isArray(data?.trust_boundaries)
    ? data.trust_boundaries.filter(isRecord).map((item: Record<string, any>) => ({
        id: typeof item.id === 'string' ? item.id : crypto.randomUUID(),
        name: typeof item.name === 'string' ? item.name : 'Unnamed boundary',
        component_ids: stringList(item.component_ids),
      }))
    : [];

  const threats = Array.isArray(data?.threats)
    ? data.threats.filter(isRecord).map((item: Record<string, any>) => ({
        id: typeof item.id === 'string' ? item.id : crypto.randomUUID(),
        component_id: typeof item.component_id === 'string' ? item.component_id : '',
        component_name: typeof item.component_name === 'string' ? item.component_name : '',
        category: typeof item.category === 'string' ? item.category : 'Other',
        title: typeof item.title === 'string' ? item.title : 'Untitled threat',
        description: typeof item.description === 'string' ? item.description : '',
        severity: typeof item.severity === 'string' ? item.severity.toLowerCase() : 'low',
        attack_vector: typeof item.attack_vector === 'string' ? item.attack_vector : '',
        mitigation: typeof item.mitigation === 'string' ? item.mitigation : '',
        likelihood: typeof item.likelihood === 'string' || typeof item.likelihood === 'number' ? item.likelihood : 'low',
        impact: typeof item.impact === 'string' || typeof item.impact === 'number' ? item.impact : 'low',
        risk_score: typeof item.risk_score === 'number' ? item.risk_score : undefined,
        prerequisites: typeof item.prerequisites === 'string' ? item.prerequisites : undefined,
        exploitation_complexity: typeof item.exploitation_complexity === 'string' ? item.exploitation_complexity : undefined,
        real_world_examples: typeof item.real_world_examples === 'string' ? item.real_world_examples : undefined,
        mitre_technique: typeof item.mitre_technique === 'string' ? item.mitre_technique : undefined,
        linked_node_id: typeof item.linked_node_id === 'string' ? item.linked_node_id : undefined,
      }))
    : [];

  return {
    ...data,
    id: typeof data?.id === 'string' ? data.id : crypto.randomUUID(),
    project_id: typeof data?.project_id === 'string' ? data.project_id : '',
    name: typeof data?.name === 'string' ? data.name : 'Untitled Threat Model',
    description: typeof data?.description === 'string' ? data.description : '',
    methodology: typeof data?.methodology === 'string' ? data.methodology : 'stride',
    scope: typeof data?.scope === 'string' ? data.scope : '',
    components,
    data_flows: dataFlows,
    trust_boundaries: trustBoundaries,
    threats,
    ai_summary: typeof data?.ai_summary === 'string' ? data.ai_summary : '',
    created_at: typeof data?.created_at === 'string' ? data.created_at : '',
  };
}

const METHODOLOGIES = [
  { id: 'stride', label: 'STRIDE' },
  { id: 'pasta', label: 'PASTA' },
  { id: 'linddun', label: 'LINDDUN' },
];

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-500 bg-red-500/10',
  high: 'text-orange-500 bg-orange-500/10',
  medium: 'text-yellow-500 bg-yellow-500/10',
  low: 'text-blue-500 bg-blue-500/10',
  info: 'text-gray-400 bg-gray-500/10',
};

const CATEGORY_COLORS: Record<string, string> = {
  spoofing: 'bg-purple-500',
  tampering: 'bg-red-500',
  repudiation: 'bg-orange-500',
  'information disclosure': 'bg-yellow-500',
  'denial of service': 'bg-blue-500',
  'elevation of privilege': 'bg-pink-500',
  // LINDDUN
  linkability: 'bg-purple-500',
  identifiability: 'bg-red-500',
  'non-repudiation': 'bg-orange-500',
  detectability: 'bg-yellow-500',
  disclosure: 'bg-blue-500',
  unawareness: 'bg-pink-500',
  'non-compliance': 'bg-cyan-500',
};

const METHODOLOGY_CATEGORIES: Record<string, string[]> = {
  stride: ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'],
  pasta: ['Attack Simulation', 'Vulnerability Analysis', 'Risk Analysis', 'Exploitation', 'Impact'],
  linddun: ['Linkability', 'Identifiability', 'Non-repudiation', 'Detectability', 'Disclosure', 'Unawareness', 'Non-compliance'],
};

const COMPLEXITY_COLORS: Record<string, string> = {
  trivial: 'text-red-400 bg-red-500/10',
  low: 'text-orange-400 bg-orange-500/10',
  moderate: 'text-yellow-400 bg-yellow-500/10',
  high: 'text-blue-400 bg-blue-500/10',
  expert: 'text-green-400 bg-green-500/10',
};

const COMPONENT_ICONS: Record<string, React.ReactNode> = {
  web_app: <Globe size={16} />,
  api: <Server size={16} />,
  database: <Database size={16} />,
  service: <Box size={16} />,
  external: <Cloud size={16} />,
  user: <User size={16} />,
};

export function ThreatModelView() {
  const { currentProject, nodes, setNodes } = useStore();
  const [threatModels, setThreatModels] = useState<ThreatModelData[]>([]);
  const [selected, setSelected] = useState<ThreatModelData | null>(null);
  const [dfdLoading, setDfdLoading] = useState(false);
  const [threatLoading, setThreatLoading] = useState(false);
  const [fullLoading, setFullLoading] = useState(false);
  const [linkLoading, setLinkLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createMethodology, setCreateMethodology] = useState('stride');
  const [systemDesc, setSystemDesc] = useState('');
  const [activeTab, setActiveTab] = useState<'dfd' | 'threats' | 'matrix' | 'summary'>('dfd');
  const [expandedThreat, setExpandedThreat] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [deepDiveLoading, setDeepDiveLoading] = useState<string | null>(null);
  const [deepDiveResults, setDeepDiveResults] = useState<Record<string, any>>({});
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // Load nodes from API when entering this view
  useEffect(() => {
    if (currentProject && nodes.length === 0) {
      api.listNodes(currentProject.id).then((data) => { if (data.length) setNodes(data); }).catch(() => {});
    }
  }, [currentProject?.id]);

  useEffect(() => {
    if (currentProject) loadModels();
  }, [currentProject?.id]);

  useEffect(() => {
    if (selected && activeTab === 'dfd') drawDFD();
  }, [selected, activeTab]);

  const loadModels = async () => {
    if (!currentProject) return;
    try {
      const data = await api.listThreatModels(currentProject.id);
      setThreatModels(Array.isArray(data) ? data.map((item) => normalizeThreatModel(item)) : []);
    } catch (e: any) { toast.error(e.message); }
  };

  const handleCreate = async () => {
    if (!currentProject) { toast('Open a standalone scan or project scan workspace to create threat models', { icon: '📂' }); return; }
    try {
      const tm = await api.createThreatModel({
        project_id: currentProject.id,
        name: createName || `Threat Model (${createMethodology.toUpperCase()})`,
        methodology: createMethodology,
      });
      const normalized = normalizeThreatModel(tm);
      setThreatModels([normalized, ...threatModels]);
      setSelected(normalized);
      setShowCreate(false);
      setCreateName('');
    } catch (e: any) { toast.error(e.message); }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.deleteThreatModel(id);
      setThreatModels(threatModels.filter(t => t.id !== id));
      if (selected?.id === id) setSelected(null);
      toast.success('Threat model deleted');
    } catch (e: any) { toast.error(e.message); }
  };

  const handleGenerateDFD = async () => {
    if (!selected || !systemDesc.trim()) return;
    setDfdLoading(true);
    try {
      const result = await api.aiGenerateDFD(selected.id, { system_description: systemDesc });
      const normalized = normalizeThreatModel(result);
      setSelected(normalized);
      setThreatModels(threatModels.map(t => t.id === normalized.id ? normalized : t));
      toast.success('DFD generated');
    } catch (e: any) { toast.error(e.message); }
    finally { setDfdLoading(false); }
  };

  const handleGenerateThreats = async () => {
    if (!selected) return;
    setThreatLoading(true);
    try {
      const result = await api.aiGenerateThreats(selected.id, {});
      const normalized = normalizeThreatModel(result);
      setSelected(normalized);
      setThreatModels(threatModels.map(t => t.id === normalized.id ? normalized : t));
      setActiveTab('threats');
      toast.success(`AI found ${normalized.threats?.length || 0} threats`);
    } catch (e: any) { toast.error(e.message); }
    finally { setThreatLoading(false); }
  };

  const handleFullAnalysis = async () => {
    if (!currentProject) { toast('Open a standalone scan or project scan workspace to run full analysis', { icon: '📂' }); return; }
    if (!systemDesc.trim()) return;
    setFullLoading(true);
    try {
      const result = await api.aiFullThreatModel(currentProject.id, {
        system_description: systemDesc,
        methodology: createMethodology,
        name: createName || 'AI Threat Model',
      });
      const normalized = normalizeThreatModel(result);
      setThreatModels([normalized, ...threatModels]);
      setSelected(normalized);
      setActiveTab('threats');
      toast.success('Full AI analysis complete');
    } catch (e: any) { toast.error(e.message); }
    finally { setFullLoading(false); }
  };

  const handleLinkToTree = async () => {
    if (!selected) return;
    setLinkLoading(true);
    try {
      await api.linkThreatsToTree(selected.id, {});
      toast.success('Threats linked to attack tree as nodes');
    } catch (e: any) { toast.error(e.message); }
    finally { setLinkLoading(false); }
  };

  const handleDeepDive = async (threatId: string) => {
    if (!selected) return;
    setDeepDiveLoading(threatId);
    try {
      const result = await api.aiDeepDiveThreat(selected.id, { threat_id: threatId });
      setDeepDiveResults(prev => ({ ...prev, [threatId]: result }));
      toast.success('Deep-dive analysis complete');
    } catch (e: any) { toast.error(e.message); }
    finally { setDeepDiveLoading(null); }
  };

  // Simple canvas-based DFD rendering
  const drawDFD = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || !selected) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const components = selected.components || [];
    const flows = selected.data_flows || [];
    const boundaries = selected.trust_boundaries || [];

    canvas.width = canvas.offsetWidth * 2;
    canvas.height = canvas.offsetHeight * 2;
    ctx.scale(2, 2);
    ctx.clearRect(0, 0, canvas.offsetWidth, canvas.offsetHeight);

    const W = canvas.offsetWidth;
    const H = canvas.offsetHeight;

    // Position components in a grid if no coordinates
    const positionedComponents = components.map((c, i) => ({
      ...c,
      x: c.x || 80 + (i % 4) * 180,
      y: c.y || 80 + Math.floor(i / 4) * 140,
    }));

    // Draw trust boundaries
    boundaries.forEach(b => {
      const bComps = positionedComponents.filter(c => b.component_ids?.includes(c.id));
      if (bComps.length === 0) return;
      const minX = Math.min(...bComps.map(c => c.x)) - 40;
      const minY = Math.min(...bComps.map(c => c.y)) - 40;
      const maxX = Math.max(...bComps.map(c => c.x)) + 120;
      const maxY = Math.max(...bComps.map(c => c.y)) + 80;

      ctx.save();
      ctx.setLineDash([6, 4]);
      ctx.strokeStyle = '#f97316';
      ctx.lineWidth = 1.5;
      ctx.strokeRect(minX, minY, maxX - minX, maxY - minY);
      ctx.fillStyle = '#f9731610';
      ctx.fillRect(minX, minY, maxX - minX, maxY - minY);
      ctx.setLineDash([]);
      ctx.fillStyle = '#f97316';
      ctx.font = '10px sans-serif';
      ctx.fillText(b.name, minX + 4, minY - 4);
      ctx.restore();
    });

    // Draw data flows
    flows.forEach(f => {
      const src = positionedComponents.find(c => c.id === f.source);
      const tgt = positionedComponents.find(c => c.id === f.target);
      if (!src || !tgt) return;

      const sx = src.x + 40;
      const sy = src.y + 25;
      const tx = tgt.x + 40;
      const ty = tgt.y + 25;

      ctx.beginPath();
      ctx.moveTo(sx, sy);
      ctx.lineTo(tx, ty);
      ctx.strokeStyle = '#6366f180';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      // Arrow
      const angle = Math.atan2(ty - sy, tx - sx);
      const arrowLen = 8;
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(tx - arrowLen * Math.cos(angle - 0.4), ty - arrowLen * Math.sin(angle - 0.4));
      ctx.lineTo(tx - arrowLen * Math.cos(angle + 0.4), ty - arrowLen * Math.sin(angle + 0.4));
      ctx.closePath();
      ctx.fillStyle = '#6366f1';
      ctx.fill();

      // Label
      const mx = (sx + tx) / 2;
      const my = (sy + ty) / 2;
      ctx.fillStyle = '#888';
      ctx.font = '9px sans-serif';
      ctx.fillText(f.protocol || '', mx, my - 6);
    });

    // Draw components
    positionedComponents.forEach(c => {
      ctx.fillStyle = '#1e1e2e';
      ctx.strokeStyle = '#444';
      ctx.lineWidth = 1;
      const r = 6;
      const w = 80, h = 50;
      ctx.beginPath();
      ctx.roundRect(c.x, c.y, w, h, r);
      ctx.fill();
      ctx.stroke();

      // Type indicator strip
      const typeColor =
        c.type === 'database' ? '#22c55e' :
        c.type === 'external' ? '#f59e0b' :
        c.type === 'web_app' ? '#3b82f6' :
        c.type === 'api' ? '#8b5cf6' :
        c.type === 'user' ? '#ec4899' : '#6b7280';
      ctx.fillStyle = typeColor;
      ctx.beginPath();
      ctx.roundRect(c.x, c.y, w, 4, [r, r, 0, 0]);
      ctx.fill();

      // Name
      ctx.fillStyle = '#e0e0e0';
      ctx.font = 'bold 10px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(c.name?.substring(0, 12) || '', c.x + w / 2, c.y + 24);
      ctx.fillStyle = '#888';
      ctx.font = '8px sans-serif';
      ctx.fillText(c.type || '', c.x + w / 2, c.y + 38);
      ctx.textAlign = 'start';

      // Threat count badge
      const compThreats = (selected.threats || []).filter((t: any) => t.component_id === c.id);
      if (compThreats.length > 0) {
        const hasCritical = compThreats.some((t: any) => t.severity === 'critical');
        const hasHigh = compThreats.some((t: any) => t.severity === 'high');
        const badgeColor = hasCritical ? '#ef4444' : hasHigh ? '#f97316' : '#eab308';
        const bx = c.x + w - 8;
        const by = c.y - 4;
        ctx.beginPath();
        ctx.arc(bx, by, 9, 0, Math.PI * 2);
        ctx.fillStyle = badgeColor;
        ctx.fill();
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 9px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(String(compThreats.length), bx, by + 3);
        ctx.textAlign = 'start';
      }
    });
  }, [selected]);

  const components = selected?.components || [];
  const threats = selected?.threats || [];

  // Filtered threats
  const filteredThreats = useMemo(() => threats.filter(t => {
    if (severityFilter !== 'all' && t.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return t.title?.toLowerCase().includes(q) || t.description?.toLowerCase().includes(q)
        || t.category?.toLowerCase().includes(q) || t.attack_vector?.toLowerCase().includes(q);
    }
    return true;
  }), [threats, severityFilter, searchQuery]);

  // Group threats by category
  const threatsByCategory: Record<string, Threat[]> = {};
  filteredThreats.forEach(t => {
    const cat = t.category?.toLowerCase() || 'other';
    if (!threatsByCategory[cat]) threatsByCategory[cat] = [];
    threatsByCategory[cat].push(t);
  });

  // Threats per component (for DFD badges + matrix)
  const threatsByComponent = useMemo(() => {
    const map: Record<string, Threat[]> = {};
    threats.forEach(t => {
      const cid = t.component_id || 'unknown';
      if (!map[cid]) map[cid] = [];
      map[cid].push(t);
    });
    return map;
  }, [threats]);

  // Matrix data: components × methodology categories
  const matrixData = useMemo(() => {
    const cats = METHODOLOGY_CATEGORIES[selected?.methodology || 'stride'] || METHODOLOGY_CATEGORIES.stride;
    return {
      categories: cats,
      rows: components.map(c => ({
        component: c,
        cells: cats.map(cat => {
          const matching = threats.filter(t => t.component_id === c.id && t.category?.toLowerCase() === cat.toLowerCase());
          const maxSev = matching.reduce((best, t) => {
            const order = ['critical', 'high', 'medium', 'low'];
            return order.indexOf(t.severity) < order.indexOf(best) ? t.severity : best;
          }, 'low' as string);
          return { count: matching.length, maxSeverity: matching.length > 0 ? maxSev : null, threats: matching };
        }),
      })),
    };
  }, [components, threats, selected?.methodology]);

  // Summary stats
  const summaryStats = useMemo(() => {
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    let totalRisk = 0;
    threats.forEach(t => {
      if (t.severity in sevCounts) sevCounts[t.severity as keyof typeof sevCounts]++;
      totalRisk += (t.risk_score || (Number(t.likelihood) || 5) * (Number(t.impact) || 5));
    });
    const avgRisk = threats.length ? Math.round(totalRisk / threats.length) : 0;

    // Top 5 threats by risk
    const topThreats = [...threats].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0)).slice(0, 5);

    // Component risk ranking
    const compRisk = components.map(c => {
      const ct = threatsByComponent[c.id] || [];
      const risk = ct.reduce((sum, t) => sum + (t.risk_score || 0), 0);
      return { ...c, threatCount: ct.length, totalRisk: risk, avgRisk: ct.length ? Math.round(risk / ct.length) : 0 };
    }).sort((a, b) => b.totalRisk - a.totalRisk);

    return { sevCounts, avgRisk, topThreats, compRisk, totalRisk };
  }, [threats, components, threatsByComponent]);

  if (!currentProject) {
    return (
      <StandaloneLanding
        icon={<ShieldCheck size={28} className="text-emerald-500" />}
        title="Threat Modeling Workspace"
        description="Generate threat models inside either a standalone scan workspace or a project scan workspace. The workspace objective and system description can drive full AI analysis, then link findings back into the attack tree."
        features={[
          { icon: <Database size={15} className="text-emerald-500" />, title: 'DFD Generation', desc: 'Build data flow diagrams for scoped systems, services, and trust boundaries.' },
          { icon: <Shield size={15} className="text-emerald-500" />, title: 'Threat Discovery', desc: 'Run STRIDE, PASTA, or LINDDUN analyses with risk scoring and narratives.' },
          { icon: <Link2 size={15} className="text-emerald-500" />, title: 'Tree Linking', desc: 'Push validated threats back into the workspace attack tree as actionable nodes.' },
        ]}
      />
    );
  }

  return (
    <div className="h-full flex flex-col">
      {/* Toolbar */}
      <div className="border-b px-4 py-2 flex items-center gap-3 bg-card shrink-0 flex-wrap">
        <ShieldCheck size={16} className="text-emerald-500" />
        <h2 className="font-semibold text-sm">Threat Modeling</h2>
        <div className="border-l h-5 mx-1" />

        <select value={selected?.id || ''} onChange={(e) => setSelected(threatModels.find(t => t.id === e.target.value) || null)}
          className="text-xs bg-transparent border rounded px-2 py-1">
          <option value="">Select model...</option>
          {threatModels.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>

        <select value={createMethodology} onChange={(e) => setCreateMethodology(e.target.value)}
          className="text-xs bg-transparent border rounded px-2 py-1">
          {METHODOLOGIES.map(m => <option key={m.id} value={m.id}>{m.label}</option>)}
        </select>

        {showCreate ? (
          <div className="flex items-center gap-1">
            <input value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="Name..."
              className="text-xs bg-transparent border rounded px-2 py-1 w-32" />
            <button onClick={handleCreate} className="text-xs px-2 py-1 rounded bg-emerald-600 text-white hover:bg-emerald-700">Create</button>
            <button onClick={() => setShowCreate(false)} className="p-0.5"><X size={12} /></button>
          </div>
        ) : (
          <button onClick={() => setShowCreate(true)} className="p-1 rounded hover:bg-accent"><Plus size={14} /></button>
        )}

        <div className="flex-1" />

        {selected && components.length > 0 && (
          <button onClick={handleGenerateThreats} disabled={threatLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-amber-600 text-white text-xs font-medium hover:bg-amber-700 disabled:opacity-50">
            {threatLoading ? <Loader2 size={13} className="animate-spin" /> : <AlertTriangle size={13} />}
            AI Find Threats
          </button>
        )}

        {selected && threats.length > 0 && (
          <button onClick={handleLinkToTree} disabled={linkLoading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-purple-600 text-white text-xs font-medium hover:bg-purple-700 disabled:opacity-50">
            {linkLoading ? <Loader2 size={13} className="animate-spin" /> : <Link2 size={13} />}
            Link to Tree
          </button>
        )}

        {selected && (
          <button onClick={() => handleDelete(selected.id)} className="p-1 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive">
            <Trash2 size={14} />
          </button>
        )}
      </div>

      {/* Content */}
      {!selected ? (
        <div className="flex-1 flex items-center justify-center text-muted-foreground p-6">
          <div className="text-center max-w-lg">
            <ShieldCheck size={40} className="mx-auto mb-3 text-emerald-500/50" />
            <p className="text-sm mb-4">Describe your system and let AI generate a threat model</p>

            <textarea value={systemDesc} onChange={(e) => setSystemDesc(e.target.value)}
              placeholder="Describe the system to threat-model, e.g.: A web app with a React frontend, Node.js API server, PostgreSQL database, and external payment gateway. Users authenticate via OAuth2..."
              className="w-full h-32 text-xs bg-transparent border rounded-lg p-3 resize-none focus:border-emerald-500 outline-none mb-3"
            />
            <button onClick={handleFullAnalysis} disabled={fullLoading || !systemDesc.trim()}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 text-white text-sm font-medium hover:bg-emerald-700 disabled:opacity-50 mx-auto">
              {fullLoading ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />}
              AI Full Threat Analysis
            </button>
          </div>
        </div>
      ) : (
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b shrink-0">
            {(['dfd', 'threats', 'matrix', 'summary'] as const).map(tab => (
              <button key={tab} onClick={() => setActiveTab(tab)}
                className={cn('px-4 py-2 text-xs font-medium border-b-2 transition-colors',
                  activeTab === tab ? 'border-primary text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground'
                )}>
                {tab === 'dfd' ? `Data Flow Diagram (${components.length})` :
                 tab === 'threats' ? `Threats (${threats.length})` :
                 tab === 'matrix' ? `${(selected?.methodology || 'stride').toUpperCase()} Matrix` : 'Summary & Risk'}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="flex-1 overflow-auto">
            {activeTab === 'dfd' && (
              <div className="h-full flex flex-col">
                {/* DFD generation input */}
                <div className="p-3 border-b shrink-0">
                  <div className="flex gap-2">
                    <textarea value={systemDesc} onChange={(e) => setSystemDesc(e.target.value)}
                      placeholder="Describe the system..."
                      className="flex-1 text-xs bg-transparent border rounded-lg p-2 resize-none h-12 focus:border-emerald-500 outline-none" />
                    <button onClick={handleGenerateDFD} disabled={dfdLoading || !systemDesc.trim()}
                      className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-emerald-600 text-white text-xs font-medium hover:bg-emerald-700 disabled:opacity-50 shrink-0 self-end">
                      {dfdLoading ? <Loader2 size={13} className="animate-spin" /> : <Brain size={13} />}
                      Generate DFD
                    </button>
                  </div>
                </div>

                {components.length === 0 ? (
                  <div className="flex-1 flex items-center justify-center text-muted-foreground">
                    <p className="text-xs">Describe your system above and click Generate DFD</p>
                  </div>
                ) : (
                  <div className="flex-1 relative">
                    <canvas ref={canvasRef} className="w-full h-full" style={{ imageRendering: 'auto' }} />
                    {/* Components legend with threat counts */}
                    <div className="absolute top-3 right-3 bg-card/90 backdrop-blur border rounded-lg p-2 text-[10px] space-y-1 max-h-[260px] overflow-y-auto">
                      <div className="text-[9px] text-muted-foreground font-semibold mb-1 uppercase tracking-wider">Components</div>
                      {components.map(c => {
                        const ct = threatsByComponent[c.id] || [];
                        const hasCrit = ct.some(t => t.severity === 'critical');
                        const hasHigh = ct.some(t => t.severity === 'high');
                        return (
                          <div key={c.id} className="flex items-center gap-1.5">
                            {COMPONENT_ICONS[c.type] || <Box size={12} />}
                            <span className="flex-1">{c.name}</span>
                            {ct.length > 0 && (
                              <span className={cn('px-1 py-0.5 rounded text-[9px] font-bold',
                                hasCrit ? 'bg-red-500/20 text-red-400' : hasHigh ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-400'
                              )}>
                                {ct.length}
                              </span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'threats' && (
              <div className="p-4 space-y-4">
                {threats.length === 0 ? (
                  <div className="text-center text-muted-foreground py-12">
                    <AlertTriangle size={32} className="mx-auto mb-2 text-amber-500/40" />
                    <p className="text-sm">No threats identified yet</p>
                    <p className="text-xs mt-1">Generate a DFD first, then click <strong>AI Find Threats</strong></p>
                  </div>
                ) : (
                  <>
                    {/* Filter bar */}
                    <div className="flex items-center gap-2 flex-wrap">
                      <div className="relative flex-1 min-w-[200px] max-w-sm">
                        <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-muted-foreground" />
                        <input value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)}
                          placeholder="Search threats..."
                          className="w-full text-xs bg-transparent border rounded-lg pl-8 pr-3 py-1.5 focus:border-emerald-500 outline-none" />
                      </div>
                      <div className="flex items-center gap-1">
                        <Filter size={12} className="text-muted-foreground" />
                        {['all', 'critical', 'high', 'medium', 'low'].map(sev => (
                          <button key={sev} onClick={() => setSeverityFilter(sev)}
                            className={cn('px-2 py-0.5 rounded text-[10px] font-medium transition-colors',
                              severityFilter === sev
                                ? sev === 'all' ? 'bg-foreground/10 text-foreground' : SEVERITY_COLORS[sev]
                                : 'text-muted-foreground hover:text-foreground'
                            )}>
                            {sev === 'all' ? 'All' : `${sev} (${threats.filter(t => t.severity === sev).length})`}
                          </button>
                        ))}
                      </div>
                      <span className="text-[10px] text-muted-foreground ml-auto">
                        {filteredThreats.length} of {threats.length} threats
                      </span>
                    </div>

                    {/* Grouped threats */}
                    {Object.entries(threatsByCategory).map(([cat, catThreats]) => (
                      <div key={cat}>
                        <div className="flex items-center gap-2 mb-2">
                          <div className={cn('w-2.5 h-2.5 rounded-full', CATEGORY_COLORS[cat] || 'bg-gray-400')} />
                          <h3 className="text-xs font-semibold uppercase tracking-wider">{cat}</h3>
                          <span className="text-[10px] text-muted-foreground">({catThreats.length})</span>
                        </div>
                        <div className="space-y-1.5">
                          {catThreats.map(t => (
                            <div key={t.id} className="border rounded-lg overflow-hidden">
                              <button onClick={() => setExpandedThreat(expandedThreat === t.id ? null : t.id)}
                                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-left hover:bg-accent/50">
                                <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0', SEVERITY_COLORS[t.severity] || SEVERITY_COLORS.medium)}>
                                  {t.severity}
                                </span>
                                <span className="font-medium flex-1">{t.title}</span>
                                {t.risk_score && (
                                  <span className="text-[10px] text-muted-foreground shrink-0">Risk: {t.risk_score}</span>
                                )}
                                {t.mitre_technique && (
                                  <span className="text-[10px] text-purple-400 shrink-0">{t.mitre_technique}</span>
                                )}
                                {expandedThreat === t.id ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                              </button>
                              {expandedThreat === t.id && (
                                <div className="px-3 pb-3 text-xs space-y-3 border-t">
                                  <div className="mt-2">
                                    <div className="text-[10px] text-muted-foreground font-semibold">Description</div>
                                    <p>{t.description}</p>
                                  </div>
                                  <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">Attack Vector</div>
                                      <p>{t.attack_vector}</p>
                                    </div>
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">Likelihood</div>
                                      <p>{t.likelihood}/10</p>
                                    </div>
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">Impact</div>
                                      <p>{t.impact}/10</p>
                                    </div>
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">Exploitation Complexity</div>
                                      <p className={cn('inline-block px-1.5 py-0.5 rounded', COMPLEXITY_COLORS[t.exploitation_complexity || ''] || '')}>{t.exploitation_complexity || 'N/A'}</p>
                                    </div>
                                  </div>
                                  {t.prerequisites && (
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1"><Target size={10} /> Prerequisites</div>
                                      <p>{t.prerequisites}</p>
                                    </div>
                                  )}
                                  {t.real_world_examples && (
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1"><ExternalLink size={10} /> Real-World Examples</div>
                                      <p className="text-purple-400/80">{t.real_world_examples}</p>
                                    </div>
                                  )}
                                  <div>
                                    <div className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1">
                                      <Shield size={10} className="text-green-500" /> Mitigation
                                    </div>
                                    <p className="text-green-500/80">{t.mitigation}</p>
                                  </div>

                                  {/* Deep Dive Button + Results */}
                                  <div className="pt-2 border-t">
                                    {!deepDiveResults[t.id] ? (
                                      <button onClick={() => handleDeepDive(t.id)} disabled={deepDiveLoading === t.id}
                                        className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-red-600/80 text-white text-[11px] font-medium hover:bg-red-600 disabled:opacity-50">
                                        {deepDiveLoading === t.id ? <Loader2 size={12} className="animate-spin" /> : <Crosshair size={12} />}
                                        AI Exploitation Deep-Dive
                                      </button>
                                    ) : (
                                      <div className="space-y-3 bg-red-500/5 border border-red-500/20 rounded-lg p-3">
                                        <div className="flex items-center gap-1.5 text-red-400 font-semibold text-[11px]">
                                          <Crosshair size={12} /> Exploitation Deep-Dive
                                        </div>
                                        {deepDiveResults[t.id].exploitation_narrative && (
                                          <div>
                                            <div className="text-[10px] text-muted-foreground font-semibold mb-1">Exploitation Narrative</div>
                                            <p className="text-xs whitespace-pre-wrap leading-relaxed">{deepDiveResults[t.id].exploitation_narrative}</p>
                                          </div>
                                        )}
                                        {deepDiveResults[t.id].attack_chain?.length > 0 && (
                                          <div>
                                            <div className="text-[10px] text-muted-foreground font-semibold mb-1">Attack Chain</div>
                                            <div className="space-y-1.5">
                                              {deepDiveResults[t.id].attack_chain.map((step: any, i: number) => (
                                                <div key={i} className="flex gap-2 items-start">
                                                  <div className="shrink-0 w-5 h-5 rounded-full bg-red-500/20 text-red-400 flex items-center justify-center text-[10px] font-bold mt-0.5">{step.step}</div>
                                                  <div className="flex-1">
                                                    <div className="font-medium">{step.action}</div>
                                                    {step.tools && <div className="text-muted-foreground"><span className="text-purple-400">Tools:</span> {step.tools}</div>}
                                                    {step.output && <div className="text-muted-foreground"><span className="text-emerald-400">Output:</span> {step.output}</div>}
                                                    {step.detection_risk && <div className="text-muted-foreground">Detection risk: <span className={step.detection_risk === 'high' ? 'text-red-400' : step.detection_risk === 'medium' ? 'text-yellow-400' : 'text-green-400'}>{step.detection_risk}</span></div>}
                                                  </div>
                                                </div>
                                              ))}
                                            </div>
                                          </div>
                                        )}
                                        {deepDiveResults[t.id].evasion_techniques?.length > 0 && (
                                          <div>
                                            <div className="text-[10px] text-muted-foreground font-semibold mb-1">Evasion Techniques</div>
                                            <ul className="list-disc list-inside space-y-0.5">{deepDiveResults[t.id].evasion_techniques.map((e: string, i: number) => <li key={i}>{e}</li>)}</ul>
                                          </div>
                                        )}
                                        {deepDiveResults[t.id].pivot_opportunities?.length > 0 && (
                                          <div>
                                            <div className="text-[10px] text-muted-foreground font-semibold mb-1">Pivot Opportunities</div>
                                            <ul className="list-disc list-inside space-y-0.5">{deepDiveResults[t.id].pivot_opportunities.map((p: string, i: number) => <li key={i}>{p}</li>)}</ul>
                                          </div>
                                        )}
                                        {deepDiveResults[t.id].indicators_of_compromise?.length > 0 && (
                                          <div>
                                            <div className="text-[10px] text-muted-foreground font-semibold mb-1">Indicators of Compromise</div>
                                            <ul className="list-disc list-inside space-y-0.5">{deepDiveResults[t.id].indicators_of_compromise.map((ioc: string, i: number) => <li key={i}>{ioc}</li>)}</ul>
                                          </div>
                                        )}
                                        {deepDiveResults[t.id].risk_rating && (
                                          <div className="flex gap-3">
                                            <div className="text-center"><div className="text-lg font-bold text-red-400">{deepDiveResults[t.id].risk_rating.exploitability}</div><div className="text-[9px] text-muted-foreground">Exploitability</div></div>
                                            <div className="text-center"><div className="text-lg font-bold text-orange-400">{deepDiveResults[t.id].risk_rating.impact}</div><div className="text-[9px] text-muted-foreground">Impact</div></div>
                                            <div className="text-center"><div className="text-lg font-bold text-yellow-400">{deepDiveResults[t.id].risk_rating.overall}</div><div className="text-[9px] text-muted-foreground">Overall</div></div>
                                          </div>
                                        )}
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </>
                )}
              </div>
            )}

            {/* Matrix Tab */}
            {activeTab === 'matrix' && (
              <div className="p-4 overflow-auto">
                {threats.length === 0 ? (
                  <div className="text-center text-muted-foreground py-12">
                    <Grid3X3 size={32} className="mx-auto mb-2 text-purple-500/40" />
                    <p className="text-sm">No threat data for matrix</p>
                    <p className="text-xs mt-1">Generate threats first to populate the {(selected?.methodology || 'stride').toUpperCase()} matrix</p>
                  </div>
                ) : (
                  <div>
                    <div className="mb-3 flex items-center gap-2">
                      <Grid3X3 size={14} className="text-purple-400" />
                      <h3 className="text-xs font-semibold">{(selected?.methodology || 'stride').toUpperCase()} Threat Matrix — Components × Categories</h3>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs border-collapse">
                        <thead>
                          <tr>
                            <th className="text-left p-2 border-b text-muted-foreground font-medium sticky left-0 bg-card z-10 min-w-[140px]">Component</th>
                            {matrixData.categories.map(cat => (
                              <th key={cat} className="p-2 border-b text-muted-foreground font-medium text-center min-w-[100px]">
                                <div className="flex flex-col items-center gap-1">
                                  <div className={cn('w-2 h-2 rounded-full', CATEGORY_COLORS[cat.toLowerCase()] || 'bg-gray-400')} />
                                  <span className="text-[10px]">{cat}</span>
                                </div>
                              </th>
                            ))}
                            <th className="p-2 border-b text-muted-foreground font-medium text-center min-w-[60px]">Total</th>
                          </tr>
                        </thead>
                        <tbody>
                          {matrixData.rows.map(row => {
                            const total = row.cells.reduce((s, c) => s + c.count, 0);
                            return (
                              <tr key={row.component.id} className="hover:bg-accent/30">
                                <td className="p-2 border-b sticky left-0 bg-card z-10">
                                  <div className="flex items-center gap-1.5">
                                    {COMPONENT_ICONS[row.component.type] || <Box size={12} />}
                                    <span className="font-medium">{row.component.name}</span>
                                  </div>
                                </td>
                                {row.cells.map((cell, ci) => (
                                  <td key={ci} className="p-2 border-b text-center">
                                    {cell.count > 0 ? (
                                      <div className={cn('inline-flex items-center justify-center w-7 h-7 rounded-md text-[11px] font-bold',
                                        cell.maxSeverity === 'critical' ? 'bg-red-500/30 text-red-400' :
                                        cell.maxSeverity === 'high' ? 'bg-orange-500/30 text-orange-400' :
                                        cell.maxSeverity === 'medium' ? 'bg-yellow-500/30 text-yellow-400' :
                                        'bg-blue-500/20 text-blue-400'
                                      )}>
                                        {cell.count}
                                      </div>
                                    ) : (
                                      <span className="text-muted-foreground/30">—</span>
                                    )}
                                  </td>
                                ))}
                                <td className="p-2 border-b text-center font-bold text-muted-foreground">{total}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                        <tfoot>
                          <tr className="bg-muted/20">
                            <td className="p-2 font-medium sticky left-0 bg-muted/20 z-10">Total</td>
                            {matrixData.categories.map((cat, ci) => {
                              const colTotal = matrixData.rows.reduce((s, r) => s + r.cells[ci].count, 0);
                              return <td key={ci} className="p-2 text-center font-bold">{colTotal}</td>;
                            })}
                            <td className="p-2 text-center font-bold text-amber-400">{threats.length}</td>
                          </tr>
                        </tfoot>
                      </table>
                    </div>

                    {/* Matrix legend */}
                    <div className="mt-4 flex items-center gap-4 text-[10px] text-muted-foreground">
                      <span>Cell severity:</span>
                      <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-500/30" /> Critical</span>
                      <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-orange-500/30" /> High</span>
                      <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-yellow-500/30" /> Medium</span>
                      <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-blue-500/20" /> Low</span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Summary & Risk Tab */}
            {activeTab === 'summary' && (
              <div className="p-6 max-w-4xl mx-auto space-y-6 overflow-auto">
                {/* AI Summary */}
                {selected.ai_summary ? (
                  <div className="text-xs whitespace-pre-wrap leading-relaxed bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-4">
                    <div className="text-[11px] font-semibold text-emerald-500 mb-2 flex items-center gap-1.5">
                      <Brain size={13} /> AI Threat Landscape Summary
                    </div>
                    {selected.ai_summary}
                  </div>
                ) : (
                  <p className="text-xs text-muted-foreground">No summary available yet. Generate threats to get an AI summary.</p>
                )}

                {/* Key Metrics */}
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 text-center">
                  <div className="p-3 rounded-lg bg-muted/30 border">
                    <div className="text-lg font-bold">{components.length}</div>
                    <div className="text-[10px] text-muted-foreground">Components</div>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/30 border">
                    <div className="text-lg font-bold">{(selected.data_flows || []).length}</div>
                    <div className="text-[10px] text-muted-foreground">Data Flows</div>
                  </div>
                  <div className="p-3 rounded-lg bg-muted/30 border">
                    <div className="text-lg font-bold">{(selected.trust_boundaries || []).length}</div>
                    <div className="text-[10px] text-muted-foreground">Trust Boundaries</div>
                  </div>
                  <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/20">
                    <div className="text-lg font-bold text-amber-500">{threats.length}</div>
                    <div className="text-[10px] text-muted-foreground">Total Threats</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <div className="text-lg font-bold text-red-400">{summaryStats.avgRisk}</div>
                    <div className="text-[10px] text-muted-foreground">Avg Risk Score</div>
                  </div>
                </div>

                {threats.length > 0 && (
                  <>
                    {/* Severity Distribution - visual bars */}
                    <div>
                      <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5"><BarChart3 size={13} /> Severity Distribution</h3>
                      <div className="space-y-2">
                        {(['critical', 'high', 'medium', 'low'] as const).map(sev => {
                          const count = summaryStats.sevCounts[sev];
                          const pct = threats.length ? Math.round((count / threats.length) * 100) : 0;
                          return (
                            <div key={sev} className="flex items-center gap-3">
                              <span className={cn('text-[10px] font-bold uppercase w-16 text-right', SEVERITY_COLORS[sev])}>{sev}</span>
                              <div className="flex-1 bg-muted/30 rounded-full h-4 overflow-hidden">
                                <div className={cn('h-full rounded-full transition-all', sev === 'critical' ? 'bg-red-500' : sev === 'high' ? 'bg-orange-500' : sev === 'medium' ? 'bg-yellow-500' : 'bg-blue-500')}
                                  style={{ width: `${pct}%` }} />
                              </div>
                              <span className="text-xs font-medium w-12 text-right">{count} ({pct}%)</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* Top 5 Highest Risk Threats */}
                    <div>
                      <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5"><TrendingUp size={13} className="text-red-400" /> Top 5 Highest Risk Threats</h3>
                      <div className="space-y-1.5">
                        {summaryStats.topThreats.map((t, i) => (
                          <div key={t.id} className="flex items-center gap-2 p-2 rounded-lg bg-muted/20 border text-xs">
                            <span className="shrink-0 w-5 h-5 rounded-full bg-red-500/20 text-red-400 flex items-center justify-center text-[10px] font-bold">{i + 1}</span>
                            <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0', SEVERITY_COLORS[t.severity])}>{t.severity}</span>
                            <span className="font-medium flex-1 truncate">{t.title}</span>
                            {t.mitre_technique && <span className="text-[10px] text-purple-400 shrink-0">{t.mitre_technique}</span>}
                            <span className="text-muted-foreground shrink-0">Risk: {t.risk_score || '—'}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Component Risk Ranking */}
                    <div>
                      <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5"><Target size={13} className="text-amber-400" /> Component Risk Ranking</h3>
                      <div className="space-y-1.5">
                        {summaryStats.compRisk.map((c, i) => (
                          <div key={c.id} className="flex items-center gap-2 p-2 rounded-lg bg-muted/20 border text-xs">
                            <span className="shrink-0 w-5 h-5 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center text-[10px] font-bold">{i + 1}</span>
                            <div className="flex items-center gap-1.5 flex-1">
                              {COMPONENT_ICONS[c.type] || <Box size={12} />}
                              <span className="font-medium">{c.name}</span>
                              <span className="text-[10px] text-muted-foreground">({c.technology || c.type})</span>
                            </div>
                            <span className="text-[10px] text-muted-foreground shrink-0">{c.threatCount} threats</span>
                            <div className="shrink-0 w-12 bg-muted/30 rounded-full h-2 overflow-hidden">
                              <div className={cn('h-full rounded-full', c.totalRisk > 200 ? 'bg-red-500' : c.totalRisk > 100 ? 'bg-orange-500' : c.totalRisk > 50 ? 'bg-yellow-500' : 'bg-blue-500')}
                                style={{ width: `${Math.min(100, (c.totalRisk / (summaryStats.compRisk[0]?.totalRisk || 1)) * 100)}%` }} />
                            </div>
                            <span className="text-muted-foreground shrink-0 w-14 text-right">Σ {c.totalRisk}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Category Coverage */}
                    <div>
                      <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5"><Grid3X3 size={13} className="text-purple-400" /> Category Coverage</h3>
                      <div className="flex flex-wrap gap-2">
                        {(METHODOLOGY_CATEGORIES[selected?.methodology || 'stride'] || []).map(cat => {
                          const count = threats.filter(t => t.category?.toLowerCase() === cat.toLowerCase()).length;
                          return (
                            <div key={cat} className={cn('px-3 py-2 rounded-lg border text-xs', count > 0 ? 'bg-muted/20' : 'bg-muted/5 opacity-50')}>
                              <div className="flex items-center gap-1.5 mb-1">
                                <div className={cn('w-2 h-2 rounded-full', CATEGORY_COLORS[cat.toLowerCase()] || 'bg-gray-400')} />
                                <span className="font-medium">{cat}</span>
                              </div>
                              <span className={cn('text-sm font-bold', count > 0 ? 'text-foreground' : 'text-muted-foreground')}>{count}</span>
                              <span className="text-[10px] text-muted-foreground ml-1">threats</span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
