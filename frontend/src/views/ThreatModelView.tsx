import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import type { PointerEvent as ReactPointerEvent, WheelEvent as ReactWheelEvent } from 'react';
import type { PlanningProfile, ReferenceLink } from '@/types';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import { StandaloneLanding } from '@/components/StandaloneLanding';
import { ReferencePicker } from '@/components/ReferencePicker';
import { getPlanningProfileOption, PLANNING_PROFILE_OPTIONS } from '@/utils/planningProfiles';
import { mergeReferenceLinks, normalizeReferenceLinks, removeReferenceLink } from '@/utils/referenceLinks';
import { useAdvisorPageContext } from '@/hooks/useAdvisorPageContext';
import toast from 'react-hot-toast';
import {
  ShieldCheck, Plus, Trash2, Brain, Loader2, Sparkles, Database, ArrowRight,
  Server, Globe, Lock, User, Cloud, ChevronDown, ChevronRight, Link2,
  AlertTriangle, Shield, Box, X, Search, Filter, Target, BarChart3,
  Grid3X3, Eye, Zap, TrendingUp, Crosshair, ExternalLink, Info, Maximize2,
  Minimize2, Minus, Move
} from 'lucide-react';


interface Component {
  id: string;
  name: string;
  type: string;
  technology: string;
  description?: string;
  attack_surface?: string;
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
  target_type?: string;
  pasta_stage?: string;
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
  entry_surface?: string;
  trust_boundary?: string;
  business_impact?: string;
  detection_notes?: string;
  real_world_examples?: string;
  mitre_technique?: string;
  linked_node_id?: string;
  references?: ReferenceLink[];
}

interface ThreatAnalysisMetadata {
  highest_risk_areas: string[];
  attack_surface_score?: number;
  recommended_attack_priorities: string[];
  generation_warnings: string[];
  generation_strategy?: string;
  chunk_count?: number;
  pending_chunk_count?: number;
  generation_status?: string;
}

interface DFDGenerationMetadata {
  generation_warnings: string[];
  generation_strategy?: string;
  generation_status?: string;
  current_stage?: string;
  zone_count?: number;
  pending_zone_count?: number;
  pending_zone_ids: string[];
  cross_zone_flow_status?: string;
  topology_summary?: string;
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
  dfd_metadata: DFDGenerationMetadata;
  analysis_metadata: ThreatAnalysisMetadata;
  deep_dive_cache: Record<string, any>;
  created_at: string;
}

interface DfdViewport {
  scale: number;
  offsetX: number;
  offsetY: number;
}

interface DfdPanState {
  pointerId: number;
  startX: number;
  startY: number;
  originOffsetX: number;
  originOffsetY: number;
}

const DFD_COMPONENT_WIDTH = 112;
const DFD_COMPONENT_HEIGHT = 56;
const DFD_GRID_X_GAP = 180;
const DFD_GRID_Y_GAP = 140;
const DFD_LAYOUT_START_X = 80;
const DFD_LAYOUT_START_Y = 80;
const DFD_COLLISION_X_BUFFER = 28;
const DFD_COLLISION_Y_BUFFER = 40;
const DFD_VIEW_PADDING = 72;
const DFD_MIN_SCALE = 0.45;
const DFD_MAX_SCALE = 2.75;
const DFD_AUTO_FIT_MAX_SCALE = 1.6;

function clampNumber(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

function truncateCanvasText(
  context: CanvasRenderingContext2D,
  value: string,
  maxWidth: number,
): string {
  if (!value) return '';
  if (context.measureText(value).width <= maxWidth) return value;

  let current = value;
  while (current.length > 1 && context.measureText(`${current}...`).width > maxWidth) {
    current = current.slice(0, -1);
  }
  return `${current.trimEnd()}...`;
}

function getDefaultDfdPosition(index: number) {
  return {
    x: DFD_LAYOUT_START_X + (index % 4) * DFD_GRID_X_GAP,
    y: DFD_LAYOUT_START_Y + Math.floor(index / 4) * DFD_GRID_Y_GAP,
  };
}

function hasDfdComponentCollision(
  current: Pick<Component, 'x' | 'y'>,
  existing: Pick<Component, 'x' | 'y'>,
): boolean {
  return (
    current.x < existing.x + DFD_COMPONENT_WIDTH + DFD_COLLISION_X_BUFFER &&
    current.x + DFD_COMPONENT_WIDTH + DFD_COLLISION_X_BUFFER > existing.x &&
    current.y < existing.y + DFD_COMPONENT_HEIGHT + DFD_COLLISION_Y_BUFFER &&
    current.y + DFD_COMPONENT_HEIGHT + DFD_COLLISION_Y_BUFFER > existing.y
  );
}

function isDfdLayoutCrowded(components: Component[]): boolean {
  for (let index = 0; index < components.length; index += 1) {
    for (let compareIndex = index + 1; compareIndex < components.length; compareIndex += 1) {
      if (hasDfdComponentCollision(components[index], components[compareIndex])) {
        return true;
      }
    }
  }
  return false;
}

function findNearestAvailableDfdSlot(
  preferredColumn: number,
  preferredRow: number,
  occupied: Set<string>,
  maxRadius: number,
) {
  for (let radius = 0; radius <= maxRadius; radius += 1) {
    const seen = new Set<string>();
    for (let row = preferredRow - radius; row <= preferredRow + radius; row += 1) {
      for (let column = preferredColumn - radius; column <= preferredColumn + radius; column += 1) {
        const safeRow = Math.max(0, row);
        const safeColumn = Math.max(0, column);
        const key = `${safeColumn}:${safeRow}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (occupied.has(key)) continue;
        return { column: safeColumn, row: safeRow };
      }
    }
  }

  let column = Math.max(0, preferredColumn);
  const row = Math.max(0, preferredRow);
  while (occupied.has(`${column}:${row}`)) {
    column += 1;
  }
  return { column, row };
}

function getPositionedDfdComponents(components: Component[]): Component[] {
  const initialPositions = components.map((component, index) => {
    const fallback = getDefaultDfdPosition(index);
    return {
      ...component,
      x: Number.isFinite(component.x) && component.x !== 0 ? component.x : fallback.x,
      y: Number.isFinite(component.y) && component.y !== 0 ? component.y : fallback.y,
    };
  });

  if (!isDfdLayoutCrowded(initialPositions)) {
    return initialPositions;
  }

  const occupied = new Set<string>();
  const laidOut = initialPositions
    .map((component, index) => ({ component, index }))
    .sort((left, right) => (
      left.component.y === right.component.y
        ? left.component.x - right.component.x
        : left.component.y - right.component.y
    ))
    .map(({ component, index }) => {
      const fallback = getDefaultDfdPosition(index);
      const baseX = Number.isFinite(component.x) ? component.x : fallback.x;
      const baseY = Number.isFinite(component.y) ? component.y : fallback.y;
      const preferredColumn = Math.max(0, Math.round((baseX - DFD_LAYOUT_START_X) / DFD_GRID_X_GAP));
      const preferredRow = Math.max(0, Math.round((baseY - DFD_LAYOUT_START_Y) / DFD_GRID_Y_GAP));
      const slot = findNearestAvailableDfdSlot(preferredColumn, preferredRow, occupied, initialPositions.length + 4);
      occupied.add(`${slot.column}:${slot.row}`);
      return {
        ...component,
        x: DFD_LAYOUT_START_X + slot.column * DFD_GRID_X_GAP,
        y: DFD_LAYOUT_START_Y + slot.row * DFD_GRID_Y_GAP,
      };
    });

  return components.map((component) => laidOut.find((item) => item.id === component.id) || component);
}

function getDfdContentBounds(components: Component[], boundaries: TrustBoundary[]) {
  if (components.length === 0) {
    return {
      minX: 0,
      minY: 0,
      maxX: DFD_COMPONENT_WIDTH,
      maxY: DFD_COMPONENT_HEIGHT,
      width: DFD_COMPONENT_WIDTH,
      height: DFD_COMPONENT_HEIGHT,
    };
  }

  let minX = Math.min(...components.map((component) => component.x));
  let minY = Math.min(...components.map((component) => component.y));
  let maxX = Math.max(...components.map((component) => component.x + DFD_COMPONENT_WIDTH));
  let maxY = Math.max(...components.map((component) => component.y + DFD_COMPONENT_HEIGHT));

  boundaries.forEach((boundary) => {
    const boundaryComponents = components.filter((component) => boundary.component_ids?.includes(component.id));
    if (boundaryComponents.length === 0) return;

    const boundaryMinX = Math.min(...boundaryComponents.map((component) => component.x)) - 48;
    const boundaryMinY = Math.min(...boundaryComponents.map((component) => component.y)) - 44;
    const boundaryMaxX = Math.max(...boundaryComponents.map((component) => component.x + DFD_COMPONENT_WIDTH)) + 48;
    const boundaryMaxY = Math.max(...boundaryComponents.map((component) => component.y + DFD_COMPONENT_HEIGHT)) + 44;

    minX = Math.min(minX, boundaryMinX);
    minY = Math.min(minY, boundaryMinY);
    maxX = Math.max(maxX, boundaryMaxX);
    maxY = Math.max(maxY, boundaryMaxY);
  });

  return {
    minX,
    minY,
    maxX,
    maxY,
    width: Math.max(maxX - minX, DFD_COMPONENT_WIDTH),
    height: Math.max(maxY - minY, DFD_COMPONENT_HEIGHT),
  };
}

function createFittedDfdViewport(
  bounds: ReturnType<typeof getDfdContentBounds>,
  width: number,
  height: number,
): DfdViewport {
  const availableWidth = Math.max(width - DFD_VIEW_PADDING * 2, 220);
  const availableHeight = Math.max(height - DFD_VIEW_PADDING * 2, 220);
  const scale = clampNumber(
    Math.min(availableWidth / bounds.width, availableHeight / bounds.height, DFD_AUTO_FIT_MAX_SCALE),
    DFD_MIN_SCALE,
    DFD_AUTO_FIT_MAX_SCALE,
  );

  return {
    scale,
    offsetX: (width - bounds.width * scale) / 2 - bounds.minX * scale,
    offsetY: (height - bounds.height * scale) / 2 - bounds.minY * scale,
  };
}

function drawDfdGrid(
  context: CanvasRenderingContext2D,
  width: number,
  height: number,
  viewport: DfdViewport,
) {
  const gridSize = 80 * viewport.scale;
  if (!Number.isFinite(gridSize) || gridSize < 26 || gridSize > 220) return;

  const startX = ((viewport.offsetX % gridSize) + gridSize) % gridSize;
  const startY = ((viewport.offsetY % gridSize) + gridSize) % gridSize;

  context.save();
  context.strokeStyle = 'rgba(148, 163, 184, 0.08)';
  context.lineWidth = 1;

  for (let x = startX; x < width; x += gridSize) {
    context.beginPath();
    context.moveTo(x, 0);
    context.lineTo(x, height);
    context.stroke();
  }

  for (let y = startY; y < height; y += gridSize) {
    context.beginPath();
    context.moveTo(0, y);
    context.lineTo(width, y);
    context.stroke();
  }

  context.restore();
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

function resolveThreatTarget(
  targetId: string,
  components: Component[],
  dataFlows: DataFlow[],
): { label: string; type?: string } {
  if (!targetId) return { label: '' };
  const component = components.find((item) => item.id === targetId);
  if (component) {
    return { label: component.name, type: 'component' };
  }
  const flow = dataFlows.find((item) => item.id === targetId);
  if (!flow) {
    return { label: targetId };
  }
  const source = components.find((item) => item.id === flow.source)?.name || flow.source;
  const target = components.find((item) => item.id === flow.target)?.name || flow.target;
  const label = flow.label ? `${flow.label} (${source} -> ${target})` : `${source} -> ${target}`;
  return { label, type: 'data_flow' };
}

function formatThreatTargetType(targetType?: string): string {
  return targetType === 'data_flow' ? 'Data Flow' : 'Component';
}

function threatRiskScore(threat: Threat): number {
  return threat.risk_score || (Number(threat.likelihood) || 5) * (Number(threat.impact) || 5);
}

function threatDimensionLabel(methodology?: string): string {
  return methodology === 'pasta' ? 'Stage' : 'Category';
}

function threatDimensionValue(threat: Threat, methodology?: string): string {
  if (methodology === 'pasta') {
    return threat.pasta_stage?.trim() || 'Unassigned';
  }
  return threat.category?.trim() || 'Other';
}

function threatSecondaryCategory(threat: Threat, methodology?: string): string {
  if (methodology === 'pasta') {
    return threat.category?.trim() || '';
  }
  return '';
}

function normalizeThreatModel(data: any): ThreatModelData {
  const methodology = typeof data?.methodology === 'string' ? data.methodology : 'stride';
  const components = Array.isArray(data?.components)
    ? data.components.filter(isRecord).map((item: Record<string, any>) => ({
        id: typeof item.id === 'string' ? item.id : crypto.randomUUID(),
        name: typeof item.name === 'string' ? item.name : 'Unnamed component',
        type: typeof item.type === 'string' ? item.type : 'service',
        technology: typeof item.technology === 'string' ? item.technology : '',
        description: typeof item.description === 'string' ? item.description : undefined,
        attack_surface: typeof item.attack_surface === 'string' ? item.attack_surface : undefined,
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
    ? data.threats.filter(isRecord).map((item: Record<string, any>) => {
        const target = resolveThreatTarget(
          typeof item.component_id === 'string' ? item.component_id : '',
          components,
          dataFlows,
        );
        return {
          id: typeof item.id === 'string' ? item.id : crypto.randomUUID(),
          component_id: typeof item.component_id === 'string' ? item.component_id : '',
          component_name: typeof item.component_name === 'string' && item.component_name.trim()
            ? item.component_name
            : target.label,
          target_type: typeof item.target_type === 'string' ? item.target_type : target.type,
          pasta_stage: typeof item.pasta_stage === 'string' ? item.pasta_stage : undefined,
          category: typeof item.category === 'string' ? item.category : '',
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
          entry_surface: typeof item.entry_surface === 'string' ? item.entry_surface : undefined,
          trust_boundary: typeof item.trust_boundary === 'string' ? item.trust_boundary : undefined,
          business_impact: typeof item.business_impact === 'string' ? item.business_impact : undefined,
          detection_notes: typeof item.detection_notes === 'string' ? item.detection_notes : undefined,
          real_world_examples: typeof item.real_world_examples === 'string' ? item.real_world_examples : undefined,
          mitre_technique: typeof item.mitre_technique === 'string' ? item.mitre_technique : undefined,
          linked_node_id: typeof item.linked_node_id === 'string' ? item.linked_node_id : undefined,
          references: normalizeReferenceLinks(item.references),
        };
      })
    : [];

  return {
    ...data,
    id: typeof data?.id === 'string' ? data.id : crypto.randomUUID(),
    project_id: typeof data?.project_id === 'string' ? data.project_id : '',
    name: typeof data?.name === 'string' ? data.name : 'Untitled Threat Model',
    description: typeof data?.description === 'string' ? data.description : '',
    methodology,
    scope: typeof data?.scope === 'string' ? data.scope : '',
    components,
    data_flows: dataFlows,
    trust_boundaries: trustBoundaries,
    threats,
    ai_summary: typeof data?.ai_summary === 'string' ? data.ai_summary : '',
    dfd_metadata: isRecord(data?.dfd_metadata)
      ? {
          generation_warnings: stringList(data.dfd_metadata.generation_warnings),
          generation_strategy: typeof data.dfd_metadata.generation_strategy === 'string'
            ? data.dfd_metadata.generation_strategy
            : undefined,
          generation_status: typeof data.dfd_metadata.generation_status === 'string'
            ? data.dfd_metadata.generation_status
            : undefined,
          current_stage: typeof data.dfd_metadata.current_stage === 'string'
            ? data.dfd_metadata.current_stage
            : undefined,
          zone_count: typeof data.dfd_metadata.zone_count === 'number'
            ? data.dfd_metadata.zone_count
            : undefined,
          pending_zone_count: typeof data.dfd_metadata.pending_zone_count === 'number'
            ? data.dfd_metadata.pending_zone_count
            : undefined,
          pending_zone_ids: stringList(data.dfd_metadata.pending_zone_ids),
          cross_zone_flow_status: typeof data.dfd_metadata.cross_zone_flow_status === 'string'
            ? data.dfd_metadata.cross_zone_flow_status
            : undefined,
          topology_summary: typeof data.dfd_metadata.topology_summary === 'string'
            ? data.dfd_metadata.topology_summary
            : undefined,
        }
      : {
          generation_warnings: [],
          pending_zone_ids: [],
        },
    analysis_metadata: isRecord(data?.analysis_metadata)
      ? {
          highest_risk_areas: stringList(data.analysis_metadata.highest_risk_areas),
          attack_surface_score: typeof data.analysis_metadata.attack_surface_score === 'number'
            ? data.analysis_metadata.attack_surface_score
            : undefined,
          recommended_attack_priorities: stringList(data.analysis_metadata.recommended_attack_priorities),
          generation_warnings: stringList(data.analysis_metadata.generation_warnings),
          generation_strategy: typeof data.analysis_metadata.generation_strategy === 'string'
            ? data.analysis_metadata.generation_strategy
            : undefined,
          chunk_count: typeof data.analysis_metadata.chunk_count === 'number'
            ? data.analysis_metadata.chunk_count
            : undefined,
          pending_chunk_count: typeof data.analysis_metadata.pending_chunk_count === 'number'
            ? data.analysis_metadata.pending_chunk_count
            : undefined,
          generation_status: typeof data.analysis_metadata.generation_status === 'string'
            ? data.analysis_metadata.generation_status
            : undefined,
        }
      : {
          highest_risk_areas: [],
          recommended_attack_priorities: [],
          generation_warnings: [],
        },
    deep_dive_cache: isRecord(data?.deep_dive_cache)
      ? Object.fromEntries(Object.entries(data.deep_dive_cache).filter(([, value]) => isRecord(value)))
      : {},
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
  // PASTA
  'attack simulation': 'bg-fuchsia-500',
  'vulnerability analysis': 'bg-rose-500',
  'risk analysis': 'bg-amber-500',
  exploitation: 'bg-red-500',
  impact: 'bg-cyan-500',
  // LINDDUN
  linkability: 'bg-purple-500',
  identifiability: 'bg-red-500',
  'non-repudiation': 'bg-orange-500',
  detectability: 'bg-yellow-500',
  disclosure: 'bg-blue-500',
  unawareness: 'bg-pink-500',
  'non-compliance': 'bg-cyan-500',
};

const METHODOLOGY_DIMENSIONS: Record<string, string[]> = {
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
  const { currentProject, setNodes } = useStore();
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
  const [operatorGuidance, setOperatorGuidance] = useState('');
  const [planningProfile, setPlanningProfile] = useState<PlanningProfile>('planning_first');
  const [activeTab, setActiveTab] = useState<'dfd' | 'threats' | 'matrix' | 'summary'>('dfd');
  const [expandedThreat, setExpandedThreat] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [deepDiveLoading, setDeepDiveLoading] = useState<string | null>(null);
  const [deepDiveResults, setDeepDiveResults] = useState<Record<string, any>>({});
  const [fullAnalysisStage, setFullAnalysisStage] = useState<'idle' | 'dfd' | 'threats'>('idle');
  const [isDfdFullscreen, setIsDfdFullscreen] = useState(false);
  const [isDfdPanning, setIsDfdPanning] = useState(false);
  const [dfdViewport, setDfdViewport] = useState<DfdViewport>({ scale: 1, offsetX: 32, offsetY: 32 });
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const dfdContainerRef = useRef<HTMLDivElement>(null);
  const dfdPanStateRef = useRef<DfdPanState | null>(null);
  const selectedPlanningProfile = useMemo(() => getPlanningProfileOption(planningProfile), [planningProfile]);
  const positionedDfdComponents = useMemo(
    () => getPositionedDfdComponents(selected?.components || []),
    [selected?.components],
  );
  const dfdLayoutSignature = useMemo(() => {
    if (!selected) return '';
    return JSON.stringify({
      components: positionedDfdComponents.map((component) => [
        component.id,
        component.x,
        component.y,
        component.type,
        component.name,
      ]),
      flows: (selected.data_flows || []).map((flow) => [flow.id, flow.source, flow.target, flow.protocol, flow.label]),
      boundaries: (selected.trust_boundaries || []).map((boundary) => [
        boundary.id,
        boundary.name,
        ...(boundary.component_ids || []),
      ]),
    });
  }, [positionedDfdComponents, selected]);

  // Keep the shared node store aligned with the active project.
  useEffect(() => {
    if (!currentProject) {
      setNodes([]);
      return;
    }
    api.listNodes(currentProject.id)
      .then((data) => setNodes(Array.isArray(data) ? data : []))
      .catch(() => setNodes([]));
  }, [currentProject?.id, setNodes]);

  useEffect(() => {
    setSystemDesc(selected?.scope || '');
  }, [selected?.id, selected?.scope]);

  useEffect(() => {
    setDeepDiveResults(selected?.deep_dive_cache || {});
  }, [selected?.id, selected?.deep_dive_cache]);

  useEffect(() => {
    if (activeTab !== 'dfd' && isDfdFullscreen) {
      setIsDfdFullscreen(false);
    }
  }, [activeTab, isDfdFullscreen]);

  useEffect(() => {
    if (!selected && isDfdFullscreen) {
      setIsDfdFullscreen(false);
    }
  }, [isDfdFullscreen, selected]);

  useEffect(() => {
    if (!isDfdFullscreen) return;

    const previousOverflow = document.body.style.overflow;
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setIsDfdFullscreen(false);
      }
    };

    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [isDfdFullscreen]);

  const loadModels = useCallback(async () => {
    if (!currentProject) return;
    try {
      const data = await api.listThreatModels(currentProject.id);
      const normalized = Array.isArray(data) ? data.map((item) => normalizeThreatModel(item)) : [];
      const {
        pendingViewSelection: currentPendingViewSelection,
        clearPendingViewSelection: clearPendingSelection,
      } = useStore.getState();
      const requestedThreatModelId = currentPendingViewSelection?.view === 'threat_model'
        ? currentPendingViewSelection.artifactId
        : null;
      setThreatModels(normalized);
      setSelected((current) => (
        requestedThreatModelId
          ? normalized.find((item) => item.id === requestedThreatModelId) || normalized[0] || null
          : current
            ? normalized.find((item) => item.id === current.id) || null
            : current
      ));
      if (requestedThreatModelId) {
        clearPendingSelection();
      }
    } catch (e: any) { toast.error(e.message); }
  }, [currentProject]);

  useEffect(() => {
    if (currentProject) loadModels();
  }, [currentProject, loadModels]);

  const syncThreatModel = useCallback((updated: ThreatModelData) => {
    setSelected(updated);
    setThreatModels((current) => {
      const index = current.findIndex((item) => item.id === updated.id);
      if (index === -1) {
        return [updated, ...current];
      }
      return current.map((item) => (item.id === updated.id ? updated : item));
    });
  }, []);

  const persistThreatReferences = useCallback(async (nextThreats: Threat[]) => {
    if (!selected) return;
    const optimistic = normalizeThreatModel({ ...selected, threats: nextThreats });
    syncThreatModel(optimistic);
    try {
      const updated = await api.updateThreatModel(selected.id, { threats: nextThreats });
      syncThreatModel(normalizeThreatModel(updated));
    } catch (error: any) {
      toast.error(error.message);
      void loadModels();
    }
  }, [loadModels, selected, syncThreatModel]);

  const addThreatReference = useCallback((threatId: string, item: {
    framework: string;
    ref_id: string;
    ref_name: string;
    score: number;
    reasons: string[];
  }) => {
    if (!selected) return;
    const nextThreats = selected.threats.map((threat) => (
      threat.id === threatId
        ? { ...threat, references: mergeReferenceLinks(threat.references || [], [item]) }
        : threat
    ));
    void persistThreatReferences(nextThreats);
  }, [persistThreatReferences, selected]);

  const removeThreatReference = useCallback((threatId: string, framework: string, refId: string) => {
    if (!selected) return;
    const nextThreats = selected.threats.map((threat) => (
      threat.id === threatId
        ? { ...threat, references: removeReferenceLink(threat.references || [], framework, refId) }
        : threat
    ));
    void persistThreatReferences(nextThreats);
  }, [persistThreatReferences, selected]);

  const handleCreate = async () => {
    if (!currentProject) { toast('Open a project workspace to create threat models', { icon: '📂' }); return; }
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
    toast('DFD generation started. Complex systems can take several minutes. You can keep using other tools while it runs.', {
      duration: 5000,
    });
    try {
      const result = await api.aiGenerateDFD(selected.id, {
        system_description: systemDesc,
        user_guidance: operatorGuidance,
        planning_profile: planningProfile,
      });
      syncThreatModel(normalizeThreatModel(result));
      toast.success('DFD generated');
    } catch (e: any) { toast.error(e.message); }
    finally { setDfdLoading(false); }
  };

  const handleGenerateThreats = async () => {
    if (!selected) return;
    setThreatLoading(true);
    toast('Threat generation started. Large systems can take around 10-20 minutes, sometimes longer. You can keep using other tools while it runs.', {
      duration: 6000,
    });
    try {
      const result = await api.aiGenerateThreats(selected.id, {
        user_guidance: operatorGuidance,
        planning_profile: planningProfile,
      });
      const normalized = normalizeThreatModel(result);
      syncThreatModel(normalized);
      setActiveTab('threats');
      toast.success(`AI found ${normalized.threats?.length || 0} threats`);
    } catch (e: any) { toast.error(e.message); }
    finally { setThreatLoading(false); }
  };

  const handleFullAnalysis = async () => {
    if (!currentProject) { toast('Open a project workspace to run full analysis', { icon: '📂' }); return; }
    if (!systemDesc.trim()) return;
    setFullLoading(true);
    setFullAnalysisStage('dfd');
    try {
      const created = normalizeThreatModel(await api.createThreatModel({
        project_id: currentProject.id,
        name: createName || 'AI Threat Model',
        methodology: createMethodology,
        scope: systemDesc,
        description: systemDesc.slice(0, 200),
      }));
      setThreatModels((current) => [created, ...current.filter((item) => item.id !== created.id)]);
      setSelected(created);
      setActiveTab('dfd');

      toast('Full analysis started. Large systems can take around 10-20 minutes, sometimes longer. You can keep using other tools while it runs.', {
        duration: 6000,
      });

      setDfdLoading(true);
      const dfdResult = normalizeThreatModel(await api.aiGenerateDFD(created.id, {
        system_description: systemDesc,
        user_guidance: operatorGuidance,
        planning_profile: planningProfile,
      }));
      syncThreatModel(dfdResult);
      setDfdLoading(false);

      if (dfdResult.dfd_metadata?.generation_status && dfdResult.dfd_metadata.generation_status !== 'completed') {
        setActiveTab('dfd');
        throw new Error('DFD generation is still incomplete. Open this model and use Resume DFD to finish the analysis.');
      }

      setFullAnalysisStage('threats');
      setThreatLoading(true);
      const threatResult = normalizeThreatModel(await api.aiGenerateThreats(created.id, {
        user_guidance: operatorGuidance,
        planning_profile: planningProfile,
      }));
      syncThreatModel(threatResult);
      setActiveTab('threats');
      toast.success('Full AI analysis complete');
    } catch (e: any) {
      toast.error(e.message);
      void loadModels();
    } finally {
      setDfdLoading(false);
      setThreatLoading(false);
      setFullLoading(false);
      setFullAnalysisStage('idle');
    }
  };

  const handleLinkToTree = async () => {
    if (!selected || !currentProject) return;
    const threatIds = visibleUnlinkedThreats.map((threat) => threat.id);
    if (threatIds.length === 0) return;
    setLinkLoading(true);
    try {
      const [linkResult, updatedThreatModel, updatedNodes] = await Promise.all([
        api.linkThreatsToTree(selected.id, { threat_ids: threatIds }),
        api.getThreatModel(selected.id),
        api.listNodes(currentProject.id),
      ]);
      syncThreatModel(normalizeThreatModel(updatedThreatModel));
      setNodes(Array.isArray(updatedNodes) ? updatedNodes : []);
      toast.success(`Linked ${linkResult.created} threats${linkResult.skipped ? `, skipped ${linkResult.skipped} already linked` : ''}`);
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

  const handleResetDfdView = useCallback(() => {
    const container = dfdContainerRef.current;
    if (!container || positionedDfdComponents.length === 0) return;

    setDfdViewport(createFittedDfdViewport(
      getDfdContentBounds(positionedDfdComponents, selected?.trust_boundaries || []),
      container.clientWidth,
      container.clientHeight,
    ));
  }, [positionedDfdComponents, selected?.trust_boundaries]);

  const zoomDfd = useCallback((factor: number, focusX?: number, focusY?: number) => {
    const container = dfdContainerRef.current;
    if (!container) return;

    const centerX = focusX ?? container.clientWidth / 2;
    const centerY = focusY ?? container.clientHeight / 2;

    setDfdViewport((current) => {
      const nextScale = clampNumber(current.scale * factor, DFD_MIN_SCALE, DFD_MAX_SCALE);
      if (Math.abs(nextScale - current.scale) < 0.001) {
        return current;
      }

      const worldX = (centerX - current.offsetX) / current.scale;
      const worldY = (centerY - current.offsetY) / current.scale;

      return {
        scale: nextScale,
        offsetX: centerX - worldX * nextScale,
        offsetY: centerY - worldY * nextScale,
      };
    });
  }, []);

  const handleDfdPointerDown = useCallback((event: ReactPointerEvent<HTMLCanvasElement>) => {
    if (event.pointerType === 'mouse' && event.button !== 0) return;
    const canvas = canvasRef.current;
    if (!canvas) return;

    canvas.setPointerCapture(event.pointerId);
    dfdPanStateRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      startY: event.clientY,
      originOffsetX: dfdViewport.offsetX,
      originOffsetY: dfdViewport.offsetY,
    };
    setIsDfdPanning(true);
  }, [dfdViewport.offsetX, dfdViewport.offsetY]);

  const handleDfdPointerMove = useCallback((event: ReactPointerEvent<HTMLCanvasElement>) => {
    const panState = dfdPanStateRef.current;
    if (!panState || panState.pointerId !== event.pointerId) return;

    setDfdViewport((current) => ({
      ...current,
      offsetX: panState.originOffsetX + (event.clientX - panState.startX),
      offsetY: panState.originOffsetY + (event.clientY - panState.startY),
    }));
  }, []);

  const handleDfdPointerUp = useCallback((event: ReactPointerEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (canvas?.hasPointerCapture(event.pointerId)) {
      canvas.releasePointerCapture(event.pointerId);
    }
    dfdPanStateRef.current = null;
    setIsDfdPanning(false);
  }, []);

  const handleDfdWheel = useCallback((event: ReactWheelEvent<HTMLCanvasElement>) => {
    const container = dfdContainerRef.current;
    if (!container) return;

    event.preventDefault();
    const rect = container.getBoundingClientRect();
    zoomDfd(
      event.deltaY < 0 ? 1.12 : 0.9,
      event.clientX - rect.left,
      event.clientY - rect.top,
    );
  }, [zoomDfd]);

  // Interactive canvas-based DFD rendering
  const drawDFD = useCallback(() => {
    const canvas = canvasRef.current;
    if (!canvas || !selected) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const components = positionedDfdComponents;
    const flows = selected.data_flows || [];
    const boundaries = selected.trust_boundaries || [];
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    const dpr = window.devicePixelRatio || 1;

    if (!width || !height) return;

    canvas.width = Math.floor(width * dpr);
    canvas.height = Math.floor(height * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    drawDfdGrid(ctx, width, height, dfdViewport);
    ctx.save();
    ctx.translate(dfdViewport.offsetX, dfdViewport.offsetY);
    ctx.scale(dfdViewport.scale, dfdViewport.scale);

    boundaries.forEach((boundary) => {
      const boundaryComponents = components.filter((component) => boundary.component_ids?.includes(component.id));
      if (boundaryComponents.length === 0) return;

      const minX = Math.min(...boundaryComponents.map((component) => component.x)) - 48;
      const minY = Math.min(...boundaryComponents.map((component) => component.y)) - 44;
      const maxX = Math.max(...boundaryComponents.map((component) => component.x + DFD_COMPONENT_WIDTH)) + 48;
      const maxY = Math.max(...boundaryComponents.map((component) => component.y + DFD_COMPONENT_HEIGHT)) + 44;

      ctx.save();
      ctx.setLineDash([10, 6]);
      ctx.strokeStyle = '#fb923c';
      ctx.lineWidth = 1.5;
      ctx.fillStyle = 'rgba(251, 146, 60, 0.08)';
      ctx.beginPath();
      ctx.roundRect(minX, minY, maxX - minX, maxY - minY, 16);
      ctx.fill();
      ctx.stroke();
      ctx.setLineDash([]);

      ctx.font = '11px sans-serif';
      const boundaryLabel = truncateCanvasText(ctx, boundary.name, Math.max(maxX - minX - 16, 48));
      const boundaryLabelWidth = ctx.measureText(boundaryLabel).width + 14;
      ctx.fillStyle = '#111827';
      ctx.beginPath();
      ctx.roundRect(minX + 10, minY - 16, boundaryLabelWidth, 18, 9);
      ctx.fill();
      ctx.fillStyle = '#fdba74';
      ctx.fillText(boundaryLabel, minX + 17, minY - 3);
      ctx.restore();
    });

    flows.forEach((flow) => {
      const source = components.find((component) => component.id === flow.source);
      const target = components.find((component) => component.id === flow.target);
      if (!source || !target) return;

      const flowThreats = (selected.threats || []).filter((threat: Threat) => (
        threat.target_type === 'data_flow' && threat.component_id === flow.id
      ));

      const sx = source.x + DFD_COMPONENT_WIDTH / 2;
      const sy = source.y + DFD_COMPONENT_HEIGHT / 2;
      const tx = target.x + DFD_COMPONENT_WIDTH / 2;
      const ty = target.y + DFD_COMPONENT_HEIGHT / 2;

      ctx.beginPath();
      ctx.moveTo(sx, sy);
      ctx.lineTo(tx, ty);
      ctx.strokeStyle = '#818cf8';
      ctx.lineWidth = 1.5;
      ctx.stroke();

      const angle = Math.atan2(ty - sy, tx - sx);
      const arrowLen = 10;
      ctx.beginPath();
      ctx.moveTo(tx, ty);
      ctx.lineTo(tx - arrowLen * Math.cos(angle - 0.45), ty - arrowLen * Math.sin(angle - 0.45));
      ctx.lineTo(tx - arrowLen * Math.cos(angle + 0.45), ty - arrowLen * Math.sin(angle + 0.45));
      ctx.closePath();
      ctx.fillStyle = '#6366f1';
      ctx.fill();

      const mx = (sx + tx) / 2;
      const my = (sy + ty) / 2;
      if (flow.protocol) {
        ctx.font = '10px sans-serif';
        const protocolLabel = truncateCanvasText(ctx, flow.protocol, 120);
        const labelWidth = ctx.measureText(protocolLabel).width + 12;
        ctx.fillStyle = '#0f172a';
        ctx.beginPath();
        ctx.roundRect(mx - labelWidth / 2, my - 18, labelWidth, 16, 8);
        ctx.fill();
        ctx.fillStyle = '#c7d2fe';
        ctx.textAlign = 'center';
        ctx.fillText(protocolLabel, mx, my - 7);
        ctx.textAlign = 'start';
      }

      if (flowThreats.length > 0) {
        const hasCritical = flowThreats.some((threat: Threat) => threat.severity === 'critical');
        const hasHigh = flowThreats.some((threat: Threat) => threat.severity === 'high');
        const badgeColor = hasCritical ? '#ef4444' : hasHigh ? '#f97316' : '#eab308';
        ctx.fillStyle = badgeColor;
        ctx.beginPath();
        ctx.roundRect(mx - 12, my + 4, 24, 14, 7);
        ctx.fill();
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 9px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(String(flowThreats.length), mx, my + 14);
        ctx.textAlign = 'start';
      }
    });

    components.forEach((component) => {
      ctx.fillStyle = '#0f172a';
      ctx.strokeStyle = '#334155';
      ctx.lineWidth = 1.25;
      ctx.beginPath();
      ctx.roundRect(component.x, component.y, DFD_COMPONENT_WIDTH, DFD_COMPONENT_HEIGHT, 10);
      ctx.fill();
      ctx.stroke();

      const typeColor =
        component.type === 'database' ? '#22c55e' :
        component.type === 'external' ? '#f59e0b' :
        component.type === 'web_app' ? '#3b82f6' :
        component.type === 'api' ? '#8b5cf6' :
        component.type === 'user' ? '#ec4899' : '#6b7280';
      ctx.fillStyle = typeColor;
      ctx.beginPath();
      ctx.roundRect(component.x, component.y, DFD_COMPONENT_WIDTH, 5, [10, 10, 0, 0]);
      ctx.fill();

      ctx.fillStyle = '#e2e8f0';
      ctx.font = 'bold 11px sans-serif';
      ctx.textAlign = 'center';
      ctx.fillText(
        truncateCanvasText(ctx, component.name || '', DFD_COMPONENT_WIDTH - 16),
        component.x + DFD_COMPONENT_WIDTH / 2,
        component.y + 26,
      );
      ctx.fillStyle = '#94a3b8';
      ctx.font = '9px sans-serif';
      ctx.fillText(
        truncateCanvasText(ctx, component.type || '', DFD_COMPONENT_WIDTH - 16),
        component.x + DFD_COMPONENT_WIDTH / 2,
        component.y + 41,
      );
      ctx.textAlign = 'start';

      const componentThreats = (selected.threats || []).filter((threat: Threat) => threat.component_id === component.id);
      if (componentThreats.length > 0) {
        const hasCritical = componentThreats.some((threat) => threat.severity === 'critical');
        const hasHigh = componentThreats.some((threat) => threat.severity === 'high');
        const badgeColor = hasCritical ? '#ef4444' : hasHigh ? '#f97316' : '#eab308';
        const badgeX = component.x + DFD_COMPONENT_WIDTH - 10;
        const badgeY = component.y - 6;
        ctx.beginPath();
        ctx.arc(badgeX, badgeY, 10, 0, Math.PI * 2);
        ctx.fillStyle = badgeColor;
        ctx.fill();
        ctx.fillStyle = '#fff';
        ctx.font = 'bold 9px sans-serif';
        ctx.textAlign = 'center';
        ctx.fillText(String(componentThreats.length), badgeX, badgeY + 3);
        ctx.textAlign = 'start';
      }
    });
    ctx.restore();
  }, [dfdViewport, positionedDfdComponents, selected]);

  useEffect(() => {
    if (!selected || activeTab !== 'dfd') return;
    drawDFD();
  }, [activeTab, drawDFD]);

  useEffect(() => {
    if (!selected || activeTab !== 'dfd' || positionedDfdComponents.length === 0) return;
    const frame = window.requestAnimationFrame(() => {
      handleResetDfdView();
    });
    return () => window.cancelAnimationFrame(frame);
  }, [activeTab, dfdLayoutSignature, handleResetDfdView, isDfdFullscreen, positionedDfdComponents.length]);

  useEffect(() => {
    if (activeTab !== 'dfd') return;
    const container = dfdContainerRef.current;
    if (!container) return;

    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', drawDFD);
      return () => window.removeEventListener('resize', drawDFD);
    }

    const observer = new ResizeObserver(() => drawDFD());
    observer.observe(container);
    return () => observer.disconnect();
  }, [activeTab, drawDFD, isDfdFullscreen]);

  const components = selected?.components || [];
  const threats = selected?.threats || [];
  const dfdMetadata = selected?.dfd_metadata || {
    generation_warnings: [],
    pending_zone_ids: [],
  };
  const analysisMetadata = selected?.analysis_metadata || {
    highest_risk_areas: [],
    recommended_attack_priorities: [],
    generation_warnings: [],
  };
  const selectedMethodology = selected?.methodology || 'stride';
  const dimensionLabel = threatDimensionLabel(selectedMethodology);
  const dfdComplete = !dfdMetadata.generation_status || dfdMetadata.generation_status === 'completed';
  const dfdRunning = dfdLoading || dfdMetadata.generation_status === 'running';
  const threatsRunning = threatLoading || analysisMetadata.generation_status === 'running';
  const generationInProgress = dfdRunning || threatsRunning || fullLoading;
  const generationStatusTitle = fullLoading
    ? fullAnalysisStage === 'threats'
      ? 'Full analysis is generating threats.'
      : 'Full analysis is building the DFD.'
    : threatsRunning
      ? 'Threat generation is running.'
      : dfdRunning
        ? 'DFD generation is running.'
        : '';
  const generationStatusDetail = fullLoading || threatsRunning
    ? 'Large systems can take around 10-20 minutes, sometimes longer. You can switch to other tools while this runs; progress is saved to this threat model.'
    : 'Complex systems can take several minutes. You can switch to other tools while this runs; progress is saved to this threat model.';
  const advisorContext = useMemo(() => ({
    view: 'threat_model' as const,
    title: selected ? `Threat Model: ${selected.name}` : 'Threat Modeling',
    summary: selected
      ? `Reviewing the ${selectedMethodology.toUpperCase()} threat model on the ${activeTab} tab.`
      : 'Threat modeling workspace for DFD generation, threat analysis, and risk review.',
    packets: [
      selected ? `Methodology: ${selectedMethodology.toUpperCase()}` : '',
      selected ? `Active tab: ${activeTab}` : '',
      selected ? `Components: ${selected.components.length}` : '',
      selected ? `Data flows: ${selected.data_flows.length}` : '',
      selected ? `Threats: ${selected.threats.length}` : '',
      activeTab === 'threats' ? `Threat severity filter: ${severityFilter}` : '',
      dfdRunning ? 'DFD generation is running' : '',
      threatsRunning ? 'Threat generation is running' : '',
    ],
  }), [activeTab, dfdRunning, selected, selectedMethodology, severityFilter, threatsRunning]);
  useAdvisorPageContext(advisorContext);

  useEffect(() => {
    if (!selected?.id || !generationInProgress) return;

    let cancelled = false;
    const refreshSelected = async () => {
      try {
        const refreshed = await api.getThreatModel(selected.id);
        if (!cancelled) {
          syncThreatModel(normalizeThreatModel(refreshed));
        }
      } catch {
        // Ignore transient refresh failures while generation is still running.
      }
    };

    void refreshSelected();
    const intervalId = window.setInterval(() => {
      void refreshSelected();
    }, 8000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, [generationInProgress, selected?.id, syncThreatModel]);

  // Filtered threats
  const filteredThreats = useMemo(() => threats.filter(t => {
    if (severityFilter !== 'all' && t.severity !== severityFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return t.title?.toLowerCase().includes(q) || t.description?.toLowerCase().includes(q)
        || t.category?.toLowerCase().includes(q) || t.pasta_stage?.toLowerCase().includes(q)
        || t.attack_vector?.toLowerCase().includes(q);
    }
    return true;
  }), [threats, severityFilter, searchQuery]);

  const componentThreats = useMemo(
    () => threats.filter((threat) => threat.target_type !== 'data_flow'),
    [threats],
  );

  const dataFlowThreats = useMemo(
    () => threats.filter((threat) => threat.target_type === 'data_flow'),
    [threats],
  );

  const visibleUnlinkedThreats = useMemo(
    () => filteredThreats.filter((threat) => !threat.linked_node_id),
    [filteredThreats],
  );

  const threatsByDimension = useMemo(() => {
    const groups: Array<{ key: string; label: string; threats: Threat[] }> = [];
    const byKey: Record<string, { key: string; label: string; threats: Threat[] }> = {};
    filteredThreats.forEach((threat) => {
      const label = threatDimensionValue(threat, selectedMethodology);
      const key = label.toLowerCase();
      if (!byKey[key]) {
        byKey[key] = { key, label, threats: [] };
        groups.push(byKey[key]);
      }
      byKey[key].threats.push(threat);
    });
    return groups.sort((left, right) => (
      right.threats.length - left.threats.length || left.label.localeCompare(right.label)
    ));
  }, [filteredThreats, selectedMethodology]);

  // Threats per component (for DFD badges + matrix)
  const threatsByComponent = useMemo(() => {
    const map: Record<string, Threat[]> = {};
    componentThreats.forEach(t => {
      const cid = t.component_id || 'unknown';
      if (!map[cid]) map[cid] = [];
      map[cid].push(t);
    });
    return map;
  }, [componentThreats]);

  const threatsByDataFlow = useMemo(() => {
    const map: Record<string, Threat[]> = {};
    dataFlowThreats.forEach((threat) => {
      const flowId = threat.component_id || 'unknown';
      if (!map[flowId]) map[flowId] = [];
      map[flowId].push(threat);
    });
    return map;
  }, [dataFlowThreats]);

  // Matrix data: components × methodology categories
  const componentMatrixData = useMemo(() => {
    const cats = METHODOLOGY_DIMENSIONS[selectedMethodology] || METHODOLOGY_DIMENSIONS.stride;
    return {
      categories: cats,
      rows: components.map(c => ({
        component: c,
        cells: cats.map(cat => {
          const matching = componentThreats.filter(t => (
            t.component_id === c.id && threatDimensionValue(t, selectedMethodology).toLowerCase() === cat.toLowerCase()
          ));
          const maxSev = matching.reduce((best, t) => {
            const order = ['critical', 'high', 'medium', 'low'];
            return order.indexOf(t.severity) < order.indexOf(best) ? t.severity : best;
          }, 'low' as string);
          return { count: matching.length, maxSeverity: matching.length > 0 ? maxSev : null, threats: matching };
        }),
      })),
    };
  }, [components, componentThreats, selectedMethodology]);

  const flowMatrixData = useMemo(() => {
    const cats = METHODOLOGY_DIMENSIONS[selectedMethodology] || METHODOLOGY_DIMENSIONS.stride;
    const flows = selected?.data_flows || [];
    return {
      categories: cats,
      rows: flows.map((flow) => ({
        flow,
        cells: cats.map((cat) => {
          const matching = dataFlowThreats.filter((threat) => (
            threat.component_id === flow.id && threatDimensionValue(threat, selectedMethodology).toLowerCase() === cat.toLowerCase()
          ));
          const maxSev = matching.reduce((best, threat) => {
            const order = ['critical', 'high', 'medium', 'low'];
            return order.indexOf(threat.severity) < order.indexOf(best) ? threat.severity : best;
          }, 'low' as string);
          return { count: matching.length, maxSeverity: matching.length > 0 ? maxSev : null, threats: matching };
        }),
      })).filter((row) => row.cells.some((cell) => cell.count > 0)),
    };
  }, [dataFlowThreats, selected?.data_flows, selectedMethodology]);

  // Summary stats
  const summaryStats = useMemo(() => {
    const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    let totalRisk = 0;
    threats.forEach(t => {
      if (t.severity in sevCounts) sevCounts[t.severity as keyof typeof sevCounts]++;
      totalRisk += threatRiskScore(t);
    });
    const avgRisk = threats.length ? Math.round(totalRisk / threats.length) : 0;

    // Top 5 threats by risk
    const topThreats = [...threats].sort((a, b) => threatRiskScore(b) - threatRiskScore(a)).slice(0, 5);

    // Component risk ranking
    const compRisk = components.map(c => {
      const ct = threatsByComponent[c.id] || [];
      const risk = ct.reduce((sum, t) => sum + threatRiskScore(t), 0);
      return { ...c, threatCount: ct.length, totalRisk: risk, avgRisk: ct.length ? Math.round(risk / ct.length) : 0 };
    }).filter((item) => item.threatCount > 0).sort((a, b) => b.totalRisk - a.totalRisk);

    const flowRisk = (selected?.data_flows || []).map((flow) => {
      const ft = threatsByDataFlow[flow.id] || [];
      const risk = ft.reduce((sum, threat) => sum + threatRiskScore(threat), 0);
      const sourceName = components.find((component) => component.id === flow.source)?.name || flow.source;
      const targetName = components.find((component) => component.id === flow.target)?.name || flow.target;
      const label = flow.label ? `${flow.label} (${sourceName} -> ${targetName})` : `${sourceName} -> ${targetName}`;
      return {
        ...flow,
        label,
        threatCount: ft.length,
        totalRisk: risk,
        avgRisk: ft.length ? Math.round(risk / ft.length) : 0,
      };
    }).filter((item) => item.threatCount > 0).sort((a, b) => b.totalRisk - a.totalRisk);

    return { sevCounts, avgRisk, topThreats, compRisk, flowRisk, totalRisk };
  }, [threats, components, selected?.data_flows, threatsByComponent, threatsByDataFlow]);

  const threatGenerationLabel = analysisMetadata.generation_status === 'partial' || analysisMetadata.generation_status === 'running'
    ? 'Resume Threats'
    : 'AI Find Threats';

  if (!currentProject) {
    return (
      <StandaloneLanding
        icon={<ShieldCheck size={28} className="text-emerald-500" />}
        title="Threat Modeling Workspace"
        description="Generate project-scoped threat models from a system description, review the resulting DFD and threats, then link validated findings back into the project attack tree."
        features={[
          { icon: <Database size={15} className="text-emerald-500" />, title: 'DFD Generation', desc: 'Build data flow diagrams for project components, trust boundaries, and data flows.' },
          { icon: <Shield size={15} className="text-emerald-500" />, title: 'Threat Discovery', desc: 'Run STRIDE, PASTA, or LINDDUN analyses with risk scoring, references, and narratives.' },
          { icon: <Link2 size={15} className="text-emerald-500" />, title: 'Tree Linking', desc: 'Link unlinked threats back into the project attack tree as actionable nodes.' },
        ]}
      />
    );
  }

  return (
    <>
      {isDfdFullscreen && (
        <div className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm" />
      )}
      <div className="h-full flex flex-col relative">
      {/* Toolbar */}
      <div className="border-b px-4 py-2 flex items-center gap-3 bg-card shrink-0 flex-wrap">
        <ShieldCheck size={16} className="text-emerald-500" />
        <h2 className="font-semibold text-sm">Threat Modeling</h2>
        <div className="border-l h-5 mx-1" />

        <select value={selected?.id || ''} onChange={(e) => setSelected(threatModels.find(t => t.id === e.target.value) || null)}
          className="select-field text-xs px-2 py-1">
          <option value="">Select model...</option>
          {threatModels.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
        </select>

        <select value={createMethodology} onChange={(e) => setCreateMethodology(e.target.value)}
          className="select-field text-xs px-2 py-1">
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

        <select
          value={planningProfile}
          onChange={(e) => setPlanningProfile(e.target.value as PlanningProfile)}
          className="select-field text-xs px-2 py-1"
        >
          {PLANNING_PROFILE_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>

        <input
          value={operatorGuidance}
          onChange={(e) => setOperatorGuidance(e.target.value)}
          placeholder="Optional analyst guidance..."
          className="text-xs bg-transparent border rounded px-2 py-1 min-w-[220px] flex-1 max-w-sm"
        />

        {selected && components.length > 0 && (
          <button onClick={handleGenerateThreats} disabled={threatLoading || !dfdComplete}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-amber-600 text-white text-xs font-medium hover:bg-amber-700 disabled:opacity-50">
            {threatLoading ? <Loader2 size={13} className="animate-spin" /> : <AlertTriangle size={13} />}
            {threatLoading ? 'Generating Threats...' : dfdComplete ? threatGenerationLabel : 'Finish DFD First'}
          </button>
        )}

        {selected && threats.length > 0 && (
          <button onClick={handleLinkToTree} disabled={linkLoading || visibleUnlinkedThreats.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-purple-600 text-white text-xs font-medium hover:bg-purple-700 disabled:opacity-50">
            {linkLoading ? <Loader2 size={13} className="animate-spin" /> : <Link2 size={13} />}
            Link Unlinked Threats
          </button>
        )}

        {selected && (
          <button onClick={() => handleDelete(selected.id)} className="p-1 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive">
            <Trash2 size={14} />
          </button>
        )}
      </div>

      {selected && generationInProgress && (
        <div className="border-b border-amber-500/20 bg-amber-500/5 px-4 py-2">
          <div className="flex items-start gap-2 text-xs">
            <Info size={13} className="mt-0.5 shrink-0 text-amber-500" />
            <div className="space-y-0.5">
              <div className="font-medium text-amber-500">{generationStatusTitle}</div>
              <div className="text-muted-foreground">{generationStatusDetail}</div>
            </div>
          </div>
        </div>
      )}

      {/* Content */}
      {!selected ? (
        <div className="flex-1 flex items-center justify-center text-muted-foreground p-6">
          <div className="text-center max-w-lg">
            <ShieldCheck size={40} className="mx-auto mb-3 text-emerald-500/50" />
            <p className="text-sm mb-4">Describe your system and let AI generate a threat model</p>
            <p className="text-xs text-muted-foreground mb-4">{selectedPlanningProfile.label}: {selectedPlanningProfile.description}</p>

            <textarea value={systemDesc} onChange={(e) => setSystemDesc(e.target.value)}
              placeholder="Describe the system to threat-model, e.g.: A web app with a React frontend, Node.js API server, PostgreSQL database, and external payment gateway. Users authenticate via OAuth2..."
              className="w-full h-32 text-xs bg-transparent border rounded-lg p-3 resize-none focus:border-emerald-500 outline-none mb-3"
            />
            <button onClick={handleFullAnalysis} disabled={fullLoading || !systemDesc.trim()}
              className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-emerald-600 text-white text-sm font-medium hover:bg-emerald-700 disabled:opacity-50 mx-auto">
              {fullLoading ? <Loader2 size={15} className="animate-spin" /> : <Sparkles size={15} />}
              {fullLoading
                ? fullAnalysisStage === 'threats'
                  ? 'Generating Threats...'
                  : 'Building DFD...'
                : 'AI Full Threat Analysis'}
            </button>
            <p className="mt-3 text-[11px] text-muted-foreground">
              Large systems can take around 10-20 minutes, sometimes longer. You can use other areas of the app while it runs.
            </p>
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
                      {dfdLoading
                        ? 'Generating DFD...'
                        : dfdMetadata.generation_status === 'partial' || dfdMetadata.generation_status === 'running'
                          ? 'Resume DFD'
                          : 'Generate DFD'}
                    </button>
                  </div>
                  {(dfdMetadata.topology_summary || dfdMetadata.generation_warnings.length > 0 || dfdMetadata.zone_count || dfdMetadata.generation_status) && (
                    <div className="mt-3 rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3 text-xs space-y-2">
                      <div className="flex items-center gap-2 text-emerald-400 font-semibold">
                        <Info size={12} /> DFD Generation Notes
                      </div>
                      {(dfdMetadata.generation_strategy || dfdMetadata.zone_count || dfdMetadata.generation_status) && (
                        <div className="text-muted-foreground">
                          Strategy: {dfdMetadata.generation_strategy || 'standard'}
                          {dfdMetadata.zone_count ? ` (${dfdMetadata.zone_count} zones)` : ''}
                          {dfdMetadata.generation_status ? `, status: ${dfdMetadata.generation_status}` : ''}
                          {dfdMetadata.current_stage ? `, stage: ${dfdMetadata.current_stage}` : ''}
                          {typeof dfdMetadata.pending_zone_count === 'number' && dfdMetadata.pending_zone_count > 0
                            ? `, pending zones: ${dfdMetadata.pending_zone_count}`
                            : ''}
                          {dfdMetadata.cross_zone_flow_status ? `, cross-zone flows: ${dfdMetadata.cross_zone_flow_status}` : ''}
                        </div>
                      )}
                      {dfdMetadata.topology_summary && (
                        <div className="text-muted-foreground whitespace-pre-wrap leading-relaxed">
                          {dfdMetadata.topology_summary}
                        </div>
                      )}
                      {dfdMetadata.generation_warnings.length > 0 && (
                        <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                          {dfdMetadata.generation_warnings.map((warning, index) => <li key={index}>{warning}</li>)}
                        </ul>
                      )}
                    </div>
                  )}
                </div>

                {components.length === 0 ? (
                  <div className="flex-1 flex items-center justify-center text-muted-foreground">
                    <p className="text-xs">
                      {dfdMetadata.generation_status === 'partial'
                        ? 'DFD generation is partial. Click Resume DFD to finish the remaining zones.'
                        : 'Describe your system above and click Generate DFD'}
                    </p>
                  </div>
                ) : (
                  <div
                    className={cn(
                      'flex-1 relative min-h-[360px] overflow-hidden',
                      isDfdFullscreen && 'fixed inset-4 z-50 rounded-2xl border border-border/50 bg-background shadow-2xl',
                    )}
                  >
                    <div
                      ref={dfdContainerRef}
                      className="absolute inset-0 overflow-hidden bg-slate-950/[0.03]"
                    >
                      <canvas
                        ref={canvasRef}
                        className={cn('w-full h-full touch-none select-none', isDfdPanning ? 'cursor-grabbing' : 'cursor-grab')}
                        style={{ imageRendering: 'auto' }}
                        onPointerDown={handleDfdPointerDown}
                        onPointerMove={handleDfdPointerMove}
                        onPointerUp={handleDfdPointerUp}
                        onPointerLeave={handleDfdPointerUp}
                        onPointerCancel={handleDfdPointerUp}
                        onWheel={handleDfdWheel}
                        onDoubleClick={handleResetDfdView}
                      />

                      <div className="absolute top-3 left-3 z-10 flex flex-wrap items-center gap-2 rounded-xl border border-border/70 bg-card/95 px-3 py-2 text-[11px] shadow-lg backdrop-blur">
                        <button
                          onClick={() => zoomDfd(0.9)}
                          className="rounded-md border border-border/70 p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                          title="Zoom out"
                        >
                          <Minus size={13} />
                        </button>
                        <span className="min-w-[48px] text-center font-medium text-foreground">
                          {Math.round(dfdViewport.scale * 100)}%
                        </span>
                        <button
                          onClick={() => zoomDfd(1.12)}
                          className="rounded-md border border-border/70 p-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                          title="Zoom in"
                        >
                          <Plus size={13} />
                        </button>
                        <button
                          onClick={handleResetDfdView}
                          className="flex items-center gap-1 rounded-md border border-border/70 px-2 py-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                          title="Fit the diagram to the available space"
                        >
                          <Crosshair size={12} />
                          Fit
                        </button>
                        <button
                          onClick={() => setIsDfdFullscreen((current) => !current)}
                          className="flex items-center gap-1 rounded-md border border-border/70 px-2 py-1 text-muted-foreground hover:bg-accent hover:text-foreground"
                          title={isDfdFullscreen ? 'Exit full screen' : 'Open full screen'}
                        >
                          {isDfdFullscreen ? <Minimize2 size={12} /> : <Maximize2 size={12} />}
                          {isDfdFullscreen ? 'Exit' : 'Full screen'}
                        </button>
                        <div className="hidden xl:flex items-center gap-1.5 border-l border-border/70 pl-2 text-[10px] text-muted-foreground">
                          <Move size={11} />
                          Drag to pan
                        </div>
                        <div className="hidden xl:block text-[10px] text-muted-foreground">
                          Wheel to zoom {isDfdFullscreen ? ' • Esc to close' : ''}
                        </div>
                      </div>

                      {/* Topology legend with threat counts */}
                      <div className={cn(
                        'absolute top-3 right-3 z-10 bg-card/92 backdrop-blur border rounded-lg p-2 text-[10px] space-y-2 overflow-y-auto max-w-[280px]',
                        isDfdFullscreen ? 'max-h-[calc(100vh-9rem)]' : 'max-h-[320px]',
                      )}>
                        <div className="text-[9px] text-muted-foreground font-semibold mb-1 uppercase tracking-wider">Components</div>
                      {components.map(c => {
                        const ct = threatsByComponent[c.id] || [];
                        const hasCrit = ct.some(t => t.severity === 'critical');
                        const hasHigh = ct.some(t => t.severity === 'high');
                        return (
                          <div key={c.id} className="space-y-0.5">
                            <div className="flex items-center gap-1.5">
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
                            {(c.attack_surface || c.technology) && (
                              <div className="pl-4 text-[9px] text-muted-foreground truncate">
                                {c.attack_surface || c.technology}
                              </div>
                            )}
                          </div>
                        );
                      })}
                      {dataFlowThreats.length > 0 && (
                        <div className="pt-1 border-t border-border/60">
                          <div className="text-[9px] text-muted-foreground font-semibold mb-1 uppercase tracking-wider">Data Flows</div>
                          <div className="space-y-1">
                            {(selected.data_flows || []).filter((flow) => (threatsByDataFlow[flow.id] || []).length > 0).map((flow) => {
                              const flowThreatList = threatsByDataFlow[flow.id] || [];
                              const hasCrit = flowThreatList.some((threat) => threat.severity === 'critical');
                              const hasHigh = flowThreatList.some((threat) => threat.severity === 'high');
                              const sourceName = components.find((component) => component.id === flow.source)?.name || flow.source;
                              const targetName = components.find((component) => component.id === flow.target)?.name || flow.target;
                              const flowLabel = flow.label ? `${flow.label} (${sourceName} -> ${targetName})` : `${sourceName} -> ${targetName}`;
                              return (
                                <div key={flow.id} className="space-y-0.5">
                                  <div className="flex items-center gap-1.5">
                                    <ArrowRight size={11} className="text-indigo-400 shrink-0" />
                                    <span className="flex-1 truncate">{flowLabel}</span>
                                    <span className={cn('px-1 py-0.5 rounded text-[9px] font-bold',
                                      hasCrit ? 'bg-red-500/20 text-red-400' : hasHigh ? 'bg-orange-500/20 text-orange-400' : 'bg-yellow-500/20 text-yellow-400'
                                    )}>
                                      {flowThreatList.length}
                                    </span>
                                  </div>
                                  <div className="pl-4 text-[9px] text-muted-foreground truncate">
                                    {flow.protocol || 'Unspecified protocol'}
                                  </div>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}
                    </div>
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
                    <p className="text-xs mt-1">Generate a DFD first, then click <strong>{threatGenerationLabel}</strong></p>
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
                    {threatsByDimension.map(({ key, label, threats: groupedThreats }) => (
                      <div key={key}>
                        <div className="flex items-center gap-2 mb-2">
                          <div className={cn('w-2.5 h-2.5 rounded-full', CATEGORY_COLORS[key] || 'bg-gray-400')} />
                          <h3 className="text-xs font-semibold uppercase tracking-wider">{label}</h3>
                          <span className="text-[10px] text-muted-foreground">({groupedThreats.length})</span>
                        </div>
                        <div className="space-y-1.5">
                          {groupedThreats.map(t => (
                            <div key={t.id} className="border rounded-lg overflow-hidden">
                              <button onClick={() => setExpandedThreat(expandedThreat === t.id ? null : t.id)}
                                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-left hover:bg-accent/50">
                                <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-bold shrink-0', SEVERITY_COLORS[t.severity] || SEVERITY_COLORS.medium)}>
                                  {t.severity}
                                </span>
                                <div className="flex-1 min-w-0">
                                  <div className="font-medium truncate">{t.title}</div>
                                  {t.component_name && (
                                    <div className="text-[10px] text-muted-foreground truncate">
                                      Target: {t.component_name}
                                    </div>
                                  )}
                                </div>
                                <span className="px-1.5 py-0.5 rounded border text-[10px] text-muted-foreground shrink-0">
                                  {formatThreatTargetType(t.target_type)}
                                </span>
                                {selectedMethodology === 'pasta' && t.pasta_stage && (
                                  <span className="px-1.5 py-0.5 rounded border text-[10px] text-muted-foreground shrink-0">
                                    {t.pasta_stage}
                                  </span>
                                )}
                                {selectedMethodology === 'pasta' && threatSecondaryCategory(t, selectedMethodology) && (
                                  <span className="px-1.5 py-0.5 rounded bg-muted/40 text-[10px] text-muted-foreground shrink-0">
                                    {threatSecondaryCategory(t, selectedMethodology)}
                                  </span>
                                )}
                                {t.linked_node_id && (
                                  <span className="px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px] font-medium shrink-0">
                                    Linked
                                  </span>
                                )}
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
                                      <div className="text-[10px] text-muted-foreground font-semibold">Target</div>
                                      <p>{t.component_name || t.component_id || 'Unmapped target'}</p>
                                    </div>
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">Target Type</div>
                                      <p>{formatThreatTargetType(t.target_type)}</p>
                                    </div>
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">
                                        {selectedMethodology === 'pasta' ? 'PASTA Stage' : 'Category'}
                                      </div>
                                      <p>{threatDimensionValue(t, selectedMethodology)}</p>
                                    </div>
                                    {selectedMethodology === 'pasta' && (
                                      <div>
                                        <div className="text-[10px] text-muted-foreground font-semibold">Technical Category</div>
                                        <p>{threatSecondaryCategory(t, selectedMethodology) || 'Not specified'}</p>
                                      </div>
                                    )}
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">Attack Vector</div>
                                      <p>{t.attack_vector}</p>
                                    </div>
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">Entry Surface</div>
                                      <p>{t.entry_surface || 'Not specified'}</p>
                                    </div>
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">Trust Boundary</div>
                                      <p>{t.trust_boundary || 'Not specified'}</p>
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
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold">Tree Link</div>
                                      <p>{t.linked_node_id ? 'Linked to attack tree' : 'Not linked yet'}</p>
                                    </div>
                                  </div>
                                  {t.business_impact && (
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1"><BarChart3 size={10} /> Business Impact</div>
                                      <p>{t.business_impact}</p>
                                    </div>
                                  )}
                                  {t.detection_notes && (
                                    <div>
                                      <div className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1"><Eye size={10} /> Detection Notes</div>
                                      <p>{t.detection_notes}</p>
                                    </div>
                                  )}
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

                                  <div className="space-y-2">
                                    <div className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1">
                                      <Info size={10} /> References
                                    </div>
                                    <ReferencePicker
                                      artifactType="threat_model"
                                      contextPreset={currentProject?.context_preset || ''}
                                      objective={currentProject?.root_objective || selected?.name || ''}
                                      scope={selected?.scope || currentProject?.description || ''}
                                      targetKind={t.target_type || 'threat'}
                                      targetSummary={[
                                        t.title,
                                        t.description,
                                        t.component_name,
                                        t.attack_vector,
                                        t.mitre_technique,
                                      ].filter(Boolean).join(' ')}
                                      placeholder="Search references for this threat"
                                      onAdd={(item) => addThreatReference(t.id, item)}
                                    />
                                    {(t.references || []).length > 0 ? (
                                      <div className="space-y-1">
                                        {(t.references || []).map((reference) => (
                                          <div key={`${reference.framework}:${reference.ref_id}`} className="flex items-start gap-2 rounded border bg-background/40 px-2 py-1.5">
                                            <div className="min-w-0 flex-1">
                                              <div className="flex items-center gap-2 text-[10px]">
                                                <span className="font-semibold uppercase tracking-wide text-muted-foreground">{reference.framework}</span>
                                                <span className="font-mono text-purple-400">{reference.ref_id}</span>
                                              </div>
                                              <div className="mt-0.5 text-[11px] font-medium">{reference.ref_name}</div>
                                              {(reference.source || reference.confidence != null || reference.rationale) && (
                                                <div className="mt-0.5 text-[10px] text-muted-foreground leading-4">
                                                  {reference.source ? `Source: ${reference.source}` : ''}
                                                  {reference.confidence != null ? `${reference.source ? ' · ' : ''}${Math.round(reference.confidence * 100)}%` : ''}
                                                  {reference.rationale ? ` · ${reference.rationale}` : ''}
                                                </div>
                                              )}
                                            </div>
                                            <button
                                              type="button"
                                              onClick={() => removeThreatReference(t.id, reference.framework, reference.ref_id)}
                                              className="rounded p-1 text-muted-foreground transition-colors hover:bg-destructive/10 hover:text-destructive"
                                              title="Remove reference"
                                            >
                                              <X size={10} />
                                            </button>
                                          </div>
                                        ))}
                                      </div>
                                    ) : (
                                      <p className="text-[11px] text-muted-foreground">No references linked to this threat yet.</p>
                                    )}
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
                  <div className="space-y-6">
                    <div className="mb-3 flex items-center gap-2">
                      <Grid3X3 size={14} className="text-purple-400" />
                      <h3 className="text-xs font-semibold">{selectedMethodology.toUpperCase()} Threat Matrix — Components × {selectedMethodology === 'pasta' ? 'Stages' : 'Categories'}</h3>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs border-collapse">
                        <thead>
                          <tr>
                            <th className="text-left p-2 border-b text-muted-foreground font-medium sticky left-0 bg-card z-10 min-w-[140px]">Component</th>
                            {componentMatrixData.categories.map(cat => (
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
                          {componentMatrixData.rows.map(row => {
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
                            {componentMatrixData.categories.map((_, ci) => {
                              const colTotal = componentMatrixData.rows.reduce((s, r) => s + r.cells[ci].count, 0);
                              return <td key={ci} className="p-2 text-center font-bold">{colTotal}</td>;
                            })}
                            <td className="p-2 text-center font-bold text-amber-400">{componentThreats.length}</td>
                          </tr>
                        </tfoot>
                      </table>
                    </div>

                    {flowMatrixData.rows.length > 0 && (
                      <div>
                        <div className="mb-3 flex items-center gap-2">
                          <ArrowRight size={14} className="text-indigo-400" />
                          <h3 className="text-xs font-semibold">{selectedMethodology.toUpperCase()} Threat Matrix — Data Flows × {selectedMethodology === 'pasta' ? 'Stages' : 'Categories'}</h3>
                        </div>
                        <div className="overflow-x-auto">
                          <table className="w-full text-xs border-collapse">
                            <thead>
                              <tr>
                                <th className="text-left p-2 border-b text-muted-foreground font-medium sticky left-0 bg-card z-10 min-w-[220px]">Data Flow</th>
                                {flowMatrixData.categories.map(cat => (
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
                              {flowMatrixData.rows.map((row) => {
                                const total = row.cells.reduce((sum, cell) => sum + cell.count, 0);
                                const sourceName = components.find((component) => component.id === row.flow.source)?.name || row.flow.source;
                                const targetName = components.find((component) => component.id === row.flow.target)?.name || row.flow.target;
                                const flowLabel = row.flow.label ? `${row.flow.label} (${sourceName} -> ${targetName})` : `${sourceName} -> ${targetName}`;
                                return (
                                  <tr key={row.flow.id} className="hover:bg-accent/30">
                                    <td className="p-2 border-b sticky left-0 bg-card z-10">
                                      <div className="flex items-center gap-1.5">
                                        <ArrowRight size={12} className="text-indigo-400 shrink-0" />
                                        <div className="min-w-0">
                                          <div className="font-medium truncate">{flowLabel}</div>
                                          <div className="text-[10px] text-muted-foreground truncate">{row.flow.protocol || 'Unspecified protocol'}</div>
                                        </div>
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
                                {flowMatrixData.categories.map((_, ci) => {
                                  const colTotal = flowMatrixData.rows.reduce((sum, row) => sum + row.cells[ci].count, 0);
                                  return <td key={ci} className="p-2 text-center font-bold">{colTotal}</td>;
                                })}
                                <td className="p-2 text-center font-bold text-indigo-400">{dataFlowThreats.length}</td>
                              </tr>
                            </tfoot>
                          </table>
                        </div>
                      </div>
                    )}

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

                {(analysisMetadata.generation_warnings.length > 0 || analysisMetadata.chunk_count || analysisMetadata.generation_strategy) && (
                  <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-4 text-xs space-y-2">
                    <div className="flex items-center gap-2 text-amber-400 font-semibold">
                      <Info size={12} /> Generation Notes
                    </div>
                    {(analysisMetadata.generation_strategy || analysisMetadata.chunk_count) && (
                      <div className="text-muted-foreground">
                        Strategy: {analysisMetadata.generation_strategy || 'standard'}
                        {analysisMetadata.chunk_count ? ` (${analysisMetadata.chunk_count} primary chunks)` : ''}
                        {analysisMetadata.generation_status ? `, status: ${analysisMetadata.generation_status}` : ''}
                        {typeof analysisMetadata.pending_chunk_count === 'number' && analysisMetadata.pending_chunk_count > 0
                          ? `, pending: ${analysisMetadata.pending_chunk_count}`
                          : ''}
                      </div>
                    )}
                    {analysisMetadata.generation_warnings.length > 0 && (
                      <ul className="list-disc list-inside space-y-1 text-muted-foreground">
                        {analysisMetadata.generation_warnings.map((warning, index) => <li key={index}>{warning}</li>)}
                      </ul>
                    )}
                  </div>
                )}

                {/* Key Metrics */}
                <div className="grid grid-cols-2 md:grid-cols-6 gap-3 text-center">
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
                  <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/20">
                    <div className="text-lg font-bold text-purple-400">{analysisMetadata.attack_surface_score ?? '—'}</div>
                    <div className="text-[10px] text-muted-foreground">Attack Surface Score</div>
                  </div>
                  <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20">
                    <div className="text-lg font-bold text-red-400">{summaryStats.avgRisk}</div>
                    <div className="text-[10px] text-muted-foreground">Avg Risk Score</div>
                  </div>
                </div>

                {threats.length > 0 && (
                  <>
                    {(analysisMetadata.highest_risk_areas.length > 0 || analysisMetadata.recommended_attack_priorities.length > 0) && (
                      <div className="grid md:grid-cols-2 gap-4">
                        {analysisMetadata.highest_risk_areas.length > 0 && (
                          <div className="rounded-lg border bg-muted/20 p-4">
                            <h3 className="text-xs font-semibold mb-2 flex items-center gap-1.5"><Zap size={13} className="text-red-400" /> Highest-Risk Areas</h3>
                            <ul className="list-disc list-inside space-y-1 text-xs text-muted-foreground">
                              {analysisMetadata.highest_risk_areas.map((item, index) => <li key={index}>{item}</li>)}
                            </ul>
                          </div>
                        )}
                        {analysisMetadata.recommended_attack_priorities.length > 0 && (
                          <div className="rounded-lg border bg-muted/20 p-4">
                            <h3 className="text-xs font-semibold mb-2 flex items-center gap-1.5"><Crosshair size={13} className="text-amber-400" /> Recommended Attack Priorities</h3>
                            <ul className="list-disc list-inside space-y-1 text-xs text-muted-foreground">
                              {analysisMetadata.recommended_attack_priorities.map((item, index) => <li key={index}>{item}</li>)}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}

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
                            <div className="flex-1 min-w-0">
                              <div className="font-medium truncate">{t.title}</div>
                              {t.component_name && <div className="text-[10px] text-muted-foreground truncate">{t.component_name}</div>}
                            </div>
                            <span className="px-1.5 py-0.5 rounded border text-[10px] text-muted-foreground shrink-0">
                              {formatThreatTargetType(t.target_type)}
                            </span>
                            {t.mitre_technique && <span className="text-[10px] text-purple-400 shrink-0">{t.mitre_technique}</span>}
                            <span className="text-muted-foreground shrink-0">Risk: {threatRiskScore(t)}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Component Risk Ranking */}
                    <div>
                      <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5"><Target size={13} className="text-amber-400" /> Component Risk Ranking</h3>
                      {summaryStats.compRisk.length > 0 ? (
                        <div className="space-y-1.5">
                          {summaryStats.compRisk.map((c, i) => (
                            <div key={c.id} className="flex items-center gap-2 p-2 rounded-lg bg-muted/20 border text-xs">
                              <span className="shrink-0 w-5 h-5 rounded-full bg-amber-500/20 text-amber-400 flex items-center justify-center text-[10px] font-bold">{i + 1}</span>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-1.5">
                                  {COMPONENT_ICONS[c.type] || <Box size={12} />}
                                  <span className="font-medium">{c.name}</span>
                                  <span className="text-[10px] text-muted-foreground">({c.technology || c.type})</span>
                                </div>
                                {(c.attack_surface || c.description) && (
                                  <div className="text-[10px] text-muted-foreground truncate">
                                    {c.attack_surface || c.description}
                                  </div>
                                )}
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
                      ) : (
                        <p className="text-xs text-muted-foreground">No component-targeted threats in this model.</p>
                      )}
                    </div>

                    {summaryStats.flowRisk.length > 0 && (
                      <div>
                        <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5"><ArrowRight size={13} className="text-indigo-400" /> Data Flow Risk Ranking</h3>
                        <div className="space-y-1.5">
                          {summaryStats.flowRisk.map((flow, i) => (
                            <div key={flow.id} className="flex items-center gap-2 p-2 rounded-lg bg-muted/20 border text-xs">
                              <span className="shrink-0 w-5 h-5 rounded-full bg-indigo-500/20 text-indigo-400 flex items-center justify-center text-[10px] font-bold">{i + 1}</span>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-1.5">
                                  <ArrowRight size={12} className="text-indigo-400 shrink-0" />
                                  <span className="font-medium truncate">{flow.label}</span>
                                </div>
                                <div className="text-[10px] text-muted-foreground truncate">
                                  {flow.protocol || 'Unspecified protocol'}
                                  {flow.data_classification ? ` · ${flow.data_classification}` : ''}
                                </div>
                              </div>
                              <span className="text-[10px] text-muted-foreground shrink-0">{flow.threatCount} threats</span>
                              <div className="shrink-0 w-12 bg-muted/30 rounded-full h-2 overflow-hidden">
                                <div className={cn('h-full rounded-full', flow.totalRisk > 200 ? 'bg-red-500' : flow.totalRisk > 100 ? 'bg-orange-500' : flow.totalRisk > 50 ? 'bg-yellow-500' : 'bg-blue-500')}
                                  style={{ width: `${Math.min(100, (flow.totalRisk / (summaryStats.flowRisk[0]?.totalRisk || 1)) * 100)}%` }} />
                              </div>
                              <span className="text-muted-foreground shrink-0 w-14 text-right">Σ {flow.totalRisk}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Category / Stage Coverage */}
                    <div>
                      <h3 className="text-xs font-semibold mb-3 flex items-center gap-1.5"><Grid3X3 size={13} className="text-purple-400" /> {dimensionLabel} Coverage</h3>
                      <div className="flex flex-wrap gap-2">
                        {(METHODOLOGY_DIMENSIONS[selectedMethodology] || []).map(cat => {
                          const count = threats.filter(t => threatDimensionValue(t, selectedMethodology).toLowerCase() === cat.toLowerCase()).length;
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
    </>
  );
}
