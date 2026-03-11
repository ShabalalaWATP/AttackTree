import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import type { PlanningProfile } from '@/types';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { cn } from '@/utils/cn';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import { getPlanningProfileOption, PLANNING_PROFILE_OPTIONS } from '@/utils/planningProfiles';
import toast from 'react-hot-toast';
import {
  Network, Plus, Trash2, Sparkles, Loader2, X, BookOpen,
  ChevronRight, ChevronDown, Server, Database, Monitor, Shield,
  Cloud, Lock, Cpu, HardDrive, Radio, Building2, Users, Cog,
  Globe, Terminal, Wifi, Camera, Printer, Phone, ChevronsDown, ChevronsUp,
  Brain, Zap, List, GitFork
} from 'lucide-react';

/* ───── Types ───── */

interface InfraNode {
  id: string;
  parent_id: string | null;
  label: string;
  category: string;
  description: string;
  icon_hint: string;
  children_loaded: boolean;
  manually_added: boolean;
  position_x?: number | null;
  position_y?: number | null;
}

interface InfraMapData {
  id: string;
  project_id: string | null;
  name: string;
  description: string;
  nodes: InfraNode[];
  ai_summary: string;
  analysis_metadata?: {
    generation_strategy?: string;
    generation_status?: string;
    branch_count?: number;
    completed_branch_count?: number;
    failed_branch_count?: number;
    generation_warnings?: string[];
    last_generation_strategy?: string;
    last_generation_status?: string;
    last_generation_warnings?: string[];
  };
  created_at: string;
  updated_at: string;
}

type LayoutMode = 'tree' | 'mindmap';

type InfraNodeDraft = Pick<InfraNode, 'label' | 'category' | 'description' | 'icon_hint'>;

/* ───── Icon map ───── */

const ICON_MAP: Record<string, React.ReactNode> = {
  server: <Server size={14} />,
  database: <Database size={14} />,
  monitor: <Monitor size={14} />,
  network: <Network size={14} />,
  shield: <Shield size={14} />,
  cloud: <Cloud size={14} />,
  lock: <Lock size={14} />,
  cpu: <Cpu size={14} />,
  'hard-drive': <HardDrive size={14} />,
  radio: <Radio size={14} />,
  building: <Building2 size={14} />,
  users: <Users size={14} />,
  cog: <Cog size={14} />,
  globe: <Globe size={14} />,
  terminal: <Terminal size={14} />,
  wifi: <Wifi size={14} />,
  camera: <Camera size={14} />,
  printer: <Printer size={14} />,
  phone: <Phone size={14} />,
  router: <Network size={14} />,
  firewall: <Shield size={14} />,
  switch: <Network size={14} />,
};

const ICON_MAP_SM: Record<string, React.ReactNode> = {
  server: <Server size={11} />,
  database: <Database size={11} />,
  monitor: <Monitor size={11} />,
  network: <Network size={11} />,
  shield: <Shield size={11} />,
  cloud: <Cloud size={11} />,
  lock: <Lock size={11} />,
  cpu: <Cpu size={11} />,
  'hard-drive': <HardDrive size={11} />,
  radio: <Radio size={11} />,
  building: <Building2 size={11} />,
  users: <Users size={11} />,
  cog: <Cog size={11} />,
  globe: <Globe size={11} />,
  terminal: <Terminal size={11} />,
  wifi: <Wifi size={11} />,
  camera: <Camera size={11} />,
  printer: <Printer size={11} />,
  phone: <Phone size={11} />,
  router: <Network size={11} />,
  firewall: <Shield size={11} />,
  switch: <Network size={11} />,
};

const CATEGORY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  infrastructure: { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/30' },
  hardware: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' },
  software: { bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' },
  networking: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  security: { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/30' },
  ot_ics: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
  cloud: { bg: 'bg-sky-500/10', text: 'text-sky-400', border: 'border-sky-500/30' },
  service: { bg: 'bg-indigo-500/10', text: 'text-indigo-400', border: 'border-indigo-500/30' },
  endpoint: { bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
  storage: { bg: 'bg-teal-500/10', text: 'text-teal-400', border: 'border-teal-500/30' },
  physical: { bg: 'bg-stone-500/10', text: 'text-stone-400', border: 'border-stone-500/30' },
  personnel: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/30' },
  process: { bg: 'bg-violet-500/10', text: 'text-violet-400', border: 'border-violet-500/30' },
  general: { bg: 'bg-gray-500/10', text: 'text-gray-400', border: 'border-gray-500/30' },
};

const CAT_SVG_COLORS: Record<string, string> = {
  infrastructure: '#94a3b8', hardware: '#22d3ee', software: '#a78bfa',
  networking: '#60a5fa', security: '#4ade80', ot_ics: '#fb923c',
  cloud: '#38bdf8', service: '#818cf8', endpoint: '#fbbf24',
  storage: '#2dd4bf', physical: '#a8a29e', personnel: '#fb7185',
  process: '#8b5cf6', general: '#9ca3af',
};

const CATEGORY_OPTIONS = Object.keys(CATEGORY_COLORS);
const ICON_OPTIONS = Object.keys(ICON_MAP);

/* ───── Mind Map Layout Engine ───── */

const MM_NODE_W = 170;
const MM_NODE_H = 40;
const MM_H_GAP = 70;
const MM_V_GAP = 10;
const MM_PAD = 40;

interface LayoutItem {
  id: string;
  x: number;
  y: number;
  node: InfraNode;
}
interface LayoutEdge {
  parentId: string;
  childId: string;
}

interface MindMapPosition {
  x: number;
  y: number;
}

interface MindMapViewport {
  scale: number;
  offsetX: number;
  offsetY: number;
}

interface MindMapDragState {
  nodeId: string;
  startClientX: number;
  startClientY: number;
  originX: number;
  originY: number;
  moved: boolean;
}

interface MindMapPanState {
  startClientX: number;
  startClientY: number;
  startOffsetX: number;
  startOffsetY: number;
  moved: boolean;
}

function computeMindMapLayout(nodes: InfraNode[], childMap: Map<string, InfraNode[]>) {
  const roots = nodes.filter(n => !n.parent_id);
  if (roots.length === 0) return { items: [], edges: [], width: 0, height: 0 };

  // Cache subtree heights
  const stHeightCache = new Map<string, number>();
  function subtreeHeight(id: string): number {
    if (stHeightCache.has(id)) return stHeightCache.get(id)!;
    const children = childMap.get(id) || [];
    if (children.length === 0) {
      stHeightCache.set(id, MM_NODE_H);
      return MM_NODE_H;
    }
    const h = children.reduce((s, c) => s + subtreeHeight(c.id), 0) + (children.length - 1) * MM_V_GAP;
    const result = Math.max(MM_NODE_H, h);
    stHeightCache.set(id, result);
    return result;
  }

  const items: LayoutItem[] = [];
  const edges: LayoutEdge[] = [];

  function layout(node: InfraNode, x: number, yStart: number) {
    const treeH = subtreeHeight(node.id);
    const y = yStart + treeH / 2 - MM_NODE_H / 2;
    items.push({ id: node.id, x, y, node });

    const children = childMap.get(node.id) || [];
    if (children.length > 0) {
      let cy = yStart;
      for (const child of children) {
        const ch = subtreeHeight(child.id);
        const childY = cy + ch / 2 - MM_NODE_H / 2;
        edges.push({
          parentId: node.id,
          childId: child.id,
        });
        layout(child, x + MM_NODE_W + MM_H_GAP, cy);
        cy += ch + MM_V_GAP;
      }
    }
  }

  let rootY = 0;
  for (const root of roots) {
    layout(root, MM_PAD, rootY + MM_PAD);
    rootY += subtreeHeight(root.id) + MM_V_GAP;
  }

  // Calculate canvas dimensions
  let maxX = 0, maxY = 0;
  for (const it of items) {
    if (it.x + MM_NODE_W > maxX) maxX = it.x + MM_NODE_W;
    if (it.y + MM_NODE_H > maxY) maxY = it.y + MM_NODE_H;
  }

  return { items, edges, width: maxX + MM_PAD * 2, height: maxY + MM_PAD * 2 };
}

function buildNodePath(nodes: InfraNode[], nodeId: string | null): string[] {
  if (!nodeId) return [];
  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  const path: string[] = [];
  let currentId: string | null = nodeId;
  const seen = new Set<string>();

  while (currentId && !seen.has(currentId)) {
    seen.add(currentId);
    const current = nodeMap.get(currentId);
    if (!current) break;
    path.unshift(current.label);
    currentId = current.parent_id;
  }

  return path;
}

function buildVisibleNodeIds(nodes: InfraNode[], query: string): Set<string> | null {
  const trimmed = query.trim().toLowerCase();
  if (!trimmed) return null;

  const nodeMap = new Map(nodes.map(node => [node.id, node]));
  const childMap = new Map<string, InfraNode[]>();
  for (const node of nodes) {
    if (!node.parent_id) continue;
    const siblings = childMap.get(node.parent_id) || [];
    siblings.push(node);
    childMap.set(node.parent_id, siblings);
  }

  const visible = new Set<string>();

  const includeAncestors = (nodeId: string | null) => {
    let currentId = nodeId;
    const seen = new Set<string>();
    while (currentId && !seen.has(currentId)) {
      seen.add(currentId);
      const current = nodeMap.get(currentId);
      if (!current) break;
      visible.add(current.id);
      currentId = current.parent_id;
    }
  };

  const includeDescendants = (nodeId: string) => {
    const stack = [...(childMap.get(nodeId) || [])];
    while (stack.length) {
      const current = stack.pop();
      if (!current) continue;
      if (visible.has(current.id)) continue;
      visible.add(current.id);
      stack.push(...(childMap.get(current.id) || []));
    }
  };

  for (const node of nodes) {
    const haystack = [node.label, node.description, node.category].join(' ').toLowerCase();
    if (!haystack.includes(trimmed)) continue;
    visible.add(node.id);
    includeAncestors(node.parent_id);
    includeDescendants(node.id);
  }

  return visible;
}

function isFinitePosition(value: number | null | undefined): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function extractStoredMindMapPositions(nodes: InfraNode[]): Record<string, MindMapPosition> {
  return nodes.reduce<Record<string, MindMapPosition>>((acc, node) => {
    if (isFinitePosition(node.position_x) && isFinitePosition(node.position_y)) {
      acc[node.id] = { x: node.position_x, y: node.position_y };
    }
    return acc;
  }, {});
}

/* ───── Component ───── */

export function InfraMapView() {
  const { currentProject } = useStore();
  const [infraMaps, setInfraMaps] = useState<InfraMapData[]>([]);
  const [selected, setSelected] = useState<InfraMapData | null>(null);
  const [genLoading, setGenLoading] = useState(false);
  const [expandingNode, setExpandingNode] = useState<string | null>(null);
  const [expandedNodes, setExpandedNodes] = useState<Set<string>>(new Set());
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState('');
  const [rootLabel, setRootLabel] = useState('');
  const [userGuidance, setUserGuidance] = useState('');
  const [planningProfile, setPlanningProfile] = useState<PlanningProfile>('planning_first');
  const [showGuidance, setShowGuidance] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [showAddChild, setShowAddChild] = useState<string | null>(null);
  const [addChildLabel, setAddChildLabel] = useState('');
  const [nodeQuery, setNodeQuery] = useState('');
  const [savingNode, setSavingNode] = useState(false);
  const [editDraft, setEditDraft] = useState<InfraNodeDraft | null>(null);
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('tree');
  const [mindMapViewport, setMindMapViewport] = useState<MindMapViewport>({ scale: 1, offsetX: 24, offsetY: 24 });
  const [mindMapNodePositions, setMindMapNodePositions] = useState<Record<string, MindMapPosition>>({});
  const mindmapRef = useRef<HTMLDivElement>(null);
  const dragStateRef = useRef<MindMapDragState | null>(null);
  const panStateRef = useRef<MindMapPanState | null>(null);
  const suppressNodeClickRef = useRef(false);
  const selectedRef = useRef<InfraMapData | null>(null);
  const nodePositionsRef = useRef<Record<string, MindMapPosition>>({});
  const selectedPlanningProfile = useMemo(() => getPlanningProfileOption(planningProfile), [planningProfile]);

  useEffect(() => {
    selectedRef.current = selected;
  }, [selected]);

  useEffect(() => {
    nodePositionsRef.current = mindMapNodePositions;
  }, [mindMapNodePositions]);

  // Load maps: project-scoped or standalone
  useEffect(() => {
    loadInfraMaps();
  }, [currentProject?.id]);

  useEffect(() => {
    setMindMapNodePositions(extractStoredMindMapPositions(selected?.nodes || []));
  }, [selected?.nodes]);

  useEffect(() => {
    setMindMapViewport({ scale: 1, offsetX: 24, offsetY: 24 });
  }, [selected?.id]);

  const loadInfraMaps = async () => {
    try {
      const previousSelectedId = selected?.id;
      const data = currentProject
        ? await api.listInfraMaps(currentProject.id)
        : await api.listStandaloneInfraMaps();
      setInfraMaps(data);
      const nextSelected = data.find(m => m.id === previousSelectedId) || data[0] || null;
      setSelected(nextSelected);
      setSelectedNodeId(null);
      setShowAddChild(null);
      setNodeQuery('');
      const rootNode = (nextSelected?.nodes || []).find((n: InfraNode) => !n.parent_id);
      setExpandedNodes(rootNode ? new Set([rootNode.id]) : new Set());
    } catch (e: any) { toast.error(e.message); }
  };

  const applyMapUpdate = useCallback((result: InfraMapData) => {
    setSelected(result);
    setInfraMaps(prev => {
      const existingIndex = prev.findIndex(map => map.id === result.id);
      if (existingIndex === -1) {
        return [result, ...prev];
      }
      const next = [...prev];
      next[existingIndex] = result;
      return next;
    });
  }, []);

  const handleResetMindMapView = useCallback(() => {
    setMindMapViewport({ scale: 1, offsetX: 24, offsetY: 24 });
  }, []);

  const handleResetMindMapLayout = useCallback(async () => {
    if (!selectedRef.current) return;
    const current = selectedRef.current;
    const resetNodes = (current.nodes || []).map(({ position_x, position_y, ...node }) => node);
    try {
      const result = await api.updateInfraMap(current.id, { nodes: resetNodes });
      applyMapUpdate(result);
      setMindMapNodePositions({});
      toast.success('Mind map layout reset');
    } catch (e: any) {
      toast.error(e.message);
    }
  }, [applyMapUpdate]);

  const persistMindMapNodePosition = useCallback(async (nodeId: string, nextPosition: MindMapPosition) => {
    const current = selectedRef.current;
    if (!current) return;
    const target = (current.nodes || []).find(node => node.id === nodeId);
    if (!target) return;
    const currentX = isFinitePosition(target.position_x) ? target.position_x : null;
    const currentY = isFinitePosition(target.position_y) ? target.position_y : null;
    if (
      currentX !== null && currentY !== null
      && Math.abs(currentX - nextPosition.x) < 1
      && Math.abs(currentY - nextPosition.y) < 1
    ) {
      return;
    }

    const updatedNodes = (current.nodes || []).map(node => (
      node.id === nodeId
        ? { ...node, position_x: Math.round(nextPosition.x), position_y: Math.round(nextPosition.y) }
        : node
    ));

    try {
      const result = await api.updateInfraMap(current.id, { nodes: updatedNodes });
      applyMapUpdate(result);
    } catch (e: any) {
      toast.error(e.message);
      setMindMapNodePositions(extractStoredMindMapPositions(selectedRef.current?.nodes || []));
    }
  }, [applyMapUpdate]);

  const handleCreate = async () => {
    try {
      const payload: any = { name: createName || 'Infrastructure Map' };
      if (currentProject) payload.project_id = currentProject.id;
      const im = await api.createInfraMap(payload);
      setInfraMaps(prev => [im, ...prev]);
      setSelected(im);
      setExpandedNodes(new Set());
      setSelectedNodeId(null);
      setShowCreate(false);
      setCreateName('');
    } catch (e: any) { toast.error(e.message); }
  };

  const handleDelete = async (id: string) => {
    try {
      await api.deleteInfraMap(id);
      setInfraMaps(prev => {
        const remainingMaps = prev.filter(map => map.id !== id);
        if (selectedRef.current?.id === id) {
          const nextSelected = remainingMaps[0] || null;
          setSelected(nextSelected);
          const rootNode = (nextSelected?.nodes || []).find((n: InfraNode) => !n.parent_id);
          setExpandedNodes(rootNode ? new Set([rootNode.id]) : new Set());
          setSelectedNodeId(null);
        }
        return remainingMaps;
      });
      toast.success('Map deleted');
    } catch (e: any) { toast.error(e.message); }
  };

  const handleAiGenerate = async () => {
    setGenLoading(true);
    try {
      const genData = {
        root_label: rootLabel || undefined,
        user_guidance: userGuidance || undefined,
        planning_profile: planningProfile,
      };
      const result = currentProject
        ? await api.aiGenerateInfraMap(currentProject.id, genData)
        : await api.aiGenerateStandaloneInfraMap(genData);
      applyMapUpdate(result);
      setShowGuidance(false);
      setSelectedNodeId(null);
      setNodeQuery('');
      const rootNode = (result.nodes || []).find((n: InfraNode) => !n.parent_id);
      if (rootNode) setExpandedNodes(new Set([rootNode.id]));
      toast.success('Infrastructure map generated');
    } catch (e: any) { toast.error(e.message); }
    finally { setGenLoading(false); }
  };

  const handleAiExpand = async (nodeId: string) => {
    if (!selected) return;
    setExpandingNode(nodeId);
    try {
      const result = await api.aiExpandInfraNode(selected.id, {
        node_id: nodeId,
        user_guidance: userGuidance || undefined,
        planning_profile: planningProfile,
      });
      applyMapUpdate(result);
      setExpandedNodes(prev => new Set([...prev, nodeId]));
      toast.success('Node expanded');
    } catch (e: any) { toast.error(e.message); }
    finally { setExpandingNode(null); }
  };

  const handleAddManualChild = async (parentId: string) => {
    if (!selected || !addChildLabel.trim()) return;
    const newNode: InfraNode = {
      id: crypto.randomUUID(),
      parent_id: parentId,
      label: addChildLabel.trim(),
      category: 'general',
      description: '',
      icon_hint: 'cog',
      children_loaded: false,
      manually_added: true,
    };
    const updatedNodes = [...(selected.nodes || []), newNode];
    try {
      const result = await api.updateInfraMap(selected.id, { nodes: updatedNodes });
      applyMapUpdate(result);
      setShowAddChild(null);
      setAddChildLabel('');
      setExpandedNodes(prev => new Set([...prev, parentId]));
    } catch (e: any) { toast.error(e.message); }
  };

  const handleDeleteNode = async (nodeId: string) => {
    if (!selected) return;
    const toRemove = new Set<string>();
    const collectDescendants = (id: string) => {
      toRemove.add(id);
      for (const n of (selected.nodes || [])) {
        if (n.parent_id === id) collectDescendants(n.id);
      }
    };
    collectDescendants(nodeId);
    const updatedNodes = (selected.nodes || []).filter(n => !toRemove.has(n.id));
    try {
      const result = await api.updateInfraMap(selected.id, { nodes: updatedNodes });
      applyMapUpdate(result);
      if (selectedNodeId === nodeId) setSelectedNodeId(null);
    } catch (e: any) { toast.error(e.message); }
  };

  const toggleExpand = useCallback((nodeId: string) => {
    setExpandedNodes(prev => {
      const next = new Set(prev);
      if (next.has(nodeId)) next.delete(nodeId);
      else next.add(nodeId);
      return next;
    });
  }, []);

  // Build tree structure
  const nodes = useMemo(() => selected?.nodes || [], [selected?.nodes]);
  const rootNodes = useMemo(() => nodes.filter(n => !n.parent_id), [nodes]);
  const childMap = useMemo(() => {
    const map = new Map<string, InfraNode[]>();
    for (const n of nodes) {
      if (n.parent_id) {
        const arr = map.get(n.parent_id) || [];
        arr.push(n);
        map.set(n.parent_id, arr);
      }
    }
    return map;
  }, [nodes]);

  // Stats
  const totalNodes = nodes.length;
  const categories = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const n of nodes) {
      counts[n.category] = (counts[n.category] || 0) + 1;
    }
    return counts;
  }, [nodes]);
  const describedNodes = useMemo(() => nodes.filter(node => node.description?.trim()).length, [nodes]);
  const manualNodes = useMemo(() => nodes.filter(node => node.manually_added).length, [nodes]);
  const leafNodes = useMemo(() => nodes.filter(node => (childMap.get(node.id) || []).length === 0).length, [nodes, childMap]);
  const depth = useMemo(() => {
    let maxD = 0;
    const nodeMap = new Map(nodes.map(n => [n.id, n]));
    for (const n of nodes) {
      let d = 0;
      let cur: InfraNode | undefined = n;
      const seen = new Set<string>();
      while (cur?.parent_id && !seen.has(cur.id)) {
        seen.add(cur.id);
        d++;
        cur = nodeMap.get(cur.parent_id);
      }
      if (d > maxD) maxD = d;
    }
    return maxD;
  }, [nodes]);
  const mappedBranches = useMemo(
    () => nodes.filter(node => (childMap.get(node.id) || []).length > 0 || node.children_loaded).length,
    [nodes, childMap],
  );
  const detailCoverage = useMemo(() => {
    if (!nodes.length) return 0;
    const describedCoverage = describedNodes / nodes.length;
    const structuralCoverage = mappedBranches / nodes.length;
    return Math.round(((describedCoverage * 0.6) + (structuralCoverage * 0.4)) * 100);
  }, [describedNodes, mappedBranches, nodes.length]);

  const expandAll = useCallback(() => {
    setExpandedNodes(new Set(nodes.map(n => n.id)));
  }, [nodes]);

  const collapseAll = useCallback(() => {
    setExpandedNodes(new Set());
  }, []);

  const selectedNode = useMemo(() => nodes.find(n => n.id === selectedNodeId) || null, [nodes, selectedNodeId]);
  const selectedNodePath = useMemo(() => buildNodePath(nodes, selectedNodeId), [nodes, selectedNodeId]);
  const visibleNodeIds = useMemo(() => buildVisibleNodeIds(nodes, nodeQuery), [nodes, nodeQuery]);
  const filteredRootNodes = useMemo(
    () => rootNodes.filter(node => !visibleNodeIds || visibleNodeIds.has(node.id)),
    [rootNodes, visibleNodeIds],
  );
  const visibleNodesCount = visibleNodeIds ? nodes.filter(node => visibleNodeIds.has(node.id)).length : nodes.length;
  const infraAnalysisMetadata = selected?.analysis_metadata || {};
  const generationWarnings = useMemo(
    () => [
      ...(Array.isArray(infraAnalysisMetadata.generation_warnings) ? infraAnalysisMetadata.generation_warnings : []),
      ...(Array.isArray(infraAnalysisMetadata.last_generation_warnings) ? infraAnalysisMetadata.last_generation_warnings : []),
    ].filter((warning): warning is string => typeof warning === 'string' && warning.trim().length > 0),
    [infraAnalysisMetadata.generation_warnings, infraAnalysisMetadata.last_generation_warnings],
  );

  useEffect(() => {
    if (!selectedNode) {
      setEditDraft(null);
      return;
    }
    setEditDraft({
      label: selectedNode.label,
      category: selectedNode.category,
      description: selectedNode.description,
      icon_hint: selectedNode.icon_hint,
    });
  }, [selectedNode]);

  const handleSaveSelectedNode = async () => {
    if (!selected || !selectedNode || !editDraft) return;
    setSavingNode(true);
    try {
      const updatedNodes = (selected.nodes || []).map(node =>
        node.id === selectedNode.id ? { ...node, ...editDraft } : node,
      );
      const result = await api.updateInfraMap(selected.id, { nodes: updatedNodes });
      applyMapUpdate(result);
      toast.success('Node updated');
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setSavingNode(false);
    }
  };

  // Mind map layout
  const mmLayout = useMemo(() => computeMindMapLayout(nodes, childMap), [nodes, childMap]);
  const mmDisplayItems = useMemo(
    () => mmLayout.items.map(item => {
      const override = mindMapNodePositions[item.id];
      return override ? { ...item, x: override.x, y: override.y } : item;
    }),
    [mindMapNodePositions, mmLayout.items],
  );
  const mmDisplayItemMap = useMemo(
    () => new Map(mmDisplayItems.map(item => [item.id, item])),
    [mmDisplayItems],
  );
  const mmDisplayEdges = useMemo(() => {
    const edges: LayoutEdge[] = [];
    for (const node of nodes) {
      if (!node.parent_id) continue;
      const parent = mmDisplayItemMap.get(node.parent_id);
      const child = mmDisplayItemMap.get(node.id);
      if (!parent || !child) continue;
      edges.push({ parentId: parent.id, childId: child.id });
    }
    return edges;
  }, [mmDisplayItemMap, nodes]);
  const mmCanvas = useMemo(() => {
    if (mmDisplayItems.length === 0) {
      return { width: 900, height: 540 };
    }
    let maxX = 0;
    let maxY = 0;
    for (const item of mmDisplayItems) {
      maxX = Math.max(maxX, item.x + MM_NODE_W);
      maxY = Math.max(maxY, item.y + MM_NODE_H);
    }
    return {
      width: Math.max(maxX + MM_PAD * 2, 900),
      height: Math.max(maxY + MM_PAD * 2, 540),
    };
  }, [mmDisplayItems]);

  const handleMindMapWheel = useCallback((event: React.WheelEvent<HTMLDivElement>) => {
    event.preventDefault();
    const container = mindmapRef.current;
    if (!container) return;

    const rect = container.getBoundingClientRect();
    const cursorX = event.clientX - rect.left;
    const cursorY = event.clientY - rect.top;

    setMindMapViewport(prev => {
      const nextScale = Math.min(2.4, Math.max(0.45, prev.scale * (event.deltaY < 0 ? 1.1 : 0.92)));
      const contentX = (cursorX - prev.offsetX) / prev.scale;
      const contentY = (cursorY - prev.offsetY) / prev.scale;
      return {
        scale: nextScale,
        offsetX: cursorX - contentX * nextScale,
        offsetY: cursorY - contentY * nextScale,
      };
    });
  }, []);

  const handleMindMapBackgroundMouseDown = useCallback((event: React.MouseEvent<HTMLDivElement>) => {
    if (event.button !== 0) return;
    const target = event.target as HTMLElement | null;
    if (target?.closest('[data-mindmap-node="true"]')) return;
    panStateRef.current = {
      startClientX: event.clientX,
      startClientY: event.clientY,
      startOffsetX: mindMapViewport.offsetX,
      startOffsetY: mindMapViewport.offsetY,
      moved: false,
    };
  }, [mindMapViewport.offsetX, mindMapViewport.offsetY]);

  const handleMindMapNodeMouseDown = useCallback((event: React.MouseEvent<HTMLDivElement>, nodeId: string, x: number, y: number) => {
    if (event.button !== 0) return;
    const target = event.target as HTMLElement | null;
    if (target?.closest('button, input, textarea, select')) return;
    dragStateRef.current = {
      nodeId,
      startClientX: event.clientX,
      startClientY: event.clientY,
      originX: x,
      originY: y,
      moved: false,
    };
  }, []);

  useEffect(() => {
    const handleMouseMove = (event: MouseEvent) => {
      const dragState = dragStateRef.current;
      if (dragState) {
        const deltaX = (event.clientX - dragState.startClientX) / mindMapViewport.scale;
        const deltaY = (event.clientY - dragState.startClientY) / mindMapViewport.scale;
        if (Math.abs(deltaX) > 2 || Math.abs(deltaY) > 2) {
          dragState.moved = true;
        }
        const nextPosition = {
          x: Math.max(8, dragState.originX + deltaX),
          y: Math.max(8, dragState.originY + deltaY),
        };
        setMindMapNodePositions(prev => ({ ...prev, [dragState.nodeId]: nextPosition }));
        return;
      }

      const panState = panStateRef.current;
      if (!panState) return;
      const deltaX = event.clientX - panState.startClientX;
      const deltaY = event.clientY - panState.startClientY;
      if (Math.abs(deltaX) > 2 || Math.abs(deltaY) > 2) {
        panState.moved = true;
      }
      setMindMapViewport(prev => ({
        ...prev,
        offsetX: panState.startOffsetX + deltaX,
        offsetY: panState.startOffsetY + deltaY,
      }));
    };

    const handleMouseUp = () => {
      const dragState = dragStateRef.current;
      if (dragState) {
        dragStateRef.current = null;
        if (dragState.moved) {
          suppressNodeClickRef.current = true;
          void persistMindMapNodePosition(dragState.nodeId, nodePositionsRef.current[dragState.nodeId] || {
            x: dragState.originX,
            y: dragState.originY,
          });
          window.setTimeout(() => {
            suppressNodeClickRef.current = false;
          }, 0);
        }
      }

      const panState = panStateRef.current;
      if (panState) {
        panStateRef.current = null;
      }
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('mouseup', handleMouseUp);
    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('mouseup', handleMouseUp);
    };
  }, [mindMapViewport.scale, persistMindMapNodePosition]);

  // ─── Tree Node Renderer ───
  const renderNode = (node: InfraNode, level: number): React.ReactNode => {
    if (visibleNodeIds && !visibleNodeIds.has(node.id)) return null;
    const children = (childMap.get(node.id) || []).filter(child => !visibleNodeIds || visibleNodeIds.has(child.id));
    const isExpanded = expandedNodes.has(node.id);
    const isSelected = selectedNodeId === node.id;
    const isExpanding = expandingNode === node.id;
    const hasChildren = children.length > 0;
    const catStyle = CATEGORY_COLORS[node.category] || CATEGORY_COLORS.general;
    const icon = ICON_MAP[node.icon_hint] || <Cog size={14} />;
    const matchesQuery = nodeQuery.trim()
      ? [node.label, node.description, node.category].join(' ').toLowerCase().includes(nodeQuery.trim().toLowerCase())
      : false;

    return (
      <div key={node.id} className="select-none">
        <div
          className={cn(
            'flex items-center gap-2 px-3 py-2 rounded-lg cursor-pointer transition-all group',
            'hover:bg-accent/50',
            isSelected && 'ring-1 ring-cyan-500/50 bg-cyan-500/5',
            matchesQuery && !isSelected && 'bg-emerald-500/5 ring-1 ring-emerald-500/20',
          )}
          style={{ paddingLeft: `${12 + level * 24}px` }}
          onClick={() => setSelectedNodeId(isSelected ? null : node.id)}
        >
          <button
            onClick={(e) => { e.stopPropagation(); toggleExpand(node.id); }}
            className={cn('p-0.5 rounded hover:bg-accent shrink-0 transition-colors', !hasChildren && !node.children_loaded && 'invisible')}
          >
            {isExpanded ? <ChevronDown size={13} className="text-muted-foreground" /> : <ChevronRight size={13} className="text-muted-foreground" />}
          </button>

          <div className={cn('p-1.5 rounded-md shrink-0', catStyle.bg, catStyle.text)}>{icon}</div>

          <div className="flex-1 min-w-0">
            <span className="text-sm font-medium truncate block">{node.label}</span>
            {node.description && isExpanded && (
              <p className="text-[10px] text-muted-foreground mt-0.5 line-clamp-2">{node.description}</p>
            )}
          </div>

          <span className={cn('text-[9px] px-1.5 py-0.5 rounded-full shrink-0', catStyle.bg, catStyle.text)}>{node.category}</span>
          {hasChildren && <span className="text-[10px] text-muted-foreground">{children.length}</span>}

          <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
            {!isExpanding ? (
              <button onClick={(e) => { e.stopPropagation(); handleAiExpand(node.id); }} className="p-1 rounded hover:bg-cyan-500/20 text-cyan-500" title="AI expand"><Sparkles size={12} /></button>
            ) : (
              <Loader2 size={12} className="animate-spin text-cyan-500" />
            )}
            <button onClick={(e) => { e.stopPropagation(); setShowAddChild(showAddChild === node.id ? null : node.id); setAddChildLabel(''); }} className="p-1 rounded hover:bg-accent text-muted-foreground" title="Add child"><Plus size={12} /></button>
            {node.parent_id && (
              <button onClick={(e) => { e.stopPropagation(); handleDeleteNode(node.id); }} className="p-1 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive" title="Delete"><Trash2 size={11} /></button>
            )}
          </div>
        </div>

        {showAddChild === node.id && (
          <div className="flex items-center gap-1 ml-12 my-1" style={{ paddingLeft: `${level * 24}px` }}>
            <input autoFocus value={addChildLabel} onChange={e => setAddChildLabel(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') handleAddManualChild(node.id); if (e.key === 'Escape') setShowAddChild(null); }}
              placeholder="New item name..." className="text-xs bg-transparent border rounded px-2 py-1 flex-1" />
            <button onClick={() => handleAddManualChild(node.id)} className="text-xs px-2 py-1 rounded bg-cyan-600 text-white hover:bg-cyan-700">Add</button>
            <button onClick={() => setShowAddChild(null)} className="p-0.5 hover:bg-accent rounded"><X size={12} /></button>
          </div>
        )}

        {isExpanded && children.map(child => renderNode(child, level + 1))}
      </div>
    );
  };

  // ─── Mind Map Canvas ───
  const renderMindMap = () => {
    const filteredItems = visibleNodeIds ? mmDisplayItems.filter(item => visibleNodeIds.has(item.id)) : mmDisplayItems;
    const filteredEdges = visibleNodeIds
      ? mmDisplayEdges.filter(edge => visibleNodeIds.has(edge.parentId) && visibleNodeIds.has(edge.childId))
      : mmDisplayEdges;
    const width = mmCanvas.width;
    const height = mmCanvas.height;
    if (filteredItems.length === 0) return null;

    return (
      <div
        ref={mindmapRef}
        className={cn(
          'flex-1 overflow-hidden bg-background/50 select-none',
          panStateRef.current ? 'cursor-grabbing' : 'cursor-grab',
        )}
        style={{ position: 'relative' }}
        onWheel={handleMindMapWheel}
        onMouseDown={handleMindMapBackgroundMouseDown}
      >
        <div
          style={{
            position: 'absolute',
            inset: 0,
            transform: `translate(${mindMapViewport.offsetX}px, ${mindMapViewport.offsetY}px) scale(${mindMapViewport.scale})`,
            transformOrigin: '0 0',
          }}
        >
          <div style={{ width: `${width}px`, height: `${height}px`, position: 'relative' }}>
            <svg
              style={{ position: 'absolute', top: 0, left: 0, width: '100%', height: '100%', pointerEvents: 'none' }}
            >
              {filteredEdges.map((edge, index) => {
                const parent = mmDisplayItemMap.get(edge.parentId);
                const child = mmDisplayItemMap.get(edge.childId);
                if (!parent || !child) return null;
                const cpX = (parent.x + MM_NODE_W + child.x) / 2;
                const color = CAT_SVG_COLORS[parent.node.category] || '#6b7280';
                return (
                  <path
                    key={index}
                    d={`M${parent.x + MM_NODE_W},${parent.y + MM_NODE_H / 2} C${cpX},${parent.y + MM_NODE_H / 2} ${cpX},${child.y + MM_NODE_H / 2} ${child.x},${child.y + MM_NODE_H / 2}`}
                    fill="none"
                    stroke={color}
                    strokeWidth={1.5}
                    strokeOpacity={0.35}
                  />
                );
              })}
            </svg>

            {filteredItems.map(item => {
              const node = item.node;
              const catStyle = CATEGORY_COLORS[node.category] || CATEGORY_COLORS.general;
              const isSelected = selectedNodeId === node.id;
              const isExpanding = expandingNode === node.id;
              const icon = ICON_MAP_SM[node.icon_hint] || <Cog size={11} />;
              const children = (childMap.get(node.id) || []).filter(child => !visibleNodeIds || visibleNodeIds.has(child.id));
              const matchesQuery = nodeQuery.trim()
                ? [node.label, node.description, node.category].join(' ').toLowerCase().includes(nodeQuery.trim().toLowerCase())
                : false;

              return (
                <div
                  key={node.id}
                  data-mindmap-node="true"
                  className={cn(
                    'absolute flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border transition-all group',
                    'bg-card hover:bg-accent/30 shadow-sm hover:shadow-md',
                    dragStateRef.current?.nodeId === node.id ? 'cursor-grabbing' : 'cursor-grab',
                    isSelected ? 'ring-2 ring-cyan-500/60 border-cyan-500/40' : catStyle.border,
                    matchesQuery && !isSelected && 'ring-2 ring-emerald-500/40 border-emerald-500/30',
                  )}
                  style={{ left: item.x, top: item.y, width: MM_NODE_W, height: MM_NODE_H }}
                  onMouseDown={(event) => handleMindMapNodeMouseDown(event, node.id, item.x, item.y)}
                  onClick={() => {
                    if (suppressNodeClickRef.current) return;
                    setSelectedNodeId(isSelected ? null : node.id);
                  }}
                >
                  <div className={cn('p-1 rounded shrink-0', catStyle.bg, catStyle.text)}>{icon}</div>
                  <div className="flex-1 min-w-0 overflow-hidden">
                    <div className="text-[11px] font-medium truncate leading-tight">{node.label}</div>
                    <div className={cn('text-[8px] leading-tight', catStyle.text)}>{node.category}</div>
                  </div>
                  {children.length > 0 && (
                    <span className="text-[9px] text-muted-foreground shrink-0">{children.length}</span>
                  )}

                  <div className="absolute -top-2 -right-2 flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                    {!isExpanding ? (
                      <button onClick={(e) => { e.stopPropagation(); handleAiExpand(node.id); }}
                        className="p-1 rounded-full bg-cyan-600 text-white shadow hover:bg-cyan-700" title="AI expand">
                        <Sparkles size={10} />
                      </button>
                    ) : (
                      <span className="p-1 rounded-full bg-cyan-600 text-white shadow"><Loader2 size={10} className="animate-spin" /></span>
                    )}
                    <button onClick={(e) => { e.stopPropagation(); setShowAddChild(showAddChild === node.id ? null : node.id); setAddChildLabel(''); }}
                      className="p-1 rounded-full bg-card border shadow text-muted-foreground hover:text-foreground" title="Add child">
                      <Plus size={10} />
                    </button>
                    {node.parent_id && (
                      <button onClick={(e) => { e.stopPropagation(); handleDeleteNode(node.id); }}
                        className="p-1 rounded-full bg-card border shadow text-muted-foreground hover:text-destructive" title="Delete">
                        <Trash2 size={9} />
                      </button>
                    )}
                  </div>
                </div>
              );
            })}

            {showAddChild && filteredItems.find(it => it.id === showAddChild) && (() => {
              const item = filteredItems.find(it => it.id === showAddChild)!;
              return (
                <div className="absolute z-20 flex items-center gap-1 bg-card border rounded-lg shadow-lg p-1.5"
                  style={{ left: item.x + MM_NODE_W + 8, top: item.y }}>
                  <input autoFocus value={addChildLabel} onChange={e => setAddChildLabel(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter') handleAddManualChild(showAddChild); if (e.key === 'Escape') setShowAddChild(null); }}
                    placeholder="New item..." className="text-xs bg-transparent border rounded px-2 py-1 w-32" />
                  <button onClick={() => handleAddManualChild(showAddChild)} className="text-xs px-2 py-1 rounded bg-cyan-600 text-white hover:bg-cyan-700">Add</button>
                  <button onClick={() => setShowAddChild(null)} className="p-0.5 hover:bg-accent rounded"><X size={10} /></button>
                </div>
              );
            })()}
          </div>
        </div>
      </div>
    );
  };

  // ─── Shared toolbar + chrome ───
  const isStandalone = !currentProject;

  return (
    <div className="h-full flex flex-col">
      {/* ──── Top Toolbar ──── */}
      <div className="border-b px-4 py-2 flex items-center gap-2 bg-card shrink-0 flex-wrap">
        <Network size={16} className="text-emerald-500" />
        <h2 className="font-semibold text-sm">Infra Map</h2>
        {isStandalone && <span className="text-[9px] px-1.5 py-0.5 rounded-full bg-amber-500/15 text-amber-500 font-medium">Standalone</span>}
        <div className="border-l h-5 mx-1" />

        {/* Select map */}
        <select
          value={selected?.id || ''}
          onChange={(e) => {
            const im = infraMaps.find(m => m.id === e.target.value) || null;
            setSelected(im);
            setExpandedNodes(new Set());
            setSelectedNodeId(null);
            setNodeQuery('');
            setShowAddChild(null);
            if (im) {
              const root = (im.nodes || []).find((n: InfraNode) => !n.parent_id);
              if (root) setExpandedNodes(new Set([root.id]));
            }
          }}
          className="select-field text-xs px-2 py-1 max-w-[200px]"
        >
          <option value="">Select map...</option>
          {infraMaps.map(m => <option key={m.id} value={m.id}>{m.name}</option>)}
        </select>

        {showCreate ? (
          <div className="flex items-center gap-1">
            <input value={createName} onChange={(e) => setCreateName(e.target.value)} placeholder="Map name..."
              className="text-xs bg-transparent border rounded px-2 py-1 w-32" onKeyDown={e => e.key === 'Enter' && handleCreate()} />
            <button onClick={handleCreate} className="text-xs px-2 py-1 rounded bg-emerald-600 text-white hover:bg-emerald-700">Create</button>
            <button onClick={() => setShowCreate(false)} className="p-0.5 hover:bg-accent rounded"><X size={12} /></button>
          </div>
        ) : (
          <button onClick={() => setShowCreate(true)} className="p-1 rounded hover:bg-accent" title="Create empty map">
            <Plus size={14} />
          </button>
        )}

        <div className="flex-1" />

        {/* Layout toggle */}
        <div className="flex items-center bg-muted/50 rounded-md p-0.5">
          <button
            onClick={() => setLayoutMode('tree')}
            className={cn('flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors',
              layoutMode === 'tree' ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground hover:text-foreground'
            )}
            title="Tree view (top-down list)"
          >
            <List size={12} />
            Tree
          </button>
          <button
            onClick={() => setLayoutMode('mindmap')}
            className={cn('flex items-center gap-1 px-2 py-1 rounded text-[11px] font-medium transition-colors',
              layoutMode === 'mindmap' ? 'bg-background shadow-sm text-foreground' : 'text-muted-foreground hover:text-foreground'
            )}
            title="Mind map (flat canvas)"
          >
            <GitFork size={12} className="rotate-90" />
            Mind Map
          </button>
        </div>

        <div className="border-l h-5 mx-1" />

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
          className={cn('flex items-center gap-1 px-2 py-1 rounded text-xs transition-colors',
            showGuidance ? 'bg-amber-500/20 text-amber-500' : 'hover:bg-accent text-muted-foreground')}
          title="Add operator guidance for the AI"
        >
          <BookOpen size={12} />
          Guidance
        </button>

        {selected && nodes.length > 0 && layoutMode === 'tree' && (
          <>
            <button onClick={expandAll} className="p-1 rounded hover:bg-accent text-muted-foreground" title="Expand all"><ChevronsDown size={14} /></button>
            <button onClick={collapseAll} className="p-1 rounded hover:bg-accent text-muted-foreground" title="Collapse all"><ChevronsUp size={14} /></button>
          </>
        )}

        <button onClick={handleAiGenerate} disabled={genLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-gradient-to-r from-emerald-600 to-cyan-600 text-white text-xs font-medium hover:opacity-90 disabled:opacity-50">
          {genLoading ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
          {genLoading ? 'Generating...' : 'AI Generate'}
        </button>

        {selected && (
          <button onClick={() => setDeleteConfirmId(selected.id)} className="p-1 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive">
            <Trash2 size={14} />
          </button>
        )}
      </div>

      {/* ──── Guidance Bar ──── */}
      {showGuidance && (
        <div className="border-b px-4 py-2 bg-amber-500/5 flex items-center gap-2">
          <BookOpen size={13} className="text-amber-500 shrink-0" />
          <input value={rootLabel} onChange={(e) => setRootLabel(e.target.value)}
            placeholder="Root label: e.g. 'Data Centre', 'Corporate Network', 'SCADA System'..."
            className="text-xs bg-transparent border rounded px-3 py-1.5 w-56 placeholder:text-muted-foreground/50" />
          <input value={userGuidance} onChange={(e) => setUserGuidance(e.target.value)}
            placeholder="Additional guidance: e.g. 'Focus on OT/ICS systems', 'Include cloud infrastructure'..."
            className="flex-1 text-xs bg-transparent border rounded px-3 py-1.5 placeholder:text-muted-foreground/50"
            onKeyDown={e => { if (e.key === 'Enter') handleAiGenerate(); }} />
          <span className="text-[10px] text-muted-foreground hidden xl:inline">{selectedPlanningProfile.label}: {selectedPlanningProfile.description}</span>
          <span className="text-[10px] text-muted-foreground shrink-0">Enter to generate</span>
        </div>
      )}

      {selected && (
        <div className="border-b bg-card/40 px-4 py-3 space-y-3">
          <div className="flex items-start justify-between gap-4 flex-wrap">
            <div className="min-w-0 max-w-3xl">
              <div className="flex items-center gap-2 flex-wrap">
                <h3 className="text-sm font-semibold">{selected.name}</h3>
                <span className={cn(
                  'text-[10px] px-1.5 py-0.5 rounded-full font-medium',
                  isStandalone ? 'bg-amber-500/10 text-amber-500' : 'bg-cyan-500/10 text-cyan-400',
                )}>
                  {isStandalone ? 'Standalone Map' : 'Project Map'}
                </span>
                {detailCoverage > 0 && (
                  <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 font-medium">
                    {detailCoverage}% detailed
                  </span>
                )}
              </div>
              {selected.description && (
                <p className="text-xs text-muted-foreground mt-1">{selected.description}</p>
              )}
              {selected.ai_summary && (
                <p className="text-xs text-muted-foreground mt-2 leading-relaxed">{selected.ai_summary}</p>
              )}
              {(infraAnalysisMetadata.generation_strategy || generationWarnings.length > 0) && (
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  {infraAnalysisMetadata.generation_strategy && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 font-medium">
                      {infraAnalysisMetadata.generation_strategy === 'multi_pass' ? 'Multi-pass AI' : infraAnalysisMetadata.generation_strategy}
                    </span>
                  )}
                  {(infraAnalysisMetadata.generation_status || infraAnalysisMetadata.last_generation_status) && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded-full bg-muted text-muted-foreground font-medium">
                      {infraAnalysisMetadata.generation_status || infraAnalysisMetadata.last_generation_status}
                    </span>
                  )}
                  {typeof infraAnalysisMetadata.branch_count === 'number' && (
                    <span className="text-[10px] text-muted-foreground">
                      {infraAnalysisMetadata.completed_branch_count ?? 0} / {infraAnalysisMetadata.branch_count} branches detailed
                    </span>
                  )}
                </div>
              )}
              {generationWarnings.length > 0 && (
                <div className="mt-2 rounded-lg border border-amber-500/20 bg-amber-500/5 px-3 py-2">
                  <div className="text-[10px] font-semibold text-amber-500 mb-1">Coverage notes</div>
                  <div className="space-y-1">
                    {generationWarnings.slice(0, 3).map((warning, index) => (
                      <p key={`${warning}-${index}`} className="text-[11px] text-muted-foreground leading-relaxed">{warning}</p>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center gap-2 flex-wrap">
              <OverviewStat label="Nodes" value={totalNodes} />
              <OverviewStat label="Leaves" value={leafNodes} />
              <OverviewStat label="Detailed" value={describedNodes} />
              <OverviewStat label="Manual" value={manualNodes} />
              <OverviewStat label="Categories" value={Object.keys(categories).length} />
              <OverviewStat label="Depth" value={depth} />
            </div>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <input
              value={nodeQuery}
              onChange={(e) => setNodeQuery(e.target.value)}
              placeholder="Search nodes, categories, descriptions, and branches..."
              className="min-w-[260px] flex-1 text-xs bg-transparent border rounded px-3 py-1.5"
            />
            <span className="text-[11px] text-muted-foreground">
              {visibleNodesCount} of {totalNodes} visible
            </span>
            {nodeQuery && (
              <button
                onClick={() => setNodeQuery('')}
                className="text-xs px-2 py-1 rounded border hover:bg-accent"
              >
                Clear
              </button>
            )}
          </div>
        </div>
      )}

      {/* ──── Content ──── */}
      {!selected ? (
        /* Empty state: no map selected */
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center max-w-md">
            <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 flex items-center justify-center">
              <Network size={28} className="text-emerald-500" />
            </div>
            <p className="text-sm font-semibold mb-1">Infrastructure Mapping</p>
            <p className="text-xs mb-5 leading-relaxed">
              Build a hierarchical mind-map of your target's hardware, software, and services.
              {isStandalone
                ? ' Standalone mode — maps are independent of any project workspace.'
                : ' Start with a top-level concept like "Data Centre" and let AI break it down into Hardware, Software, Networking, OT/ICS, and more.'}
            </p>
            <div className="flex items-center justify-center gap-3">
              <button onClick={() => { setShowGuidance(true); }}
                className="flex items-center gap-1.5 px-5 py-2.5 rounded-lg bg-gradient-to-r from-emerald-600 to-cyan-600 text-white text-sm font-medium hover:opacity-90 shadow-lg shadow-emerald-500/20">
                <Sparkles size={15} /> Generate Map
              </button>
              <button onClick={() => setShowCreate(true)} className="flex items-center gap-1.5 px-4 py-2.5 rounded-lg border text-sm hover:bg-accent">
                <Plus size={15} /> Create Empty
              </button>
            </div>
          </div>
        </div>
      ) : nodes.length === 0 ? (
        /* Empty state: no nodes */
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          <div className="text-center">
            <Brain size={36} className="mx-auto mb-3 text-emerald-500/40" />
            <p className="text-sm font-medium">Empty infrastructure map</p>
            <p className="text-xs mt-1 mb-4">Click <strong>AI Generate</strong> to auto-fill, or add nodes manually</p>
            <button onClick={() => setShowGuidance(true)}
              className="flex items-center gap-1.5 px-5 py-2 rounded-lg bg-emerald-600 text-white text-sm font-medium hover:bg-emerald-700 mx-auto">
              <Sparkles size={14} /> AI Generate
            </button>
          </div>
        </div>
      ) : (
        /* Main content: tree or mind map + detail panel */
        <div className="flex-1 flex overflow-hidden">
          {layoutMode === 'tree' ? (
            /* ── Tree Panel ── */
            <div className="flex-1 overflow-auto">
              <div className="flex items-center gap-4 px-4 py-2 border-b text-[10px] text-muted-foreground bg-card/50">
                <span>{totalNodes} nodes</span>
                {nodeQuery && <span>{visibleNodesCount} visible</span>}
                <span>{depth} levels deep</span>
                <span>{describedNodes} described</span>
                <span>{manualNodes} manual</span>
                {Object.entries(categories).slice(0, 6).map(([cat, count]) => {
                  const style = CATEGORY_COLORS[cat] || CATEGORY_COLORS.general;
                  return (
                    <span key={cat} className="flex items-center gap-1">
                      <span className={cn('w-2 h-2 rounded-full', style.bg.replace('/10', '/50'))} />
                      {cat}: {count}
                    </span>
                  );
                })}
              </div>
              <div className="py-2">
                {filteredRootNodes.length > 0 ? filteredRootNodes.map(node => renderNode(node, 0)) : (
                  <div className="px-4 py-8 text-sm text-muted-foreground">
                    No infra-map nodes match the current search.
                  </div>
                )}
              </div>
            </div>
          ) : (
            /* ── Mind Map Canvas ── */
            <>
              {/* Stats ribbon for mind map too */}
              <div className="flex flex-col flex-1 overflow-hidden">
                <div className="flex flex-wrap items-center gap-4 px-4 py-2 border-b text-[10px] text-muted-foreground bg-card/50 shrink-0">
                  <span>{totalNodes} nodes</span>
                  {nodeQuery && <span>{visibleNodesCount} visible</span>}
                  <span>{depth} levels deep</span>
                  <span>{describedNodes} described</span>
                  <span>{manualNodes} manual</span>
                  <span>{Math.round(mindMapViewport.scale * 100)}% zoom</span>
                  <span>Wheel to zoom</span>
                  <span>Drag canvas to pan</span>
                  <span>Drag nodes to reposition</span>
                  {Object.entries(categories).slice(0, 6).map(([cat, count]) => {
                    const style = CATEGORY_COLORS[cat] || CATEGORY_COLORS.general;
                    return (
                      <span key={cat} className="flex items-center gap-1">
                        <span className={cn('w-2 h-2 rounded-full', style.bg.replace('/10', '/50'))} />
                        {cat}: {count}
                      </span>
                    );
                  })}
                  <div className="ml-auto flex items-center gap-2">
                    <button
                      onClick={handleResetMindMapView}
                      className="rounded border px-2 py-1 text-[10px] hover:bg-accent"
                    >
                      Reset View
                    </button>
                    <button
                      onClick={() => { void handleResetMindMapLayout(); }}
                      className="rounded border px-2 py-1 text-[10px] hover:bg-accent"
                    >
                      Auto Layout
                    </button>
                  </div>
                </div>
                {renderMindMap()}
              </div>
            </>
          )}

          {/* ── Detail Panel ── */}
          {selectedNode && (
            <div className="w-80 border-l bg-card overflow-auto shrink-0">
              <div className="p-4 space-y-4">
                <div className="flex items-start gap-3">
                  <div className={cn('p-2 rounded-lg shrink-0', (CATEGORY_COLORS[selectedNode.category] || CATEGORY_COLORS.general).bg, (CATEGORY_COLORS[selectedNode.category] || CATEGORY_COLORS.general).text)}>
                    {ICON_MAP[selectedNode.icon_hint] || <Cog size={18} />}
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="text-sm font-semibold">{selectedNode.label}</h3>
                    <span className={cn('text-[10px] px-1.5 py-0.5 rounded-full inline-block mt-1', (CATEGORY_COLORS[selectedNode.category] || CATEGORY_COLORS.general).bg, (CATEGORY_COLORS[selectedNode.category] || CATEGORY_COLORS.general).text)}>
                      {selectedNode.category}
                    </span>
                  </div>
                  <button onClick={() => setSelectedNodeId(null)} className="p-1 hover:bg-accent rounded"><X size={14} /></button>
                </div>

                {selectedNodePath.length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground font-semibold mb-1">Path</div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{selectedNodePath.join(' / ')}</p>
                  </div>
                )}

                {editDraft && (
                  <div className="space-y-3 rounded-xl border border-border/50 p-3 bg-background/40">
                    <div className="text-[10px] text-muted-foreground font-semibold">Node Details</div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] text-muted-foreground">Label</label>
                      <input
                        value={editDraft.label}
                        onChange={(e) => setEditDraft(prev => prev ? { ...prev, label: e.target.value } : prev)}
                        className="w-full text-xs bg-transparent border rounded px-2 py-1.5"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div className="space-y-1.5">
                        <label className="text-[10px] text-muted-foreground">Category</label>
                        <select
                          value={editDraft.category}
                          onChange={(e) => setEditDraft(prev => prev ? { ...prev, category: e.target.value } : prev)}
                          className="select-field w-full text-xs px-2 py-1.5"
                        >
                          {CATEGORY_OPTIONS.map(category => (
                            <option key={category} value={category}>{category}</option>
                          ))}
                        </select>
                      </div>
                      <div className="space-y-1.5">
                        <label className="text-[10px] text-muted-foreground">Icon</label>
                        <select
                          value={editDraft.icon_hint}
                          onChange={(e) => setEditDraft(prev => prev ? { ...prev, icon_hint: e.target.value } : prev)}
                          className="select-field w-full text-xs px-2 py-1.5"
                        >
                          {ICON_OPTIONS.map(iconHint => (
                            <option key={iconHint} value={iconHint}>{iconHint}</option>
                          ))}
                        </select>
                      </div>
                    </div>
                    <div className="space-y-1.5">
                      <label className="text-[10px] text-muted-foreground">Description</label>
                      <textarea
                        value={editDraft.description}
                        onChange={(e) => setEditDraft(prev => prev ? { ...prev, description: e.target.value } : prev)}
                        rows={5}
                        className="w-full text-xs bg-transparent border rounded px-2 py-1.5 resize-none"
                        placeholder="Add concrete implementation detail, trust boundaries, exposure, ownership, or security relevance..."
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={handleSaveSelectedNode}
                        disabled={savingNode || !editDraft.label.trim()}
                        className="flex items-center gap-1 px-3 py-1.5 rounded bg-emerald-600 text-white text-xs font-medium hover:bg-emerald-700 disabled:opacity-50"
                      >
                        {savingNode ? <Loader2 size={12} className="animate-spin" /> : <BookOpen size={12} />}
                        Save Details
                      </button>
                      <button
                        onClick={() => setEditDraft({
                          label: selectedNode.label,
                          category: selectedNode.category,
                          description: selectedNode.description,
                          icon_hint: selectedNode.icon_hint,
                        })}
                        className="px-3 py-1.5 rounded border text-xs hover:bg-accent"
                      >
                        Reset
                      </button>
                    </div>
                  </div>
                )}

                {(childMap.get(selectedNode.id) || []).length > 0 && (
                  <div>
                    <div className="text-[10px] text-muted-foreground font-semibold mb-1">
                      Children ({(childMap.get(selectedNode.id) || []).length})
                    </div>
                    <div className="space-y-1">
                      {(childMap.get(selectedNode.id) || []).map(child => {
                        const cs = CATEGORY_COLORS[child.category] || CATEGORY_COLORS.general;
                        return (
                          <button key={child.id}
                            onClick={() => { setSelectedNodeId(child.id); setExpandedNodes(prev => new Set([...prev, selectedNode.id])); }}
                            className="w-full flex items-center gap-2 p-1.5 rounded text-xs hover:bg-accent/50 text-left">
                            <div className={cn('p-1 rounded', cs.bg, cs.text)}>{ICON_MAP[child.icon_hint] || <Cog size={10} />}</div>
                            <span className="truncate flex-1">{child.label}</span>
                            <span className={cn('text-[9px] px-1 py-0.5 rounded', cs.bg, cs.text)}>{child.category}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}

                <div className="flex flex-wrap gap-2 pt-2 border-t">
                  <button onClick={() => handleAiExpand(selectedNode.id)} disabled={expandingNode === selectedNode.id}
                    className="flex items-center gap-1 px-3 py-1.5 rounded bg-cyan-600 text-white text-xs font-medium hover:bg-cyan-700 disabled:opacity-50">
                    {expandingNode === selectedNode.id ? <Loader2 size={12} className="animate-spin" /> : <Sparkles size={12} />}
                    AI Expand
                  </button>
                  <button onClick={() => { setShowAddChild(selectedNode.id); setAddChildLabel(''); }}
                    className="flex items-center gap-1 px-3 py-1.5 rounded border text-xs hover:bg-accent">
                    <Plus size={12} /> Add Child
                  </button>
                  {selectedNode.parent_id && (
                    <button onClick={() => handleDeleteNode(selectedNode.id)}
                      className="flex items-center gap-1 px-3 py-1.5 rounded border border-destructive/30 text-destructive text-xs hover:bg-destructive/10">
                      <Trash2 size={12} /> Delete
                    </button>
                  )}
                </div>

                {selected.ai_summary && (
                  <div className="pt-2 border-t">
                    <div className="text-[10px] text-muted-foreground font-semibold mb-1 flex items-center gap-1">
                      <Brain size={10} /> AI Summary
                    </div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{selected.ai_summary}</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ──── Delete Confirmation ──── */}
      <ConfirmDialog
        open={!!deleteConfirmId}
        onOpenChange={(open) => { if (!open) setDeleteConfirmId(null); }}
        onConfirm={() => { if (deleteConfirmId) { handleDelete(deleteConfirmId); setDeleteConfirmId(null); } }}
        title="Delete Infrastructure Map"
        description="This will permanently delete this infrastructure map and all its nodes. This action cannot be undone."
        confirmLabel="Delete"
        destructive
      />
    </div>
  );
}

function OverviewStat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-border/40 bg-background/40 px-3 py-2 min-w-[72px]">
      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</div>
      <div className="text-sm font-semibold mt-0.5">{value}</div>
    </div>
  );
}

export default InfraMapView;
