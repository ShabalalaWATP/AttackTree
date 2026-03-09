import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ReactFlow, Background, Controls, MiniMap, Panel,
  useNodesState, useEdgesState, addEdge,
  type Node, type Edge, type Connection, type NodeTypes,
  BackgroundVariant, MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { useStore } from '@/stores/useStore';
import { api } from '@/utils/api';
import { AttackNodeData, NODE_TYPE_CONFIG, type NodeType, type LogicType } from '@/types';
import { NodeInspector } from '@/components/NodeInspector';
import { AISuggestionsPanel } from '@/components/AISuggestionsPanel';
import { AIAgentDialog } from '@/components/AIAgentDialog';
import { AttackTreeNode } from '@/components/AttackTreeNode';
import { ConfirmDialog } from '@/components/ConfirmDialog';
import toast from 'react-hot-toast';
import { cn } from '@/utils/cn';
import { Search, Filter, Plus, Sparkles, Bot, ChevronRight, RefreshCw, Tag, X, LayoutGrid, Palette, CheckSquare, Trash2, Flame, Route, Group } from 'lucide-react';
import { toPng, toSvg } from 'html-to-image';
import { useQuery } from '@tanstack/react-query';
import type { TagData } from '@/types';

function GroupNode({ data }: { data: Record<string, unknown> }) {
  return (
    <div className="w-full h-full relative">
      <div className="absolute top-2 left-3 text-[11px] font-semibold text-muted-foreground uppercase tracking-wider">
        {String(data.label || '')}
      </div>
    </div>
  );
}

const nodeTypes: NodeTypes = { attackNode: AttackTreeNode, group: GroupNode as any };

export function TreeEditorView() {
  const {
    currentProject, nodes: storeNodes, setNodes: setStoreNodes,
    selectedNodeId, setSelectedNodeId, inspectorOpen, setInspectorOpen,
    pushUndo, searchQuery, setSearchQuery, filterNodeType, setFilterNodeType,
    aiSuggestionsOpen, setAiSuggestionsOpen, darkMode,
    filterTags, setFilterTags,
    selectedNodeIds, toggleNodeSelection, clearMultiSelect,
  } = useStore();

  const flowRef = useRef<HTMLDivElement>(null);
  const [pendingDeleteId, setPendingDeleteId] = useState<string | null>(null);
  const [agentDialogOpen, setAgentDialogOpen] = useState(false);
  const [legendOpen, setLegendOpen] = useState(false);
  const [heatmapMode, setHeatmapMode] = useState(false);
  const [criticalPathIds, setCriticalPathIds] = useState<Set<string>>(new Set());
  const [criticalPathActive, setCriticalPathActive] = useState(false);
  const [criticalPathDetails, setCriticalPathDetails] = useState<Array<{ id: string; title: string; node_type: string; inherent_risk: number | null; residual_risk: number | null; mitigation_count: number; max_mitigation_effectiveness: number }>>([]);
  const [criticalPathRisk, setCriticalPathRisk] = useState(0);
  const [groupBy, setGroupBy] = useState<string>('');
  const pendingDeleteNode = storeNodes.find(n => n.id === pendingDeleteId);

  const { data: allTags = [] } = useQuery({
    queryKey: ['tags'],
    queryFn: api.listTags,
  });

  // Convert store nodes to React Flow nodes and edges, applying all filters
  const { rfNodes, rfEdges } = useMemo(() => {
    let filtered = storeNodes;

    // Search query filter
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(n =>
        n.title.toLowerCase().includes(q) ||
        n.description?.toLowerCase().includes(q) ||
        n.threat_category?.toLowerCase().includes(q) ||
        n.attack_surface?.toLowerCase().includes(q)
      );
    }

    // Node type filter
    if (filterNodeType) {
      filtered = filtered.filter(n => n.node_type === filterNodeType);
    }

    // Tag filter
    if (filterTags.length > 0) {
      const tagSet = new Set(filterTags);
      filtered = filtered.filter(n =>
        n.tags?.some(t => tagSet.has(t.id))
      );
    }
    const filteredIds = new Set(filtered.map(n => n.id));

    const rfNodes = filtered.map((n) => ({
      id: n.id,
      type: 'attackNode' as const,
      position: { x: n.position_x, y: n.position_y },
      parentId: undefined as string | undefined,
      extent: undefined as 'parent' | undefined,
      data: {
        ...n,
        _heatmapMode: heatmapMode,
        _criticalPath: criticalPathActive && criticalPathIds.has(n.id),
      } as unknown as Record<string, unknown>,
      selected: n.id === selectedNodeId || selectedNodeIds.has(n.id),
    }));

    // Build group background nodes when groupBy is active
    const groupNodes: Node[] = [];
    if (groupBy && filtered.length > 0) {
      const groups = new Map<string, typeof filtered>();
      for (const n of filtered) {
        const key = (groupBy === 'node_type' ? n.node_type
          : groupBy === 'threat_category' ? (n.threat_category || 'Uncategorized')
          : groupBy === 'attack_surface' ? (n.attack_surface || 'Uncategorized')
          : groupBy === 'status' ? n.status
          : 'Other') || 'Uncategorized';
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key)!.push(n);
      }

      for (const [label, members] of groups) {
        if (members.length === 0) continue;
        const PAD = 60;
        const minX = Math.min(...members.map(m => m.position_x)) - PAD;
        const minY = Math.min(...members.map(m => m.position_y)) - PAD - 30;
        const maxX = Math.max(...members.map(m => m.position_x)) + 280 + PAD;
        const maxY = Math.max(...members.map(m => m.position_y)) + 160 + PAD;

        const color = groupBy === 'node_type'
          ? (NODE_TYPE_CONFIG[label as NodeType]?.color || '#6b7280')
          : '#6b7280';

        groupNodes.push({
          id: `group-${label}`,
          type: 'group',
          position: { x: minX, y: minY },
          data: { label },
          style: {
            width: maxX - minX,
            height: maxY - minY,
            backgroundColor: `${color}10`,
            border: `2px dashed ${color}40`,
            borderRadius: 12,
          },
          zIndex: -1,
          selectable: false,
          draggable: false,
        } as Node);
      }
    }

    const rfEdges: Edge[] = filtered
      .filter((n) => n.parent_id && filteredIds.has(n.parent_id))
      .map((n) => {
        const isOnCritPath = criticalPathActive && criticalPathIds.has(n.id) && criticalPathIds.has(n.parent_id!);
        return {
          id: `e-${n.parent_id}-${n.id}`,
          source: n.parent_id!,
          target: n.id,
          type: 'smoothstep',
          animated: isOnCritPath,
          style: {
            stroke: isOnCritPath ? '#ef4444' : 'hsl(var(--muted-foreground))',
            strokeWidth: isOnCritPath ? 3 : 1.5,
          },
          markerEnd: {
            type: MarkerType.ArrowClosed,
            width: 12,
            height: 12,
            color: isOnCritPath ? '#ef4444' : 'hsl(var(--muted-foreground))',
          },
        };
      });

    return { rfNodes: [...groupNodes, ...rfNodes], rfEdges };
  }, [storeNodes, selectedNodeId, selectedNodeIds, filterTags, searchQuery, filterNodeType, heatmapMode, criticalPathActive, criticalPathIds, groupBy]);

  const [flowNodes, setFlowNodes, onNodesChange] = useNodesState(rfNodes);
  const [flowEdges, setFlowEdges, onEdgesChange] = useEdgesState(rfEdges);

  useEffect(() => { setFlowNodes(rfNodes); }, [rfNodes, setFlowNodes]);
  useEffect(() => { setFlowEdges(rfEdges); }, [rfEdges, setFlowEdges]);

  const onNodeClick = useCallback((_: any, node: Node) => {
    const evt = _ as MouseEvent;
    if (evt.shiftKey) {
      toggleNodeSelection(node.id);
    } else {
      clearMultiSelect();
      setSelectedNodeId(node.id);
    }
  }, [setSelectedNodeId, toggleNodeSelection, clearMultiSelect]);

  const onPaneClick = useCallback(() => {
    setSelectedNodeId(null);
    clearMultiSelect();
  }, [setSelectedNodeId, clearMultiSelect]);

  const onNodeDragStop = useCallback(async (_: any, node: Node) => {
    const prevNode = useStore.getState().nodes.find(n => n.id === node.id);
    try {
      await api.updateNode(node.id, { position_x: node.position.x, position_y: node.position.y });
      useStore.getState().updateNodeLocal(node.id, { position_x: node.position.x, position_y: node.position.y });
    } catch (e) {
      // Revert to old position on failure
      if (prevNode) {
        useStore.getState().updateNodeLocal(node.id, { position_x: prevNode.position_x, position_y: prevNode.position_y });
      }
    }
  }, []);

  const onConnect = useCallback(async (connection: Connection) => {
    if (!connection.source || !connection.target) return;
    try {
      pushUndo('Re-parent node');
      await api.updateNode(connection.target, { parent_id: connection.source });
      useStore.getState().updateNodeLocal(connection.target, { parent_id: connection.source });
      toast.success('Node re-parented');
    } catch (e: any) {
      toast.error(e.message);
    }
  }, [pushUndo]);

  const addNode = useCallback(async (parentId: string | null, nodeType: NodeType = 'attack_step') => {
    const project = useStore.getState().currentProject;
    if (!project) { toast('Open a project to add nodes', { icon: '📂' }); return; }
    const parent = useStore.getState().nodes.find(n => n.id === parentId);
    try {
      pushUndo('Add node');
      const newNode = await api.createNode({
        project_id: project.id,
        parent_id: parentId,
        node_type: nodeType,
        title: 'New ' + (NODE_TYPE_CONFIG[nodeType]?.label || 'Node'),
        position_x: parent ? parent.position_x + 200 : 400,
        position_y: parent ? parent.position_y + 150 : 0,
      });
      useStore.getState().addNodeLocal(newNode);
      setSelectedNodeId(newNode.id);
    } catch (e: any) {
      toast.error(e.message);
    }
  }, [pushUndo, setSelectedNodeId]);

  const addRootNode = () => addNode(null, 'goal');

  const handleRecalculate = async () => {
    if (!currentProject) { toast('Open a project to recalculate risk', { icon: '📂' }); return; }
    try {
      await api.recalculateRisk(currentProject.id);
      const nodes = await api.listNodes(currentProject.id);
      setStoreNodes(nodes);
      toast.success('Risk scores recalculated');
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleCriticalPath = async () => {
    if (criticalPathActive) {
      setCriticalPathActive(false);
      setCriticalPathIds(new Set());
      setCriticalPathDetails([]);
      setCriticalPathRisk(0);
      return;
    }
    if (!currentProject) { toast('Open a project to find critical paths', { icon: '📂' }); return; }
    try {
      const data = await api.getCriticalPath(currentProject.id);
      if (data.path.length === 0) {
        toast('No paths found in tree', { icon: 'ℹ️' });
        return;
      }
      setCriticalPathIds(new Set(data.path));
      setCriticalPathDetails(data.path_details);
      setCriticalPathRisk(data.cumulative_risk);
      setCriticalPathActive(true);
      toast.success(`Critical path found: ${data.path.length} nodes, risk ${data.cumulative_risk}`);
    } catch (e: any) {
      toast.error(e.message);
    }
  };

  const handleAutoLayout = async () => {
    const all = useStore.getState().nodes;
    if (all.length === 0) return;

    // Build a children map
    const childrenMap: Record<string, string[]> = {};
    const roots: string[] = [];
    for (const n of all) {
      if (!n.parent_id) { roots.push(n.id); }
      else { (childrenMap[n.parent_id] ??= []).push(n.id); }
    }

    // Measure subtree widths
    const NODE_W = 280;
    const NODE_H = 160;
    const GAP_X = 40;
    const GAP_Y = 60;
    const widths: Record<string, number> = {};
    const calcWidth = (id: string): number => {
      const kids = childrenMap[id] || [];
      if (kids.length === 0) { widths[id] = NODE_W; return NODE_W; }
      const total = kids.reduce((s, k) => s + calcWidth(k) + GAP_X, -GAP_X);
      widths[id] = Math.max(NODE_W, total);
      return widths[id];
    };
    roots.forEach(calcWidth);

    // Assign positions
    const positions: Record<string, { x: number; y: number }> = {};
    const assign = (id: string, x: number, y: number) => {
      positions[id] = { x: x + (widths[id] - NODE_W) / 2, y };
      const kids = childrenMap[id] || [];
      let cx = x;
      for (const k of kids) {
        assign(k, cx, y + NODE_H + GAP_Y);
        cx += widths[k] + GAP_X;
      }
    };
    let startX = 0;
    for (const r of roots) {
      assign(r, startX, 0);
      startX += widths[r] + GAP_X * 2;
    }

    // Apply
    pushUndo('Auto-layout');
    const updates = Object.entries(positions).map(([id, pos]) =>
      api.updateNode(id, { position_x: pos.x, position_y: pos.y })
    );
    await Promise.all(updates);
    for (const [id, pos] of Object.entries(positions)) {
      useStore.getState().updateNodeLocal(id, { position_x: pos.x, position_y: pos.y });
    }
    toast.success('Tree auto-arranged');
  };

  const handleExportPng = async () => {
    if (!flowRef.current) return;
    try {
      const viewport = flowRef.current.querySelector('.react-flow__viewport') as HTMLElement;
      if (!viewport) return;
      const isDark = useStore.getState().darkMode;
      const dataUrl = await toPng(viewport, { backgroundColor: isDark ? '#0a1128' : '#ffffff', pixelRatio: 2 });
      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = `${currentProject?.name || 'tree'}.png`;
      a.click();
      toast.success('Exported PNG');
    } catch (e: any) {
      toast.error('PNG export failed');
    }
  };

  const handleExportSvg = async () => {
    if (!flowRef.current) return;
    try {
      const viewport = flowRef.current.querySelector('.react-flow__viewport') as HTMLElement;
      if (!viewport) return;
      const isDark = useStore.getState().darkMode;
      const dataUrl = await toSvg(viewport, { backgroundColor: isDark ? '#0a1128' : '#ffffff' });
      const a = document.createElement('a');
      a.href = dataUrl;
      a.download = `${currentProject?.name || 'tree'}.svg`;
      a.click();
      toast.success('Exported SVG');
    } catch (e: any) {
      toast.error('SVG export failed');
    }
  };

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.ctrlKey && e.key === 'z') { e.preventDefault(); useStore.getState().undo(); }
      if (e.ctrlKey && e.key === 'y') { e.preventDefault(); useStore.getState().redo(); }
      if (e.key === 'Delete' && selectedNodeId && !(e.target as any)?.closest?.('input,textarea,select')) {
        e.preventDefault();
        setPendingDeleteId(selectedNodeId);
      }
      if (e.key === 'Enter' && e.ctrlKey && selectedNodeId) {
        e.preventDefault();
        addNode(selectedNodeId);
      }
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [selectedNodeId, pushUndo, setSelectedNodeId, addNode]);

  const confirmDelete = async () => {
    if (!pendingDeleteId) return;
    try {
      pushUndo('Delete node');
      await api.deleteNode(pendingDeleteId);
      useStore.getState().removeNodeLocal(pendingDeleteId);
      setSelectedNodeId(null);
      toast.success('Node deleted');
    } catch (e: any) {
      toast.error(e.message);
    } finally {
      setPendingDeleteId(null);
    }
  };

  const bulkIds = [...selectedNodeIds];
  const bulkCount = bulkIds.length;

  const handleBulkStatusChange = async (status: string) => {
    if (bulkCount === 0) return;
    try {
      pushUndo('Bulk status change');
      await api.bulkUpdateNodes(bulkIds, { status });
      for (const id of bulkIds) {
        useStore.getState().updateNodeLocal(id, { status: status as any });
      }
      clearMultiSelect();
      toast.success(`Set ${bulkCount} nodes to ${status}`);
    } catch (e: any) { toast.error(e.message); }
  };

  const handleBulkDelete = async () => {
    if (bulkCount === 0) return;
    try {
      pushUndo('Bulk delete');
      await api.bulkDeleteNodes(bulkIds);
      for (const id of bulkIds) {
        useStore.getState().removeNodeLocal(id);
      }
      clearMultiSelect();
      setSelectedNodeId(null);
      toast.success(`Deleted ${bulkCount} nodes`);
    } catch (e: any) { toast.error(e.message); }
  };

  return (
    <div className="h-full flex">
      {/* Main canvas */}
      <div className="flex-1 relative" ref={flowRef}>
        <ReactFlow
          nodes={flowNodes}
          edges={flowEdges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          onPaneClick={onPaneClick}
          onNodeDragStop={onNodeDragStop}
          onConnect={onConnect}
          nodeTypes={nodeTypes}
          fitView
          minZoom={0.1}
          maxZoom={2}
          snapToGrid
          snapGrid={[10, 10]}
          deleteKeyCode={null}
        >
          <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="hsl(var(--border))" />
          <Controls showInteractive={false} />
          <MiniMap
            nodeColor={(n) => {
              const data = n.data as unknown as AttackNodeData;
              return NODE_TYPE_CONFIG[data?.node_type as NodeType]?.color || '#888';
            }}
            maskColor={darkMode ? 'rgba(0,0,0,0.4)' : 'rgba(0,0,0,0.08)'}
            style={{ border: '1px solid hsl(var(--border))' }}
          />

          {/* Top toolbar panel */}
          <Panel position="top-left" className="flex items-center gap-2">
            <div className="flex items-center gap-1 bg-card border rounded-lg p-1 shadow-sm">
              <div className="relative">
                <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-muted-foreground" />
                <input
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search nodes..."
                  className="pl-7 pr-2 py-1 text-xs rounded bg-background border w-40"
                />
              </div>
              <select
                value={filterNodeType}
                onChange={(e) => setFilterNodeType(e.target.value)}
                className="text-xs px-2 py-1 rounded bg-background border"
              >
                <option value="">All types</option>
                {Object.entries(NODE_TYPE_CONFIG).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
              {allTags.length > 0 && (
                <select
                  value=""
                  onChange={(e) => {
                    if (e.target.value && !filterTags.includes(e.target.value)) {
                      setFilterTags([...filterTags, e.target.value]);
                    }
                    e.target.value = '';
                  }}
                  className="text-xs px-2 py-1 rounded bg-background border"
                >
                  <option value="">Filter by tag...</option>
                  {allTags.filter((t: TagData) => !filterTags.includes(t.id)).map((t: TagData) => (
                    <option key={t.id} value={t.id}>{t.name}</option>
                  ))}
                </select>
              )}
            </div>
            {filterTags.length > 0 && (
              <div className="flex items-center gap-1 bg-card border rounded-lg p-1 shadow-sm">
                {filterTags.map(tagId => {
                  const tag = allTags.find((t: TagData) => t.id === tagId);
                  return tag ? (
                    <span key={tagId} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium bg-primary/20 text-primary">
                      <Tag size={10} />
                      {tag.name}
                      <button onClick={() => setFilterTags(filterTags.filter(id => id !== tagId))} className="hover:opacity-70">
                        <X size={10} />
                      </button>
                    </span>
                  ) : null;
                })}
                <button onClick={() => setFilterTags([])} className="text-[10px] text-muted-foreground hover:text-foreground px-1">
                  Clear
                </button>
              </div>
            )}
          </Panel>

          {/* Action buttons panel */}
          <Panel position="top-right" className="flex items-center gap-1">
            <div className="flex items-center gap-1 bg-card border rounded-lg p-1 shadow-sm">
              {storeNodes.length === 0 && (
                <button onClick={addRootNode} className="flex items-center gap-1 px-2 py-1 text-xs rounded bg-primary text-primary-foreground hover:opacity-90">
                  <Plus size={13} /> Add Root Goal
                </button>
              )}
              {selectedNodeId && (
                <button onClick={() => addNode(selectedNodeId)} className="flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-accent">
                  <Plus size={13} /> Add Child
                </button>
              )}
              <button onClick={handleAutoLayout} className="flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-accent" title="Auto-arrange tree layout">
                <LayoutGrid size={13} /> Layout
              </button>
              <button onClick={handleRecalculate} className="flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-accent" title="Recalculate all risk scores">
                <RefreshCw size={13} /> Recalc
              </button>
              <button onClick={() => setAiSuggestionsOpen(!aiSuggestionsOpen)} className={cn("flex items-center gap-1 px-2 py-1 text-xs rounded", aiSuggestionsOpen ? 'bg-primary text-primary-foreground' : 'hover:bg-accent')}>
                <Sparkles size={13} /> AI Assist
              </button>
              <button onClick={() => setAgentDialogOpen(true)} className="flex items-center gap-1 px-2 py-1 text-xs rounded hover:bg-accent" title="AI Agent — auto-generate full attack tree">
                <Bot size={13} /> AI Agent
              </button>
              <button onClick={handleExportPng} className="px-2 py-1 text-xs rounded hover:bg-accent">PNG</button>
              <button onClick={handleExportSvg} className="px-2 py-1 text-xs rounded hover:bg-accent">SVG</button>
              <div className="w-px h-5 bg-border" />
              <button onClick={() => setHeatmapMode(!heatmapMode)} className={cn("flex items-center gap-1 px-2 py-1 text-xs rounded", heatmapMode ? 'bg-orange-500 text-white' : 'hover:bg-accent')} title="Mitigation coverage heatmap">
                <Flame size={13} /> Heatmap
              </button>
              <button onClick={handleCriticalPath} className={cn("flex items-center gap-1 px-2 py-1 text-xs rounded", criticalPathActive ? 'bg-red-500 text-white' : 'hover:bg-accent')} title="Highlight critical (highest-risk) path">
                <Route size={13} /> Critical Path
              </button>
              <select
                value={groupBy}
                onChange={(e) => setGroupBy(e.target.value)}
                className="text-xs px-2 py-1 rounded bg-background border"
                title="Group nodes by attribute"
              >
                <option value="">No grouping</option>
                <option value="node_type">Group by Type</option>
                <option value="threat_category">Group by Threat Category</option>
                <option value="attack_surface">Group by Attack Surface</option>
                <option value="status">Group by Status</option>
              </select>
              <div className="w-px h-5 bg-border" />
              <button onClick={() => setLegendOpen(!legendOpen)} className={cn("p-1 rounded", legendOpen ? 'bg-primary text-primary-foreground' : 'hover:bg-accent')} title="Node colour legend">
                <Palette size={13} />
              </button>
            </div>
          </Panel>

          {/* Node colour legend */}
          {legendOpen && (
            <Panel position="bottom-left" className="mb-2">
              <div className="bg-card border rounded-lg p-3 shadow-sm space-y-1.5 text-xs max-h-[320px] overflow-auto">
                <div className="font-semibold text-[11px] mb-2">Node Types</div>
                {Object.entries(NODE_TYPE_CONFIG).map(([key, cfg]) => (
                  <div key={key} className="flex items-center gap-2">
                    <div className="w-3 h-3 rounded-sm shrink-0" style={{ backgroundColor: cfg.color }} />
                    <span>{cfg.icon}</span>
                    <span className="text-muted-foreground">{cfg.label}</span>
                  </div>
                ))}
                <div className="border-t pt-1.5 mt-2 font-semibold text-[11px]">Risk Levels</div>
                <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm bg-red-500" /><span className="text-muted-foreground">Critical (7-10)</span></div>
                <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm bg-yellow-500" /><span className="text-muted-foreground">Medium (4-6)</span></div>
                <div className="flex items-center gap-2"><div className="w-3 h-3 rounded-sm bg-green-500" /><span className="text-muted-foreground">Low (1-3)</span></div>
              </div>
            </Panel>
          )}

          {/* Heatmap legend */}
          {heatmapMode && (
            <Panel position="bottom-left" className={legendOpen ? 'mb-[340px]' : 'mb-2'}>
              <div className="bg-card border rounded-lg p-3 shadow-sm text-xs space-y-1.5">
                <div className="font-semibold text-[11px] mb-2">🔥 Heatmap Legend</div>
                <div className="flex items-center gap-2"><div className="w-8 h-3 rounded-sm" style={{ background: 'rgba(239,68,68,0.25)' }} /><span className="text-muted-foreground">No mitigations</span></div>
                <div className="flex items-center gap-2"><div className="w-8 h-3 rounded-sm" style={{ background: 'rgba(245,158,11,0.25)' }} /><span className="text-muted-foreground">Partially mitigated</span></div>
                <div className="flex items-center gap-2"><div className="w-8 h-3 rounded-sm" style={{ background: 'rgba(34,197,94,0.25)' }} /><span className="text-muted-foreground">Well mitigated (&gt;70%)</span></div>
                <div className="flex items-center gap-2"><div className="w-8 h-3 rounded-sm" style={{ background: 'rgba(107,114,128,0.1)' }} /><span className="text-muted-foreground">No risk score</span></div>
              </div>
            </Panel>
          )}

          {/* Critical path details panel */}
          {criticalPathActive && criticalPathDetails.length > 0 && (
            <Panel position="bottom-right" className="mb-2">
              <div className="bg-card border rounded-lg p-3 shadow-sm text-xs max-h-[300px] overflow-auto w-64">
                <div className="flex items-center justify-between mb-2">
                  <div className="font-semibold text-[11px]">🔴 Critical Path</div>
                  <span className="text-[10px] font-bold text-red-500">Risk: {criticalPathRisk}</span>
                </div>
                <div className="space-y-1.5">
                  {criticalPathDetails.map((d, i) => (
                    <div key={d.id} className="flex items-center gap-1.5">
                      <span className="text-muted-foreground w-4 text-right shrink-0">{i + 1}.</span>
                      <div
                        className="w-2 h-2 rounded-full shrink-0"
                        style={{ backgroundColor: NODE_TYPE_CONFIG[d.node_type as NodeType]?.color || '#888' }}
                      />
                      <span className="truncate flex-1" title={d.title}>{d.title}</span>
                      <span className={cn(
                        'px-1 py-0.5 rounded text-[9px] font-bold shrink-0',
                        (d.inherent_risk ?? 0) >= 7 ? 'bg-red-500/20 text-red-500' :
                        (d.inherent_risk ?? 0) >= 4 ? 'bg-yellow-500/20 text-yellow-600' :
                        'bg-green-500/20 text-green-600'
                      )}>
                        {d.inherent_risk ?? '—'}
                      </span>
                      {d.mitigation_count > 0 && <span title={`${d.mitigation_count} mitigation(s)`}>✅</span>}
                    </div>
                  ))}
                </div>
              </div>
            </Panel>
          )}

          {/* Bulk actions bar */}
          {bulkCount > 0 && (
            <Panel position="bottom-center">
              <div className="flex items-center gap-2 bg-card border rounded-lg p-2 shadow-lg animate-fade-in">
                <CheckSquare size={14} className="text-primary" />
                <span className="text-xs font-medium">{bulkCount} selected</span>
                <div className="w-px h-5 bg-border" />
                <select
                  defaultValue=""
                  onChange={(e) => { if (e.target.value) handleBulkStatusChange(e.target.value); e.target.value = ''; }}
                  className="text-xs px-2 py-1 rounded bg-background border"
                >
                  <option value="" disabled>Set Status...</option>
                  <option value="draft">Draft</option>
                  <option value="validated">Validated</option>
                  <option value="mitigated">Mitigated</option>
                  <option value="accepted">Accepted</option>
                  <option value="archived">Archived</option>
                </select>
                <button onClick={handleBulkDelete} className="flex items-center gap-1 px-2 py-1 text-xs rounded text-destructive hover:bg-destructive/10" title="Delete selected nodes">
                  <Trash2 size={12} /> Delete
                </button>
                <button onClick={clearMultiSelect} className="p-1 rounded hover:bg-accent" title="Clear selection">
                  <X size={12} />
                </button>
              </div>
            </Panel>
          )}
        </ReactFlow>
      </div>

      {/* AI Suggestions Panel */}
      {aiSuggestionsOpen && (
        <AISuggestionsPanel />
      )}

      {/* Inspector sidebar */}
      {inspectorOpen && selectedNodeId && (
        <NodeInspector />
      )}

      {/* AI Agent Dialog */}
      {currentProject && (
        <AIAgentDialog
          projectId={currentProject.id}
          open={agentDialogOpen}
          onClose={() => setAgentDialogOpen(false)}
          onComplete={async () => {
            const proj = useStore.getState().currentProject;
            if (!proj) return;
            const nodes = await api.listNodes(proj.id);
            setStoreNodes(nodes);
          }}
        />
      )}

      {/* Confirm delete dialog */}
      <ConfirmDialog
        open={!!pendingDeleteId}
        onOpenChange={(open) => { if (!open) setPendingDeleteId(null); }}
        onConfirm={confirmDelete}
        title="Delete Node"
        description={`Are you sure you want to delete "${pendingDeleteNode?.title || 'this node'}"? This action cannot be undone.`}
        confirmLabel="Delete"
        destructive
      />
    </div>
  );
}
